//! Fixed Qualcomm CSR commands in an isolated, bounded child process.
// Adapted from Duck-ToolBox (MIT); ABI support remains firmware-dependent.
use super::{
    cbor::{as_array, as_bytes, as_map, decode, int},
    required,
};
use anyhow::{anyhow, bail, Result};

const LIBRARY: &str = "/vendor/lib64/libkeymasterdeviceutils.so";
const DEVICE: &str = "/dev/smcinvoke";
const MAX_REQUEST: usize = 0x9000;

pub(super) fn available() -> bool {
    cfg!(all(target_os = "android", target_arch = "aarch64"))
        && std::path::Path::new(LIBRARY).is_file()
        && std::path::Path::new(DEVICE).exists()
}

pub(super) fn exchange(request: &[u8]) -> Result<Vec<u8>> {
    validate_request(request)?;
    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    {
        android::exchange(request)
    }
    #[cfg(not(all(target_os = "android", target_arch = "aarch64")))]
    {
        bail!("Native RKP requires Android arm64")
    }
}

pub(super) fn worker(directory: &str) -> Result<()> {
    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    {
        android::worker(directory)
    }
    #[cfg(not(all(target_os = "android", target_arch = "aarch64")))]
    {
        let _ = directory;
        bail!("Native RKP requires Android arm64")
    }
}

fn validate_request(request: &[u8]) -> Result<()> {
    if request.len() > MAX_REQUEST {
        bail!("native RKP request is too large");
    }
    let (command, payload) = request
        .split_at_checked(4)
        .ok_or_else(|| anyhow!("native RKP command missing"))?;
    let value = decode(payload)?;
    let fields = as_map(&value, "native RKP request")?;
    let challenge = as_bytes(required(fields, 4)?, "challenge")?;
    if challenge.is_empty() || challenge.len() > 64 {
        bail!("invalid native RKP challenge");
    }
    match u32::from_le_bytes(command.try_into()?) {
        0x3122 => {
            if fields.len() != 2 {
                bail!("V2 only accepts challenge and one public key");
            }
            let keys = decode(as_bytes(required(fields, 57)?, "keysToSign")?)?;
            let keys = as_array(&keys, "keysToSign")?;
            if keys.len() != 1 {
                bail!("native RKP requires one P256 key");
            }
            let key = as_map(&keys[0], "P256 key")?;
            if key.len() != 5 {
                bail!("unexpected P256 fields");
            }
            for (label, expected) in [(1, 2), (3, -7), (-1, 1)] {
                if required(key, label)? != &int(expected) {
                    bail!("native RKP requires ES256");
                }
            }
            let mut point = vec![4];
            for label in [-2, -3] {
                let coordinate = as_bytes(required(key, label)?, "P256 coordinate")?;
                if coordinate.len() != 32 {
                    bail!("invalid P256 coordinate");
                }
                point.extend(coordinate);
            }
            p256::PublicKey::from_sec1_bytes(&point).map_err(|_| anyhow!("invalid P256 point"))?;
        }
        0x311e => {
            if fields.len() != 5 || required(fields, 55)? != &int(0) {
                bail!("invalid native V1 fields or mode");
            }
            for label in [56, 57] {
                if as_bytes(required(fields, label)?, "MAC key or tag")?.len() != 32 {
                    bail!("invalid MAC key/tag");
                }
            }
            super::v1::validate_eek(as_bytes(required(fields, 58)?, "EEK")?)?;
        }
        _ => bail!("native RKP worker only accepts CSR V1 or V2"),
    }
    Ok(())
}

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
mod android {
    use super::*;
    use crate::rkp_v1_bridge::{read_bounded_reply, wait_bounded, write_private_file, ExchangeDir};
    use anyhow::Context;
    use std::{
        ffi::c_void,
        mem::MaybeUninit,
        os::unix::fs::MetadataExt,
        path::Path,
        process::{Command, Stdio},
    };

    pub(super) fn exchange(request: &[u8]) -> Result<Vec<u8>> {
        let mut directory = ExchangeDir::create()?;
        let result = (|| {
            write_private_file(&directory.path.join("request.bin"), request, 0o600)?;
            let mut child = Command::new(std::env::current_exe()?)
                .env(
                    "LD_LIBRARY_PATH",
                    "/system/lib64:/vendor/lib64:/odm/lib64:/vendor/lib64/hw:/odm/lib64/hw",
                )
                .arg("--rkp-native-worker")
                .arg(&directory.path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .context("start isolated native RKP worker")?;
            if !wait_bounded(&mut child)?.success() {
                bail!("native RKP worker failed; vendor ABI may be unsupported");
            }
            let reply = read_bounded_reply(&directory.path.join("reply.bin"))?;
            let (header, payload) = reply
                .split_at_checked(4)
                .context("truncated native worker reply")?;
            let status = i32::from_be_bytes(header.try_into()?);
            if status != 0 {
                bail!("native RKP CSR rejected (status {status})");
            }
            if payload.is_empty() || payload.len() > super::super::BUFFER_SIZE {
                bail!("invalid native worker payload size");
            }
            Ok(payload.to_vec())
        })();
        let cleanup = directory.cleanup();
        match (result, cleanup) {
            (Ok(reply), Ok(())) => Ok(reply),
            (Err(error), _) => Err(error),
            (_, Err(error)) => Err(error).context("remove native RKP exchange"),
        }
    }

    pub(super) fn worker(directory: &str) -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            bail!("native RKP worker requires root");
        }
        let path = Path::new(directory);
        if path.parent() != Some(Path::new(crate::root_path!("data")))
            || !path.file_name().and_then(|v| v.to_str()).is_some_and(|v| {
                v.starts_with("rkp-v1-")
                    && v.len() == 13
                    && v.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
        {
            bail!("invalid native RKP exchange directory");
        }
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            bail!("unsafe native RKP exchange directory");
        }
        let request = read_bounded_reply(&path.join("request.bin"))?;
        validate_request(&request)?;
        let result = vendor_request(&request);
        let mut reply = Vec::new();
        match result {
            Ok(value) => {
                reply.extend(0i32.to_be_bytes());
                reply.extend(value);
            }
            Err(error) => {
                reply.extend(error.to_be_bytes());
            }
        }
        write_private_file(&path.join("reply.bin"), &reply, 0o600)
    }

    type Constructor = unsafe extern "C" fn(*mut c_void, i32);
    type Destructor = unsafe extern "C" fn(*mut c_void);
    type Send = unsafe extern "C" fn(*mut c_void, *mut c_void, u32, *mut c_void, u32) -> i32;
    #[repr(C, align(16))]
    struct Object([MaybeUninit<u8>; 0x40]);
    struct Session {
        object: Box<Object>,
        destructor: Destructor,
        send: Send,
        _library: libloading::Library,
    }
    impl Drop for Session {
        fn drop(&mut self) {
            // SAFETY: the observed vendor class remains live at its original aligned address.
            unsafe { (self.destructor)(self.object.as_mut() as *mut Object as *mut c_void) };
        }
    }
    fn vendor_request(request: &[u8]) -> Result<Vec<u8>, i32> {
        let metadata = std::fs::metadata(LIBRARY).map_err(|_| -1)?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(-1);
        }
        // SAFETY: fixed vendor path and ABI, used ONLY in this disposable child.
        // Unsupported firmware may crash the child; it cannot corrupt the parent.
        let library: libloading::Library = unsafe {
            libloading::os::unix::Library::open(Some(LIBRARY), libc::RTLD_NOW | libc::RTLD_LOCAL)
        }
        .map_err(|_| -1)?
        .into();
        let constructor = *unsafe {
            library.get::<Constructor>(
                b"_ZN14keymasterutils14KeymasterUtilsC1E26keymaster_security_level_t\0",
            )
        }
        .map_err(|_| -2)?;
        let destructor =
            *unsafe { library.get::<Destructor>(b"_ZN14keymasterutils14KeymasterUtilsD1Ev\0") }
                .map_err(|_| -2)?;
        let send = *unsafe {
            library.get::<Send>(b"_ZN14keymasterutils14KeymasterUtils8send_cmdEPvjS1_j\0")
        }
        .map_err(|_| -2)?;
        let mut object = Box::new(Object([MaybeUninit::new(0); 0x40]));
        // SAFETY: aligned stable storage matches the upstream observed vendor object.
        unsafe {
            constructor(object.as_mut() as *mut Object as *mut c_void, 1);
        }
        let mut session = Session {
            object,
            destructor,
            send,
            _library: library,
        };
        let mut request = request.to_vec();
        let mut response = vec![0; super::super::BUFFER_SIZE];
        response[..4].copy_from_slice(&i32::MIN.to_le_bytes());
        // SAFETY: disjoint owned buffers, bounded lengths, initialized vendor session.
        let status = unsafe {
            (session.send)(
                session.object.as_mut() as *mut Object as *mut c_void,
                request.as_mut_ptr().cast(),
                request.len() as u32,
                response.as_mut_ptr().cast(),
                response.len() as u32,
            )
        };
        if status != 0 {
            return Err(status);
        }
        let status = i32::from_le_bytes(response[..4].try_into().map_err(|_| -3)?);
        if status != 0 {
            return Err(status);
        }
        let len = u32::from_le_bytes(response[4..8].try_into().map_err(|_| -3)?) as usize;
        if len == 0 || len > response.len() - 8 {
            return Err(-3);
        }
        Ok(response[8..8 + len].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_rejects_arbitrary_and_truncated_vendor_commands() {
        for invalid in [
            vec![],
            vec![0; 4],
            vec![0xff; 4],
            vec![0; MAX_REQUEST + 1],
            vec![0x22, 0x31, 0, 0, 0xa0],
        ] {
            assert!(validate_request(&invalid).is_err());
        }
    }
}
