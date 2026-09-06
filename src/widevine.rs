use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use goblin::elf::{
    header::{ET_DYN, ET_EXEC},
    program_header::PT_INTERP,
    Elf,
};
use quick_xml::{events::Event, Reader};
use rand::random;
use ureq::http::Uri;

use crate::webui_http::{self, DownloadPolicy};

const ATTESTATION_URL: &str = "https://rawbin.dpejoh.com/clips/attestation";
const ATTESTATION_HOST: &str = "rawbin.dpejoh.com";
const ATTESTATION_PATH: &str = "/clips/attestation";
const MAX_ATTESTATION_BYTES: usize = 32 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(60);
const TEMP_ROOT: &str = "/data/local/tmp";

const STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const SHUFFLED_ALPHABET: &[u8; 64] =
    b"1dgWnocayqxU3r6vA5lCIPYfHmkV08b4tz+KMsp2NQ9LRXihODwSj7BEFJ/ZuGTe";

struct TemporaryAttestation {
    path: Option<PathBuf>,
    file: Option<File>,
}

impl TemporaryAttestation {
    fn create(contents: &[u8]) -> Result<Self> {
        for _ in 0..16 {
            let path = Path::new(TEMP_ROOT).join(format!(
                ".omk-widevine-{}-{:016x}",
                std::process::id(),
                random::<u64>()
            ));
            let file = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to create temporary Widevine key at {}",
                            path.display()
                        )
                    })
                }
            };
            let mut temporary = Self {
                path: Some(path),
                file: Some(file),
            };
            temporary.write(contents)?;
            return Ok(temporary);
        }
        bail!("failed to allocate a unique temporary Widevine key path")
    }

    fn write(&mut self, contents: &[u8]) -> Result<()> {
        let file = self
            .file
            .as_mut()
            .expect("temporary attestation file is open");
        file.write_all(contents)
            .context("failed to write the temporary Widevine key")?;
        file.sync_all()
            .context("failed to sync the temporary Widevine key")?;
        self.file.take();
        Ok(())
    }

    fn path(&self) -> &Path {
        self.path
            .as_deref()
            .expect("temporary attestation path is available")
    }

    fn cleanup(mut self) -> Result<()> {
        self.file.take();
        {
            let path = self.path();
            fs::remove_file(path).with_context(|| {
                format!(
                    "failed to remove temporary Widevine key at {}",
                    path.display()
                )
            })?;
        }
        self.path.take();
        Ok(())
    }
}

impl Drop for TemporaryAttestation {
    fn drop(&mut self) {
        self.file.take();
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

pub fn install_widevine_l1_attestation() -> Result<()> {
    let installer = find_km_install_keybox().ok_or_else(|| {
        anyhow!(
            "KmInstallKeybox was not found under /vendor; Widevine L1 provisioning is only supported on compatible Qualcomm devices"
        )
    })?;
    let source = download_attestation()?;
    let decoded = decode_substitution(&source)?;
    let temporary = TemporaryAttestation::create(decoded.as_bytes())?;
    let install_result = run_installer(&installer, temporary.path());
    let cleanup_result = temporary.cleanup();
    combine_install_and_cleanup(install_result, cleanup_result)
}

fn combine_install_and_cleanup(
    install_result: Result<()>,
    cleanup_result: Result<()>,
) -> Result<()> {
    match (install_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(install_error), Ok(())) => Err(install_error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(install_error), Err(cleanup_error)) => Err(install_error.context(format!(
            "temporary Widevine key cleanup also failed: {cleanup_error:#}"
        ))),
    }
}

fn download_attestation() -> Result<String> {
    let uri: Uri = ATTESTATION_URL
        .parse()
        .context("Widevine attestation URL is invalid")?;
    webui_http::download_https_utf8(
        uri,
        &DownloadPolicy {
            resource: "Widevine attestation key",
            redirect_allowlist: "the fixed Widevine attestation endpoint",
            max_bytes: MAX_ATTESTATION_BYTES,
            max_size_label: "32 KiB",
            max_redirects: 0,
            timeout: REQUEST_TIMEOUT,
            connect_timeout: CONNECT_TIMEOUT,
        },
        is_allowed_attestation_uri,
    )
}

fn is_allowed_attestation_uri(uri: &Uri) -> bool {
    if uri.scheme_str() != Some("https") || uri.query().is_some() || uri.path() != ATTESTATION_PATH
    {
        return false;
    }
    let Some(authority) = uri.authority() else {
        return false;
    };
    let authority = authority.as_str();
    if authority.contains('@') {
        return false;
    }
    let host = match authority.strip_suffix(":443") {
        Some(host) if !host.contains(':') => host,
        Some(_) => return false,
        None if authority.contains(':') => return false,
        None => authority,
    };
    host.eq_ignore_ascii_case(ATTESTATION_HOST)
}

fn decode_substitution(source: &str) -> Result<String> {
    if source.is_empty() {
        bail!("Widevine attestation response is empty");
    }
    if source.len() > MAX_ATTESTATION_BYTES {
        bail!("Widevine attestation response exceeds the 32 KiB limit");
    }
    if !source.is_ascii() {
        bail!("Widevine attestation response is not ASCII");
    }

    let decoded: Vec<u8> = source
        .bytes()
        .map(|byte| {
            SHUFFLED_ALPHABET
                .iter()
                .position(|candidate| *candidate == byte)
                .map_or(byte, |index| STANDARD_ALPHABET[index])
        })
        .collect();
    let decoded = String::from_utf8(decoded).expect("ASCII substitution stays UTF-8");
    validate_attestation_xml(&decoded)?;
    crate::keybox::KeyBox::from_xml_str(&decoded)
        .context("decoded Widevine attestation key validation failed")?;
    Ok(decoded)
}

fn validate_attestation_xml(contents: &str) -> Result<()> {
    if contents
        .bytes()
        .any(|byte| !matches!(byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
    {
        bail!("decoded Widevine attestation contains unsupported control characters");
    }
    let mut reader = Reader::from_str(contents);
    let mut depth = 0usize;
    let mut root_seen = false;
    let mut root_closed = false;
    let mut declaration_seen = false;
    let mut keybox_seen = false;
    let mut private_key_seen = false;
    let mut certificate_chain_seen = false;
    let mut certificate_seen = false;

    loop {
        match reader
            .read_event()
            .context("decoded Widevine attestation is not well-formed XML")?
        {
            Event::Start(element) => {
                validate_attributes(&element)?;
                let name = element.name();
                if depth == 0 {
                    if root_seen || root_closed || name.as_ref() != "AndroidAttestation" {
                        bail!(
                            "decoded Widevine attestation must have one AndroidAttestation root element"
                        );
                    }
                    root_seen = true;
                }
                mark_required_element(
                    name.as_ref(),
                    &mut keybox_seen,
                    &mut private_key_seen,
                    &mut certificate_chain_seen,
                    &mut certificate_seen,
                );
                depth = depth
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("decoded Widevine attestation nesting is too deep"))?;
            }
            Event::Empty(element) => {
                validate_attributes(&element)?;
                if depth == 0 {
                    bail!("decoded Widevine attestation root element cannot be empty");
                }
                mark_required_element(
                    element.name().as_ref(),
                    &mut keybox_seen,
                    &mut private_key_seen,
                    &mut certificate_chain_seen,
                    &mut certificate_seen,
                );
            }
            Event::End(_) => {
                if depth == 0 {
                    bail!("decoded Widevine attestation has an unexpected closing element");
                }
                depth -= 1;
                if depth == 0 {
                    root_closed = true;
                }
            }
            Event::Text(text) => {
                if depth == 0
                    && !text
                        .as_ref()
                        .chars()
                        .all(|character| character.is_ascii_whitespace())
                {
                    bail!("decoded Widevine attestation has text outside its root element");
                }
            }
            Event::Decl(_) => {
                if declaration_seen || root_seen {
                    bail!("decoded Widevine attestation has a misplaced XML declaration");
                }
                declaration_seen = true;
            }
            Event::DocType(_) => {
                bail!("decoded Widevine attestation contains a forbidden document type")
            }
            Event::PI(_) | Event::GeneralRef(_) => {
                bail!("decoded Widevine attestation contains a forbidden XML construct")
            }
            Event::CData(_) if depth == 0 => {
                bail!("decoded Widevine attestation has CDATA outside its root element")
            }
            Event::Eof => break,
            Event::Comment(_) | Event::CData(_) => {}
        }
    }

    if !root_seen || !root_closed || depth != 0 {
        bail!("decoded Widevine attestation has an incomplete root element");
    }
    if !keybox_seen || !private_key_seen || !certificate_chain_seen || !certificate_seen {
        bail!("decoded Widevine attestation is missing required keybox elements");
    }
    Ok(())
}

fn validate_attributes(element: &quick_xml::events::BytesStart<'_>) -> Result<()> {
    for attribute in element.attributes() {
        attribute.context("decoded Widevine attestation has an invalid XML attribute")?;
    }
    Ok(())
}

fn mark_required_element(
    name: &str,
    keybox_seen: &mut bool,
    private_key_seen: &mut bool,
    certificate_chain_seen: &mut bool,
    certificate_seen: &mut bool,
) {
    match name {
        "Keybox" => *keybox_seen = true,
        "PrivateKey" => *private_key_seen = true,
        "CertificateChain" => *certificate_chain_seen = true,
        "Certificate" => *certificate_seen = true,
        _ => {}
    }
}

fn find_km_install_keybox() -> Option<PathBuf> {
    let search_roots = if usize::BITS == 64 {
        ["/vendor/lib64/hw", "/vendor/lib64", "/vendor/bin"]
    } else {
        ["/vendor/lib/hw", "/vendor/lib", "/vendor/bin"]
    };
    for root in search_roots {
        let mut candidates = Vec::new();
        collect_installers(Path::new(root), &mut candidates, 0, 16_384);
        candidates.sort();
        if let Some(installer) = candidates
            .into_iter()
            .find(|candidate| is_compatible_installer_elf(candidate))
        {
            return Some(installer);
        }
    }
    None
}

fn collect_installers(root: &Path, candidates: &mut Vec<PathBuf>, depth: usize, budget: usize) {
    if depth > 8 || candidates.len() >= budget {
        return;
    }
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries
        .flatten()
        .take(budget.saturating_sub(candidates.len()))
    {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            collect_installers(&path, candidates, depth + 1, budget);
            continue;
        }
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if !is_installer_file_name(file_name) {
            continue;
        }
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.is_file() && metadata.mode() & 0o111 != 0 {
            candidates.push(path);
        }
    }
}

fn is_installer_file_name(file_name: &str) -> bool {
    file_name.eq_ignore_ascii_case("KmInstallKeybox")
}

fn is_compatible_installer_elf(path: &Path) -> bool {
    fs::read(path)
        .ok()
        .is_some_and(|contents| is_compatible_installer_elf_bytes(&contents, usize::BITS))
}

fn is_compatible_installer_elf_bytes(contents: &[u8], target_bits: u32) -> bool {
    let Ok(elf) = Elf::parse(contents) else {
        return false;
    };
    let target_is_64 = match target_bits {
        32 => false,
        64 => true,
        _ => return false,
    };
    if elf.is_64 != target_is_64 {
        return false;
    }

    elf.header.e_type == ET_EXEC
        || (elf.header.e_type == ET_DYN
            && elf
                .program_headers
                .iter()
                .any(|header| header.p_type == PT_INTERP))
}

fn run_installer(installer: &Path, attestation: &Path) -> Result<()> {
    let library_path = if usize::BITS == 64 {
        "/vendor/lib64/hw:/vendor/lib64"
    } else {
        "/vendor/lib/hw:/vendor/lib"
    };
    let mut child = Command::new(installer)
        .arg(attestation)
        .arg("attestation")
        .arg("true")
        .env("LD_LIBRARY_PATH", library_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to start {}", installer.display()))?;

    let started = Instant::now();
    loop {
        match child
            .try_wait()
            .context("failed to query KmInstallKeybox status")?
        {
            Some(status) if status.success() => return Ok(()),
            Some(status) => {
                bail!(
                    "KmInstallKeybox reported failure ({status}); the device secure-storage state may be partial"
                )
            }
            None if started.elapsed() < INSTALL_TIMEOUT => {
                thread::sleep(Duration::from_millis(100));
            }
            None => {
                let _ = child.kill();
                let _ = child.wait();
                bail!(
                    "KmInstallKeybox timed out after {} seconds; the device secure-storage state is unknown",
                    INSTALL_TIMEOUT.as_secs()
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_u16(contents: &mut [u8], offset: usize, value: u16) {
        contents[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(contents: &mut [u8], offset: usize, value: u32) {
        contents[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(contents: &mut [u8], offset: usize, value: u64) {
        contents[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn elf_fixture(bits: u32, elf_type: u16, with_interpreter: bool) -> Vec<u8> {
        let (header_len, program_header_len) = match bits {
            32 => (52usize, 32usize),
            64 => (64usize, 56usize),
            _ => panic!("unsupported test ELF width"),
        };
        let mut contents = vec![
            0u8;
            header_len
                + if with_interpreter {
                    program_header_len + 1
                } else {
                    0
                }
        ];
        contents[..4].copy_from_slice(b"\x7fELF");
        contents[4] = if bits == 64 { 2 } else { 1 };
        contents[5] = 1;
        contents[6] = 1;
        write_u16(&mut contents, 16, elf_type);
        write_u16(&mut contents, 18, if bits == 64 { 183 } else { 40 });
        write_u32(&mut contents, 20, 1);

        if bits == 64 {
            write_u16(&mut contents, 52, header_len as u16);
            write_u16(&mut contents, 54, program_header_len as u16);
            if with_interpreter {
                write_u64(&mut contents, 32, header_len as u64);
                write_u16(&mut contents, 56, 1);
                write_u32(&mut contents, header_len, PT_INTERP);
                write_u64(
                    &mut contents,
                    header_len + 8,
                    (header_len + program_header_len) as u64,
                );
                write_u64(&mut contents, header_len + 32, 1);
            }
        } else {
            write_u16(&mut contents, 40, header_len as u16);
            write_u16(&mut contents, 42, program_header_len as u16);
            if with_interpreter {
                write_u32(&mut contents, 28, header_len as u32);
                write_u16(&mut contents, 44, 1);
                write_u32(&mut contents, header_len, PT_INTERP);
                write_u32(
                    &mut contents,
                    header_len + 4,
                    (header_len + program_header_len) as u32,
                );
                write_u32(&mut contents, header_len + 16, 1);
            }
        }
        contents
    }

    fn encode_substitution(contents: &str) -> String {
        contents
            .bytes()
            .map(|byte| {
                STANDARD_ALPHABET
                    .iter()
                    .position(|candidate| *candidate == byte)
                    .map_or(byte, |index| SHUFFLED_ALPHABET[index]) as char
            })
            .collect()
    }

    #[test]
    fn decodes_the_specter_substitution_format() {
        let xml = include_str!("../template/keybox.xml");
        assert_eq!(decode_substitution(&encode_substitution(xml)).unwrap(), xml);
    }

    #[test]
    fn rejects_attestation_with_invalid_key_material() {
        let xml = "<?xml version=\"1.0\"?><AndroidAttestation><NumberOfKeyboxes>1</NumberOfKeyboxes><Keybox DeviceID=\"attestation\"><Key algorithm=\"ecdsa\"><PrivateKey>AA==</PrivateKey><CertificateChain><NumberOfCertificates>1</NumberOfCertificates><Certificate>AA==</Certificate></CertificateChain></Key></Keybox></AndroidAttestation>";
        assert!(decode_substitution(&encode_substitution(xml)).is_err());
    }

    #[test]
    fn accepts_matching_executable_elfs() {
        assert!(is_compatible_installer_elf_bytes(
            &elf_fixture(64, ET_EXEC, false),
            64
        ));
        assert!(is_compatible_installer_elf_bytes(
            &elf_fixture(32, ET_EXEC, false),
            32
        ));
        assert!(is_compatible_installer_elf_bytes(
            &elf_fixture(64, ET_DYN, true),
            64
        ));
    }

    #[test]
    fn rejects_shared_objects_scripts_and_wrong_width_elfs() {
        assert!(!is_compatible_installer_elf_bytes(
            &elf_fixture(64, ET_DYN, false),
            64
        ));
        assert!(!is_compatible_installer_elf_bytes(
            b"#!/system/bin/sh\nexit 0\n",
            64
        ));
        assert!(!is_compatible_installer_elf_bytes(
            &elf_fixture(32, ET_EXEC, false),
            64
        ));
    }

    #[test]
    fn installer_name_match_is_exact_but_ascii_case_insensitive() {
        for accepted in ["KmInstallKeybox", "kminstallkeybox", "KMINSTALLKEYBOX"] {
            assert!(is_installer_file_name(accepted));
        }
        for rejected in [
            "KmInstallKeybox.bak",
            "libKmInstallKeybox.so",
            "vendor-KmInstallKeybox",
            "KmInstallKeybox2",
        ] {
            assert!(!is_installer_file_name(rejected));
        }
    }

    #[test]
    fn preserves_installer_and_cleanup_errors() {
        let error = combine_install_and_cleanup(
            Err(anyhow!("installer failed")),
            Err(anyhow!("cleanup failed")),
        )
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("installer failed"));
        assert!(rendered.contains("cleanup failed"));
    }

    #[test]
    fn rejects_unsafe_or_incomplete_attestation_xml() {
        for xml in [
            "<AndroidAttestation></AndroidAttestation>",
            "<!DOCTYPE x><AndroidAttestation><Keybox><PrivateKey/><CertificateChain><Certificate/></CertificateChain></Keybox></AndroidAttestation>",
            "<AndroidAttestation><Keybox><PrivateKey/><CertificateChain><Certificate/></CertificateChain></Keybox></WrongRoot>",
            "<AndroidAttestation><Keybox><PrivateKey/><CertificateChain><Certificate/></CertificateChain></Keybox></AndroidAttestation><extra/>",
        ] {
            assert!(validate_attestation_xml(xml).is_err());
        }
    }

    #[test]
    fn attestation_uri_is_exactly_scoped() {
        for allowed in [
            "https://rawbin.dpejoh.com/clips/attestation",
            "https://rawbin.dpejoh.com:443/clips/attestation",
        ] {
            assert!(is_allowed_attestation_uri(&allowed.parse().unwrap()));
        }
        for denied in [
            "http://rawbin.dpejoh.com/clips/attestation",
            "https://rawbin.dpejoh.com/clips/attestation?next=1",
            "https://rawbin.dpejoh.com/clips/other",
            "https://rawbin.dpejoh.com.evil.test/clips/attestation",
            "https://rawbin.dpejoh.com@evil.test/clips/attestation",
        ] {
            assert!(!is_allowed_attestation_uri(&denied.parse().unwrap()));
        }
    }
}
