//! Device-derived identifiers for the forged Soter replies.
//!
//! A real Soter TA mints the device identifier inside the vendor firmware and exports its
//! hexadecimal spelling as `cpu_id`. The host has nothing to read it from, so both are
//! reconstructed from the unit serial: a fixed value would be one fingerprint shared by every
//! install that reaches it. `cpu_id` and `getDeviceId` must always describe the same 16 bytes —
//! a live TA reports the same unit identity through both channels.

use std::ffi::{CString, c_char, c_void};
use std::io::Read;
use std::sync::OnceLock;

/// Longest property value Android reports, including the terminating NUL.
const PROPERTY_VALUE_MAX: usize = 92;

/// Non-cryptographic 128-bit fingerprint of `material`, rendered as the 32 lowercase hex
/// characters both identifiers are expressed in. Two independent FNV-1a lanes match the D-Soter
/// reference so the derived values line up with it.
fn hex_fingerprint32(material: &[u8]) -> String {
    const SEEDS: [u64; 2] = [0xcbf2_9ce4_8422_2325, 0x9e37_79b9_7f4a_7c15];
    const PRIMES: [u64; 2] = [0x0000_0100_0000_01b3, 0x0000_0100_0000_0193];
    let mut out = String::with_capacity(32);
    for lane in 0..2 {
        let mut hash = SEEDS[lane];
        for byte in material {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(PRIMES[lane]);
        }
        out.push_str(&format!("{hash:016x}"));
    }
    out
}

/// Read a system property. The symbol is resolved once; an unavailable property API only disables
/// the derived value instead of failing the payload.
fn property(name: &str) -> Option<String> {
    type GetProperty = unsafe extern "C" fn(*const c_char, *mut c_char) -> i32;
    static GETPROP: OnceLock<Option<GetProperty>> = OnceLock::new();
    let get = (*GETPROP.get_or_init(|| {
        let address = crate::resolve_symbol_address(c"__system_property_get")?;
        Some(unsafe { std::mem::transmute::<*mut c_void, GetProperty>(address) })
    }))?;
    let name = CString::new(name).ok()?;
    let mut value = [0u8; PROPERTY_VALUE_MAX];
    let length = unsafe { get(name.as_ptr(), value.as_mut_ptr()) };
    if length <= 0 || length as usize >= PROPERTY_VALUE_MAX {
        return None;
    }
    let bytes = value[..length as usize].to_vec();
    String::from_utf8(bytes).ok().filter(|value| !value.trim().is_empty())
}

/// Read a small text file and trim surrounding whitespace, keeping any other byte as the
/// reference implementation does.
fn read_trimmed(path: &str) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut buffer = Vec::with_capacity(256);
    file.take(256).read_to_end(&mut buffer).ok()?;
    let value = String::from_utf8_lossy(&buffer).trim().to_string();
    (!value.is_empty()).then_some(value)
}

/// A block device serial, the last source in the reference order.
fn serial_from_block_devices() -> Option<String> {
    let mut names = std::fs::read_dir("/sys/block")
        .ok()?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name())
        .collect::<Vec<_>>();
    // Sorting keeps the chosen device stable across boots; the reference leaves the order to the
    // directory listing.
    names.sort();
    names.into_iter().find_map(|name| {
        read_trimmed(&format!("/sys/block/{}/device/serial", name.to_string_lossy()))
    })
}

/// Resolve the unit serial together with the source that supplied it, so the log can name the
/// source without ever recording the serial itself.
fn device_serial() -> Option<(String, &'static str)> {
    for (name, source) in
        [("ro.serialno", "the Android property"), ("ro.boot.serialno", "the bootloader property")]
    {
        if let Some(value) = property(name) {
            return Some((value, source));
        }
    }
    for path in ["/proc/device-tree/serial-number", "/sys/firmware/devicetree/base/serial-number"] {
        if let Some(value) = read_trimmed(path) {
            return Some((value, "the device tree"));
        }
    }
    serial_from_block_devices().map(|value| (value, "a block device serial"))
}

/// Material for a derived identifier: the serial, or a fresh per-process value built from the
/// clock and the pid when no serial is readable — a fixed fallback would be one fingerprint
/// shared by every install that reaches it.
fn identifier_material(label: &str) -> Vec<u8> {
    if let Some((serial, source)) = device_serial() {
        crate::soter::log(&format!("{label} derived from {source}"));
        return serial.into_bytes();
    }
    crate::soter::log(&format!("no device serial readable; minted a per-process {label}"));
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos() as u64);
    let mut material = Vec::with_capacity(16);
    material.extend_from_slice(&nanos.to_le_bytes());
    material.extend_from_slice(&u64::from(std::process::id()).to_le_bytes());
    material
}

/// The 16-byte device identifier `getDeviceId` reports, cached for the process lifetime.
pub(crate) fn device_blob() -> &'static [u8] {
    static BLOB: OnceLock<Vec<u8>> = OnceLock::new();
    BLOB.get_or_init(|| {
        hex_fingerprint32(&identifier_material("device id"))
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
            .collect()
    })
}

/// The `cpu_id` a real TA would export for this unit: the hexadecimal spelling of the same 16
/// bytes `getDeviceId` reports, cached for the process lifetime.
pub(crate) fn cpu_id() -> &'static str {
    static CPU_ID: OnceLock<String> = OnceLock::new();
    CPU_ID.get_or_init(|| device_blob().iter().map(|byte| format!("{byte:02x}")).collect())
}

/// One hexadecimal digit; the fingerprint is always lowercase.
fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        _ => byte - b'a' + 10,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_matches_the_reference_lanes() {
        assert_eq!(hex_fingerprint32(b""), "cbf29ce4842223259e3779b97f4a7c15");
        assert_eq!(hex_fingerprint32(b"abc").len(), 32);
        assert!(hex_fingerprint32(b"abc").chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn identifiers_are_stable_sized_and_describe_the_same_unit() {
        let cpu = cpu_id();
        let blob = device_blob();
        assert_eq!(cpu.len(), 32);
        assert_eq!(blob.len(), 16);
        assert_eq!(cpu, blob.iter().map(|byte| format!("{byte:02x}")).collect::<String>());
        assert!(std::ptr::eq(cpu, cpu_id()), "cpu_id must be cached");
        assert!(std::ptr::eq(blob, device_blob()), "device blob must be cached");
    }
}
