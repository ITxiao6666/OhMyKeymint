// SPDX-License-Identifier: GPL-3.0-only
// Rust adaptation of KOWX712/PlayIntegrityFix v4.9-inject-s property_virtualizer.
// See docs/THIRD_PARTY.md. Only the current child process is changed.
use std::{
    ffi::{CStr, CString, c_void},
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
    ptr,
};

use super::{MemoryMapping, PropertyValues, parse_memory_mapping_header};

const HEADER_BYTES: usize = 128;
const INFO_BYTES: usize = 96;
const MAGIC: u32 = 0x504f5250;
const VERSION: u32 = 0xfc6ed0ab;
const LONG_FLAG: u32 = 1 << 16;
const MAX_AREA_BYTES: usize = 16 * 1024 * 1024;
// Linux/Android sys/mman.h, available across the supported kernel range.
const MREMAP_MAYMOVE: libc::c_int = 1;
const MREMAP_FIXED: libc::c_int = 2;
type Foreach =
    unsafe extern "C" fn(unsafe extern "C" fn(*const c_void, *mut c_void), *mut c_void) -> i32;

struct Area {
    mapping: MemoryMapping,
    file: File,
    shadow: *mut u8,
    installed: bool,
    patches: usize,
}

impl Drop for Area {
    fn drop(&mut self) {
        if !self.shadow.is_null() {
            unsafe {
                libc::munmap(self.shadow.cast(), self.mapping.end - self.mapping.start);
            }
        }
    }
}

fn word(bytes: &[u8], offset: usize) -> Result<u32, String> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_ne_bytes)
        .ok_or_else(|| "property area word is out of bounds".to_string())
}

fn used_end(bytes: &[u8], length: usize) -> Result<usize, String> {
    if !(HEADER_BYTES..=MAX_AREA_BYTES).contains(&length)
        || word(bytes, 8)? != MAGIC
        || word(bytes, 12)? != VERSION
    {
        return Err("unsupported property area header".to_string());
    }
    // AOSP bytes_used is relative to data_, not the start of the header.
    let used = word(bytes, 0)? as usize;
    if used < 20 || used > length - HEADER_BYTES {
        return Err("invalid property area allocation boundary".to_string());
    }
    Ok(HEADER_BYTES + used)
}

fn property_name(bytes: &[u8], offset: usize) -> Result<&[u8], String> {
    if offset < HEADER_BYTES || !offset.is_multiple_of(4) {
        return Err("unaligned property info or header overlap".to_string());
    }
    let start = offset
        .checked_add(INFO_BYTES)
        .ok_or_else(|| "property name offset overflow".to_string())?;
    let tail = bytes
        .get(start..)
        .ok_or_else(|| "property info exceeds allocated area".to_string())?;
    let length = tail
        .iter()
        .take(1024)
        .position(|value| *value == 0)
        .ok_or_else(|| "property name is not terminated within area".to_string())?;
    Ok(&tail[..length])
}

fn patch_property(bytes: &mut [u8], offset: usize, value: &CStr) -> Result<(), String> {
    let name_len = property_name(bytes, offset)?.len();
    let replacement = value.to_bytes();
    if replacement.len() >= super::PROPERTY_VALUE_MAX {
        return Err("replacement requires the long-property callback fallback".to_string());
    }
    let serial = word(bytes, offset)?;
    if serial & 1 != 0 {
        return Err("property is being updated".to_string());
    }
    if serial & LONG_FLAG != 0 {
        // prop_info::long_property.offset follows its 56-byte legacy message.
        let relative = word(bytes, offset + 4 + 56)? as usize;
        let start = offset
            .checked_add(relative)
            .ok_or_else(|| "long property offset overflow".to_string())?;
        if start < offset + INFO_BYTES + name_len + 1 {
            return Err("long property storage overlaps property metadata".to_string());
        }
        let tail = bytes
            .get(start..)
            .ok_or_else(|| "long property exceeds allocated area".to_string())?;
        let length = tail
            .iter()
            .position(|value| *value == 0)
            .ok_or_else(|| "long property value is not terminated".to_string())?;
        bytes[start..start + length + 1].fill(0);
    }
    // This is an unpublished private shadow: no readers or futex waiters exist.
    bytes[offset + 4..offset + INFO_BYTES].fill(0);
    bytes[offset + 4..offset + 4 + replacement.len()].copy_from_slice(replacement);
    let serial = ((replacement.len() as u32) << 24) | ((serial & 0x00ff_ffff) & !LONG_FLAG);
    bytes[offset..offset + 4].copy_from_slice(&serial.to_ne_bytes());
    Ok(())
}

fn area_mappings(contents: &str) -> Vec<MemoryMapping> {
    contents
        .lines()
        .filter_map(|line| {
            // Never replace another module's private copy, executable memory, or a
            // sliced mapping whose offset/layout differs from bionic's property ABI.
            let offset = line.split_whitespace().nth(2)?;
            if u64::from_str_radix(offset, 16).ok()? != 0 {
                return None;
            }
            let mapping = parse_memory_mapping_header(line)?;
            let path = mapping.path.as_deref()?;
            (mapping.readable()
                && !mapping.writable()
                && !mapping.executable()
                && !mapping.private
                && mapping.inode != 0
                && path.starts_with("/dev/__properties__/")
                && !path.contains("..")
                && mapping.end - mapping.start <= MAX_AREA_BYTES)
                .then_some(mapping)
        })
        .collect()
}

unsafe extern "C" fn warmup(_: *const c_void, _: *mut c_void) {}

unsafe extern "C" fn collect(info: *const c_void, cookie: *mut c_void) {
    if !info.is_null() {
        // cookie lives throughout the synchronous bionic enumeration.
        unsafe {
            (&mut *cookie.cast::<Vec<usize>>()).push(info as usize);
        }
    }
}

fn open_area(mapping: MemoryMapping) -> Result<Area, String> {
    let path = mapping
        .path
        .as_deref()
        .ok_or("property mapping has no path")?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("cannot open property area: {error}"))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    let length = mapping.end - mapping.start;
    if !metadata.is_file()
        || metadata.dev() != mapping.device
        || metadata.ino() != mapping.inode
        || metadata.len() < length as u64
    {
        return Err("property area identity does not match its mapping".to_string());
    }
    let mut header = [0u8; HEADER_BYTES];
    file.read_exact_at(&mut header, 0)
        .map_err(|error| error.to_string())?;
    used_end(&header, length)?;
    let shadow = unsafe {
        libc::mmap(
            ptr::null_mut(),
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    if shadow == libc::MAP_FAILED {
        return Err(format!(
            "cannot map private property shadow: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(Area {
        mapping,
        file,
        shadow: shadow.cast(),
        installed: false,
        patches: 0,
    })
}

fn rollback(areas: &mut [Area]) {
    for area in areas.iter_mut().rev().filter(|area| area.installed) {
        let restored = unsafe {
            libc::mmap(
                area.mapping.start as *mut c_void,
                area.mapping.end - area.mapping.start,
                area.mapping.protection,
                libc::MAP_FIXED | libc::MAP_SHARED,
                area.file.as_raw_fd(),
                0,
            )
        };
        if restored == libc::MAP_FAILED {
            // Never continue with partially replaced or unmapped property areas.
            super::fatal_patch_failure("could not restore original property area mapping");
        }
        area.installed = false;
    }
}

pub(super) fn install(values: &PropertyValues) -> Result<usize, String> {
    super::ensure_single_threaded()?;
    let address = super::resolve_symbol_address(c"__system_property_foreach")
        .ok_or("bionic property enumeration is unavailable")?;
    let foreach: Foreach = unsafe { std::mem::transmute(address) };
    let find_address = super::resolve_symbol_address(super::PROPERTY_FIND_SYMBOL)
        .ok_or("bionic property lookup is unavailable")?;
    let get_address = super::resolve_symbol_address(super::PROPERTY_GET_SYMBOL)
        .ok_or("bionic property read is unavailable")?;
    let find: super::PropertyFind = unsafe { std::mem::transmute(find_address) };
    let get: super::PropertyGet = unsafe { std::mem::transmute(get_address) };
    // v4.9: first open bionic's lazily loaded contexts before snapshotting maps.
    if unsafe { foreach(warmup, ptr::null_mut()) } != 0 {
        return Err("property area warmup failed".to_string());
    }
    let mut pointers = Vec::<usize>::new();
    if unsafe { foreach(collect, (&mut pointers as *mut Vec<usize>).cast()) } != 0 {
        return Err("property enumeration failed".to_string());
    }
    let maps = std::fs::read_to_string("/proc/self/maps").map_err(|error| error.to_string())?;
    let mut areas = Vec::new();
    let mut expected = Vec::new();
    for mapping in area_mappings(&maps) {
        let addresses: Vec<usize> = pointers
            .iter()
            .copied()
            .filter(|pointer| mapping.contains(*pointer, INFO_BYTES + 1))
            .collect();
        if addresses.is_empty() {
            continue;
        }
        let mut area = open_area(mapping)?;
        let length = area.mapping.end - area.mapping.start;
        // Our own writable shadow, never exposed to Android readers.
        let bytes = unsafe { std::slice::from_raw_parts_mut(area.shadow, length) };
        let end = used_end(bytes, length)?;
        let bytes = &mut bytes[..end];
        for address in addresses {
            let offset = address - area.mapping.start;
            let name = property_name(bytes, offset)?;
            if let Some(value) = values.value_for(name) {
                expected.push((
                    address,
                    CString::new(name).map_err(|error| error.to_string())?,
                    value.to_bytes().to_vec(),
                ));
                patch_property(bytes, offset, value)?;
                area.patches += 1;
            }
        }
        if area.patches > 0 {
            if unsafe { libc::mprotect(area.shadow.cast(), length, area.mapping.protection) } != 0 {
                return Err("cannot protect completed property shadow".to_string());
            }
            areas.push(area);
        }
    }
    // These core properties must be present; otherwise native hooks handle
    // already-private or unsupported vendor mappings instead of partial spoofing.
    for name in [
        b"ro.build.fingerprint".as_slice(),
        b"ro.product.first_api_level".as_slice(),
    ] {
        if !expected
            .iter()
            .any(|(_, matched, _)| matched.to_bytes() == name)
        {
            return Err("core property has no supported shared mapping".to_string());
        }
    }
    super::ensure_single_threaded()?;
    let current = std::fs::read_to_string("/proc/self/maps").map_err(|error| error.to_string())?;
    let current = area_mappings(&current);
    if areas.iter().any(|area| !current.contains(&area.mapping)) {
        return Err("property mappings changed during preflight".to_string());
    }
    for index in 0..areas.len() {
        let area = &mut areas[index];
        let length = area.mapping.end - area.mapping.start;
        // Move a fully prepared read-only private mapping over the original.
        // No RW shared mapping and no executable-memory patch is introduced.
        // A failed MREMAP_FIXED may already have removed the destination;
        // include the current area in rollback even when the syscall fails.
        area.installed = true;
        let result = unsafe {
            libc::syscall(
                libc::SYS_mremap,
                area.shadow.cast::<c_void>(),
                length,
                length,
                MREMAP_MAYMOVE | MREMAP_FIXED,
                area.mapping.start as *mut c_void,
            ) as *mut c_void
        };
        if result == libc::MAP_FAILED {
            let error = std::io::Error::last_os_error();
            rollback(&mut areas);
            return Err(format!(
                "private property mapping replacement failed: {error}"
            ));
        }
        area.shadow = ptr::null_mut();
    }
    // Verify both bionic's visible result and retained prop_info addresses.
    // Roll back all mappings if another native layer disagrees with the copy.
    for (address, name, value) in expected {
        let mut buffer = [0u8; super::PROPERTY_VALUE_MAX];
        let info = unsafe { find(name.as_ptr()) };
        let length = unsafe { get(name.as_ptr(), buffer.as_mut_ptr().cast()) };
        if info as usize != address
            || length < 0
            || length as usize != value.len()
            || buffer.get(..value.len()) != Some(value.as_slice())
        {
            rollback(&mut areas);
            return Err("private property readback did not match the profile".to_string());
        }
    }
    let verified = std::fs::read_to_string("/proc/self/maps")
        .map(|maps| {
            let mappings: Vec<_> = maps
                .lines()
                .filter_map(parse_memory_mapping_header)
                .collect();
            areas.iter().all(|area| {
                mappings.iter().any(|mapped| {
                    let mut expected = area.mapping.clone();
                    expected.private = true;
                    mapped == &expected
                })
            })
        })
        .unwrap_or(false);
    if !verified {
        rollback(&mut areas);
        return Err("private property mapping identity verification failed".to_string());
    }
    Ok(areas.iter().map(|area| area.patches).sum())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_area(long: bool) -> Vec<u8> {
        let mut bytes = vec![0; 512];
        bytes[..4].copy_from_slice(&384u32.to_ne_bytes());
        bytes[8..12].copy_from_slice(&MAGIC.to_ne_bytes());
        bytes[12..16].copy_from_slice(&VERSION.to_ne_bytes());
        let name = b"ro.build.fingerprint\0";
        bytes[224..224 + name.len()].copy_from_slice(name);
        if long {
            bytes[128..132].copy_from_slice(&LONG_FLAG.to_ne_bytes());
            bytes[188..192].copy_from_slice(&200u32.to_ne_bytes());
            bytes[328..332].copy_from_slice(b"old\0");
        }
        bytes
    }

    #[test]
    fn validates_android_header_data_relative_bounds() {
        let bytes = sample_area(false);
        assert_eq!(used_end(&bytes, 512).unwrap(), 512);
        assert!(used_end(&bytes, 511).is_err());
        let mut wrong = bytes;
        wrong[12] ^= 1;
        assert!(used_end(&wrong, 512).is_err());
    }

    #[test]
    fn demotes_long_properties_without_changing_name_or_header() {
        let mut bytes = sample_area(true);
        let header = bytes[..128].to_vec();
        patch_property(&mut bytes, 128, c"new").unwrap();
        assert_eq!(&bytes[..128], header);
        assert_eq!(property_name(&bytes, 128).unwrap(), b"ro.build.fingerprint");
        assert_eq!(&bytes[132..136], b"new\0");
        assert_eq!(&bytes[328..332], &[0; 4]);
        assert_eq!(word(&bytes, 128).unwrap(), 3 << 24);
    }

    #[test]
    fn rejects_long_replacement_and_bad_offsets_without_mutation() {
        let mut bytes = sample_area(true);
        let before = bytes.clone();
        let long = std::ffi::CString::new("x".repeat(92)).unwrap();
        assert!(patch_property(&mut bytes, 128, &long).is_err());
        assert_eq!(bytes, before);
        bytes[188..192].copy_from_slice(&u32::MAX.to_ne_bytes());
        let before = bytes.clone();
        assert!(patch_property(&mut bytes, 128, c"new").is_err());
        assert_eq!(bytes, before);
        assert!(patch_property(&mut bytes, 129, c"new").is_err());
    }

    #[test]
    fn accepts_only_shared_readonly_full_property_mappings() {
        let valid = "1000-2000 r--s 00000000 00:15 35 /dev/__properties__/u:object_r:build_prop:s0";
        assert_eq!(area_mappings(valid).len(), 1);
        for invalid in [
            valid.replace("r--s", "rw-s"),
            valid.replace("r--s", "r--p"),
            valid.replace("00000000", "00001000"),
            valid.replace("/dev/__properties__/", "/tmp/"),
        ] {
            assert!(area_mappings(&invalid).is_empty());
        }
    }
}
