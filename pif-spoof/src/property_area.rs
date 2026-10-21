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

use super::{LONG_LEGACY_ERROR, MemoryMapping, PropertyValues, parse_memory_mapping_header};

const HEADER_BYTES: usize = 128;
const INFO_BYTES: usize = 96;
const MAGIC: u32 = 0x504f5250;
const VERSION: u32 = 0xfc6ed0ab;
const LONG_FLAG: u32 = 1 << 16;
const LONG_OFFSET: usize = 4 + 56;
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
    let end = used_end(bytes, bytes.len())?;
    let name = property_name(&bytes[..end], offset)?;
    let name_len = name.len();
    let replacement = value.to_bytes();
    let is_long = replacement.len() >= super::PROPERTY_VALUE_MAX;
    if is_long && !name.starts_with(b"ro.") {
        return Err("only read-only properties support long values".to_string());
    }
    let serial = word(bytes, offset)?;
    if serial & 1 != 0 {
        return Err("property is being updated".to_string());
    }
    let old_long = if serial & LONG_FLAG != 0 {
        // prop_info::long_property.offset follows its 56-byte legacy message.
        let relative = word(bytes, offset + LONG_OFFSET)? as usize;
        let start = offset
            .checked_add(relative)
            .ok_or_else(|| "long property offset overflow".to_string())?;
        if start < offset + INFO_BYTES + name_len + 1 {
            return Err("long property storage overlaps property metadata".to_string());
        }
        let tail = bytes[..end]
            .get(start..)
            .ok_or_else(|| "long property exceeds allocated area".to_string())?;
        let length = tail
            .iter()
            .position(|value| *value == 0)
            .ok_or_else(|| "long property value is not terminated".to_string())?;
        Some(start..start + length + 1)
    } else {
        None
    };
    // Preserve prop_info addresses. AOSP long values use an offset from the
    // unchanged prop_info, with storage allocated at the area's used boundary.
    // Reuse a sufficiently large existing long value before consuming space.
    let (long_start, new_end) = if is_long {
        if let Some(old) = old_long
            .as_ref()
            .filter(|old| old.len() > replacement.len())
        {
            (old.start, end)
        } else {
            let start = end.next_multiple_of(4);
            let new_end = start
                .checked_add(value.to_bytes_with_nul().len().next_multiple_of(4))
                .filter(|new_end| *new_end <= bytes.len())
                .ok_or_else(|| "property area has no space for a long value".to_string())?;
            (start, new_end)
        }
    } else {
        (0, end)
    };
    // This is an unpublished private shadow: no readers or futex waiters exist.
    // All bounds and allocation checks above complete before the first write.
    if let Some(old) = old_long {
        bytes[old].fill(0);
    }
    bytes[offset + 4..offset + INFO_BYTES].fill(0);
    let legacy = if is_long {
        bytes[long_start..long_start + value.to_bytes_with_nul().len()]
            .copy_from_slice(value.to_bytes_with_nul());
        bytes[offset + LONG_OFFSET..offset + LONG_OFFSET + 4]
            .copy_from_slice(&((long_start - offset) as u32).to_ne_bytes());
        bytes[..4].copy_from_slice(&((new_end - HEADER_BYTES) as u32).to_ne_bytes());
        LONG_LEGACY_ERROR.to_bytes()
    } else {
        replacement
    };
    bytes[offset + 4..offset + 4 + legacy.len()].copy_from_slice(legacy);
    let serial = ((legacy.len() as u32) << 24)
        | ((serial & 0x00ff_ffff) & !LONG_FLAG)
        | if is_long { LONG_FLAG } else { 0 };
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
    let read_address = super::resolve_symbol_address(super::PROPERTY_READ_SYMBOL)
        .ok_or("bionic property callback read is unavailable")?;
    let find: super::PropertyFind = unsafe { std::mem::transmute(find_address) };
    let get: super::PropertyGet = unsafe { std::mem::transmute(get_address) };
    let read: super::PropertyReadCallbackApi = unsafe { std::mem::transmute(read_address) };
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
        used_end(bytes, length)?;
        for address in addresses {
            let offset = address - area.mapping.start;
            let end = used_end(bytes, length)?;
            let name = property_name(&bytes[..end], offset)?;
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
        let mut observed = Readback {
            name: &name,
            value: &value,
            matched: false,
        };
        if !info.is_null() {
            unsafe {
                read(
                    info,
                    Some(readback_callback),
                    (&mut observed as *mut Readback<'_>).cast(),
                );
            }
        }
        let length = unsafe { get(name.as_ptr(), buffer.as_mut_ptr().cast()) };
        let legacy = if value.len() >= super::PROPERTY_VALUE_MAX {
            LONG_LEGACY_ERROR.to_bytes()
        } else {
            value.as_slice()
        };
        if info as usize != address
            || !observed.matched
            || length < 0
            || length as usize != legacy.len()
            || buffer.get(..legacy.len()) != Some(legacy)
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

struct Readback<'a> {
    name: &'a CStr,
    value: &'a [u8],
    matched: bool,
}

unsafe extern "C" fn readback_callback(
    cookie: *mut c_void,
    name: *const libc::c_char,
    value: *const libc::c_char,
    serial: u32,
) {
    if cookie.is_null() || name.is_null() || value.is_null() {
        return;
    }
    let observed = unsafe { &mut *cookie.cast::<Readback<'_>>() };
    let name = unsafe { CStr::from_ptr(name) };
    let value = unsafe { CStr::from_ptr(value) };
    let expected_serial = if observed.value.len() >= super::PROPERTY_VALUE_MAX {
        ((LONG_LEGACY_ERROR.to_bytes().len() as u32) << 24) | LONG_FLAG
    } else {
        (observed.value.len() as u32) << 24
    };
    observed.matched = name == observed.name
        && value.to_bytes() == observed.value
        && serial & (0xff00_0001 | LONG_FLAG) == expected_serial;
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
    fn rejects_exhausted_storage_and_bad_offsets_without_mutation() {
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
    fn promotes_short_values_using_android_long_property_layout() {
        for length in [92, pif_common::MAX_VALUE_BYTES] {
            let mut bytes = sample_area(false);
            bytes.resize(1024, 0);
            bytes[..4].copy_from_slice(&128u32.to_ne_bytes());
            let replacement = CString::new("x".repeat(length)).unwrap();
            patch_property(&mut bytes, 128, &replacement).unwrap();
            assert_eq!(property_name(&bytes, 128).unwrap(), b"ro.build.fingerprint");
            assert_eq!(word(&bytes, 128 + LONG_OFFSET).unwrap(), 128);
            assert_eq!(
                &bytes[256..256 + length + 1],
                replacement.to_bytes_with_nul()
            );
            assert_eq!(
                &bytes[132..132 + LONG_LEGACY_ERROR.to_bytes_with_nul().len()],
                LONG_LEGACY_ERROR.to_bytes_with_nul()
            );
            assert_eq!(
                word(&bytes, 128).unwrap(),
                ((LONG_LEGACY_ERROR.to_bytes().len() as u32) << 24) | LONG_FLAG
            );
            assert_eq!(
                used_end(&bytes, bytes.len()).unwrap(),
                256 + (length + 1).next_multiple_of(4)
            );
        }
    }

    #[test]
    fn reuses_long_storage_and_appends_larger_values_without_touching_neighbors() {
        let mut bytes = sample_area(false);
        bytes.resize(1024, 0);
        bytes[..4].copy_from_slice(&256u32.to_ne_bytes());
        bytes[256..384].fill(0xa5);
        let neighbor = bytes[256..384].to_vec();
        let replacement = CString::new("x".repeat(120)).unwrap();
        patch_property(&mut bytes, 128, &replacement).unwrap();
        let old_end = used_end(&bytes, bytes.len()).unwrap();
        let smaller = CString::new("y".repeat(92)).unwrap();
        patch_property(&mut bytes, 128, &smaller).unwrap();
        assert_eq!(used_end(&bytes, bytes.len()).unwrap(), old_end);
        assert_eq!(&bytes[384..477], smaller.to_bytes_with_nul());
        assert!(bytes[477..505].iter().all(|byte| *byte == 0));
        let larger = CString::new("z".repeat(200)).unwrap();
        patch_property(&mut bytes, 128, &larger).unwrap();
        assert_eq!(
            word(&bytes, 128 + LONG_OFFSET).unwrap() as usize,
            old_end - 128
        );
        assert_eq!(&bytes[old_end..old_end + 201], larger.to_bytes_with_nul());
        assert!(bytes[384..505].iter().all(|byte| *byte == 0));
        assert_eq!(&bytes[256..384], neighbor);
    }

    #[test]
    fn rejects_unallocated_long_storage_and_mutable_long_values_before_writing() {
        let mut bytes = sample_area(true);
        bytes[..4].copy_from_slice(&128u32.to_ne_bytes());
        let before = bytes.clone();
        assert!(patch_property(&mut bytes, 128, c"new").is_err());
        assert_eq!(bytes, before);

        let mut bytes = sample_area(false);
        bytes[..4].copy_from_slice(&128u32.to_ne_bytes());
        bytes[224..227].copy_from_slice(b"xx.");
        let before = bytes.clone();
        let long = CString::new("x".repeat(92)).unwrap();
        assert!(patch_property(&mut bytes, 128, &long).is_err());
        assert_eq!(bytes, before);
    }

    #[test]
    fn allocates_distinct_long_values_for_properties_in_the_same_area() {
        let mut bytes = sample_area(false);
        bytes.resize(1024, 0);
        let second_name = c"ro.system.build.fingerprint";
        bytes[352..352 + second_name.to_bytes_with_nul().len()]
            .copy_from_slice(second_name.to_bytes_with_nul());
        let first = CString::new("a".repeat(92)).unwrap();
        let second = CString::new("b".repeat(pif_common::MAX_VALUE_BYTES)).unwrap();
        patch_property(&mut bytes, 128, &first).unwrap();
        patch_property(&mut bytes, 256, &second).unwrap();
        let first_start = 128 + word(&bytes, 128 + LONG_OFFSET).unwrap() as usize;
        let second_start = 256 + word(&bytes, 256 + LONG_OFFSET).unwrap() as usize;
        assert!(first_start + first.to_bytes_with_nul().len() <= second_start);
        assert_eq!(
            &bytes[first_start..first_start + first.to_bytes_with_nul().len()],
            first.to_bytes_with_nul()
        );
        assert_eq!(
            &bytes[second_start..second_start + second.to_bytes_with_nul().len()],
            second.to_bytes_with_nul()
        );
        assert_eq!(property_name(&bytes, 256).unwrap(), second_name.to_bytes());
        assert_eq!(used_end(&bytes, bytes.len()).unwrap(), 736);
    }

    #[test]
    fn callback_readback_checks_full_values_names_and_long_serial_metadata() {
        let name = c"ro.build.fingerprint";
        let value = CString::new("x".repeat(120)).unwrap();
        let serial = ((LONG_LEGACY_ERROR.to_bytes().len() as u32) << 24) | LONG_FLAG;
        let mut observed = Readback {
            name,
            value: value.to_bytes(),
            matched: false,
        };
        unsafe {
            readback_callback(
                (&mut observed as *mut Readback<'_>).cast(),
                name.as_ptr(),
                value.as_ptr(),
                serial,
            );
        }
        assert!(observed.matched);
        for (name, value, serial) in [
            (name, value.as_c_str(), serial & !LONG_FLAG),
            (name, value.as_c_str(), serial | 1),
            (name, LONG_LEGACY_ERROR, serial),
            (c"ro.build.id", value.as_c_str(), serial),
        ] {
            unsafe {
                readback_callback(
                    (&mut observed as *mut Readback<'_>).cast(),
                    name.as_ptr(),
                    value.as_ptr(),
                    serial,
                );
            }
            assert!(!observed.matched);
        }
    }

    #[test]
    fn android_bionic_reads_private_short_and_long_property_layouts() {
        let read: super::super::PropertyReadCallbackApi = unsafe {
            std::mem::transmute(
                super::super::resolve_symbol_address(super::super::PROPERTY_READ_SYMBOL).unwrap(),
            )
        };
        let legacy: super::super::PropertyReadLegacy = unsafe {
            std::mem::transmute(
                super::super::resolve_symbol_address(super::super::PROPERTY_READ_LEGACY_SYMBOL)
                    .unwrap(),
            )
        };
        // Use aligned, owned storage. This exercises the device's actual bionic
        // readers without replacing any live property mapping or global value.
        let mut storage = vec![0u32; 256];
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), storage.len() * 4)
        };
        bytes[..512].copy_from_slice(&sample_area(false));
        for length in [91, 92, pif_common::MAX_VALUE_BYTES, 4] {
            let value = CString::new("x".repeat(length)).unwrap();
            patch_property(bytes, 128, &value).unwrap();
            let property = bytes[128..].as_ptr().cast();
            let mut observed = Readback {
                name: c"ro.build.fingerprint",
                value: value.to_bytes(),
                matched: false,
            };
            unsafe {
                read(
                    property,
                    Some(readback_callback),
                    (&mut observed as *mut Readback<'_>).cast(),
                );
            }
            assert!(observed.matched, "callback rejected length {length}");

            let expected = super::super::legacy_replacement_value(&value);
            let mut buffer = [0xa5u8; super::super::PROPERTY_VALUE_MAX + 8];
            let written =
                unsafe { legacy(property, ptr::null_mut(), buffer[4..].as_mut_ptr().cast()) };
            assert_eq!(written as usize, expected.to_bytes().len());
            assert_eq!(
                &buffer[4..4 + expected.to_bytes_with_nul().len()],
                expected.to_bytes_with_nul()
            );
            assert_eq!(&buffer[..4], &[0xa5; 4]);
            assert_eq!(&buffer[buffer.len() - 4..], &[0xa5; 4]);
        }
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
