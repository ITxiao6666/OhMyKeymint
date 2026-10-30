use super::*;

fn put(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn fixture(code: i32) -> Vec<u8> {
    let mut data = vec![0u8; 188];
    data[..8].copy_from_slice(b"dex\n039\0");
    put(&mut data, 36, 112);
    put(&mut data, 40, 0x12345678);
    for (header, count, offset) in [(56, 5, 112), (64, 2, 132), (80, 2, 140), (96, 1, 156)] {
        put(&mut data, header, count);
        put(&mut data, header + 4, offset);
    }
    for (index, name) in [STUB, "I", "AAA", FIELD, "unused"].iter().enumerate() {
        let offset = data.len() as u32;
        put(&mut data, 112 + index * 4, offset);
        data.push(name.len() as u8);
        data.extend_from_slice(name.as_bytes());
        data.push(0);
    }
    put(&mut data, 132, 0); // Stub type -> first string
    put(&mut data, 136, 1); // int type -> second string
    data[142..144].copy_from_slice(&1u16.to_le_bytes());
    data[150..152].copy_from_slice(&1u16.to_le_bytes());
    put(&mut data, 144, 2); // field 0 -> AAA
    put(&mut data, 152, 3); // field 1 -> requested transaction
    let class_data = data.len() as u32;
    put(&mut data, 180, class_data);
    data.extend_from_slice(&[2, 0, 0, 0, 0, 0x18, 1, 0x18]);
    let values = data.len() as u32;
    put(&mut data, 184, values);
    data.extend_from_slice(&[2, 0x04, 17, 0x64]);
    data.extend_from_slice(&code.to_le_bytes());
    let size = data.len() as u32;
    put(&mut data, 32, size);
    data
}

#[test]
fn system_stub_constant_supports_oem_insertions_and_encoded_field_order() {
    for code in [15, 76, 88, 89, 256] {
        assert_eq!(Dex::new(&fixture(code)).unwrap().transaction().unwrap(), Some(code as u32));
    }
}

#[test]
fn malformed_framework_never_produces_a_guessed_transaction() {
    for code in [-1, 0, 0x01000000] {
        assert!(Dex::new(&fixture(code)).unwrap().transaction().is_err());
    }
    let valid = fixture(89);
    for length in 0..valid.len() {
        let mut truncated = valid[..length].to_vec();
        if length >= 36 {
            put(&mut truncated, 32, length as u32);
        }
        let result = Dex::new(&truncated).and_then(|dex| dex.transaction());
        assert!(result.is_err(), "truncated length {length}");
    }
    let mut bad = valid.clone();
    put(&mut bad, 60, u32::MAX);
    assert!(Dex::new(&bad).unwrap().transaction().is_err());
    let mut bad = valid;
    let class_data = u32::from_le_bytes(bad[180..184].try_into().unwrap()) as usize;
    bad[class_data + 7] = 0x08; // static but non-final
    assert!(Dex::new(&bad).unwrap().transaction().is_err());
}

#[test]
fn encoded_values_are_bounded_and_nested_values_can_be_skipped() {
    let raw = [0x1c, 2, 0x1e, 0x1d, 0, 1, 0, 0x3f, 0x04, 89];
    let dex = Dex { data: &raw };
    let mut cursor = 0;
    dex.skip_value(&mut cursor, 0).unwrap();
    assert_eq!(cursor, 8);
    for raw in [&[0xff][..], &[0x1c, 0xff][..], &[0x64, 1][..]] {
        assert!(Dex { data: raw }.skip_value(&mut 0, 0).is_err());
    }
}

#[test]
fn installed_android_framework_contract_is_readable() {
    let code = running_processes_transaction().unwrap();
    println!("installed getRunningAppProcesses transaction={code}");
    // Test binaries are not ActivityManager-managed application processes. This
    // validates the live reply layout without borrowing another app's identity.
    assert!(super::super::query_activity_packages(99001, std::process::id()).unwrap().is_empty());
}
