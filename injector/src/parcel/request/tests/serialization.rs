use super::*;

#[test]
fn bad_interface_marker_is_rejected() {
    let blob_key = blob_key_descriptor(None);
    let mut request = build_request_with_marker(KEYSTORE_SECURITY_LEVEL_INTERFACE, 0, |parcel| {
        parcel.write(&blob_key).unwrap()
    });
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut request);

    assert_status_code(
        unsafe {
            parse_security_level_request(
                data,
                data_size,
                offsets,
                offsets_size,
                crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#deleteKey,
            )
        },
        StatusCode::BadType,
    );
}

#[test]
fn generated_key_descriptor_round_trip_preserves_non_null_empty_blob() {
    let key = blob_key_descriptor(Some(Vec::new()));
    let mut parcel = Parcel::new();
    parcel.write(&key).unwrap();
    parcel.set_data_position(0);

    let decoded: KeyDescriptor = parcel.read().unwrap();
    assert_eq!(decoded.blob, Some(Vec::new()));
}

#[test]
fn generated_deserializers_reject_invalid_lengths_and_truncated_present_objects() {
    assert_status_code(
        parse_authorization_request_as_method(AuthorizationMethod::OnDeviceUnlocked, |parcel| {
            parcel.write(&0i32).unwrap();
            parcel.write(&-2i32).unwrap();
        }),
        StatusCode::UnexpectedNull,
    );
    assert_status_code(
        parse_operation_request_with_payload(
            crate::android::system::keystore2::IKeystoreOperation::transactions::r#update,
            |parcel| parcel.write(&-2i32).unwrap(),
        ),
        StatusCode::UnexpectedNull,
    );
    assert_status_code(
        parse_security_level_request_with_payload(
            crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#deleteKey,
            |parcel| parcel.write(&2i32).unwrap(),
        ),
        StatusCode::NotEnoughData,
    );
    assert_status_code(
        parse_security_level_request_with_payload(
            crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#generateKey,
            |parcel| {
                parcel.write(&blob_key_descriptor(None)).unwrap();
                parcel.write(&2i32).unwrap();
            },
        ),
        StatusCode::NotEnoughData,
    );
}
