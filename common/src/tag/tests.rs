// Copyright 2022, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;
use crate::expect_err;
use kmr_wire::{keymint::KeyParam, KeySizeInBits};
use std::vec;

#[test]
fn test_asymmetric_invalid_purposes() {
    for (algorithm, invalid_purpose) in [
        (Algorithm::Rsa, KeyPurpose::AgreeKey),
        (Algorithm::Ec, KeyPurpose::WrapKey),
        (Algorithm::MlDsa, KeyPurpose::Encrypt),
        (Algorithm::MlDsa, KeyPurpose::Decrypt),
        (Algorithm::MlDsa, KeyPurpose::WrapKey),
        (Algorithm::MlDsa, KeyPurpose::AgreeKey),
    ] {
        for purposes in [
            vec![invalid_purpose],
            vec![KeyPurpose::Sign, invalid_purpose],
            vec![invalid_purpose, KeyPurpose::Sign],
        ] {
            let params: Vec<_> = purposes.iter().copied().map(KeyParam::Purpose).collect();
            let result = match algorithm {
                Algorithm::Rsa => check_rsa_params(&params),
                Algorithm::Ec => {
                    check_ec_params(EcCurve::P256, &params, SecurityLevel::TrustedEnvironment)
                        .map(|_| ())
                }
                Algorithm::MlDsa => check_mldsa_params(&params, SecurityLevel::TrustedEnvironment),
                _ => unreachable!(),
            };
            let error = result.expect_err("invalid asymmetric purpose must be rejected");
            assert!(
                matches!(error.kind(), crate::ErrorKind::Hal(ErrorCode::IncompatiblePurpose, _)),
                "unexpected error for {algorithm:?} {purposes:?}: {error:?}"
            );
        }
    }
}

#[test]
fn test_rsa_valid_purposes() {
    let non_attest_purposes = [
        KeyPurpose::Encrypt,
        KeyPurpose::Decrypt,
        KeyPurpose::Sign,
        KeyPurpose::Verify,
        KeyPurpose::WrapKey,
    ];
    for purpose in non_attest_purposes {
        check_rsa_params(&[KeyParam::Purpose(purpose)]).unwrap();
    }
    let params: Vec<_> = non_attest_purposes.into_iter().map(KeyParam::Purpose).collect();
    check_rsa_params(&params).unwrap();
    check_rsa_params(&[]).unwrap();
    check_rsa_params(&[KeyParam::Purpose(KeyPurpose::AttestKey)]).unwrap();
    // Preserve the existing treatment of public-key purposes with ATTEST_KEY.
    check_rsa_params(&[
        KeyParam::Purpose(KeyPurpose::AttestKey),
        KeyParam::Purpose(KeyPurpose::Verify),
        KeyParam::Purpose(KeyPurpose::Encrypt),
    ])
    .unwrap();
}

#[test]
fn test_ec_valid_purposes() {
    for purpose in
        [KeyPurpose::Sign, KeyPurpose::Verify, KeyPurpose::AgreeKey, KeyPurpose::AttestKey]
    {
        assert_eq!(
            check_ec_params(
                EcCurve::P256,
                &[KeyParam::Purpose(purpose)],
                SecurityLevel::TrustedEnvironment
            )
            .unwrap(),
            Some(purpose)
        );
    }
    for purposes in [
        vec![KeyPurpose::Sign, KeyPurpose::Verify, KeyPurpose::AgreeKey],
        vec![KeyPurpose::AttestKey, KeyPurpose::Verify],
        vec![],
    ] {
        let params: Vec<_> = purposes.iter().copied().map(KeyParam::Purpose).collect();
        assert_eq!(
            check_ec_params(EcCurve::P256, &params, SecurityLevel::TrustedEnvironment).unwrap(),
            purposes.first().copied()
        );
    }
}

#[test]
fn test_ec_compatibility_purposes_allow_signing_in_either_order() {
    for compatibility_purpose in [KeyPurpose::Encrypt, KeyPurpose::Decrypt] {
        for purposes in
            [[KeyPurpose::Sign, compatibility_purpose], [compatibility_purpose, KeyPurpose::Sign]]
        {
            let params = [
                KeyParam::EcCurve(EcCurve::P256),
                KeyParam::Purpose(purposes[0]),
                KeyParam::Purpose(purposes[1]),
            ];
            assert_eq!(
                check_ec_params(EcCurve::P256, &params, SecurityLevel::TrustedEnvironment).unwrap(),
                Some(KeyPurpose::Sign)
            );
            assert!(matches!(
                check_ec_gen_params(&params, SecurityLevel::TrustedEnvironment).unwrap(),
                KeyGenInfo::NistEc(crate::crypto::ec::NistCurve::P256)
            ));
        }
    }
}

#[test]
fn test_ec_redundant_encryption_purposes_have_narrow_scope() {
    for curve in [EcCurve::P224, EcCurve::P256, EcCurve::P384, EcCurve::P521, EcCurve::Curve25519] {
        for extra in [KeyPurpose::Encrypt, KeyPurpose::Decrypt] {
            for purposes in [
                vec![extra],
                vec![KeyPurpose::Verify, extra],
                vec![extra, KeyPurpose::AttestKey],
                vec![KeyPurpose::AttestKey, extra],
                vec![extra, KeyPurpose::AgreeKey],
                vec![KeyPurpose::Sign, extra, KeyPurpose::AgreeKey],
                vec![KeyPurpose::Sign, extra],
                vec![extra, KeyPurpose::Sign],
            ] {
                let params: Vec<_> = purposes.iter().copied().map(KeyParam::Purpose).collect();
                let result = check_ec_params(curve, &params, SecurityLevel::TrustedEnvironment);
                if curve == EcCurve::P256
                    && purposes.contains(&KeyPurpose::Sign)
                    && !purposes.contains(&KeyPurpose::AgreeKey)
                {
                    assert_eq!(result.unwrap(), Some(KeyPurpose::Sign));
                } else {
                    let error = result.expect_err("unsupported EC purpose combination accepted");
                    assert!(matches!(
                        error.kind(),
                        crate::ErrorKind::Hal(ErrorCode::IncompatiblePurpose, _)
                    ));
                }
            }
        }
    }
}

#[test]
fn test_curve25519_verify_does_not_select_the_key_type() {
    for private_purpose in [KeyPurpose::Sign, KeyPurpose::AttestKey, KeyPurpose::AgreeKey] {
        for purposes in
            [[KeyPurpose::Verify, private_purpose], [private_purpose, KeyPurpose::Verify]]
        {
            let params = [
                KeyParam::EcCurve(EcCurve::Curve25519),
                KeyParam::Purpose(purposes[0]),
                KeyParam::Purpose(purposes[1]),
            ];
            let info = check_ec_gen_params(&params, SecurityLevel::TrustedEnvironment).unwrap();
            match private_purpose {
                KeyPurpose::AgreeKey => assert!(matches!(info, KeyGenInfo::X25519)),
                _ => assert!(matches!(info, KeyGenInfo::Ed25519)),
            }
        }
    }
}

#[test]
fn test_mldsa_valid_purposes() {
    for purposes in [
        vec![KeyPurpose::Sign],
        vec![KeyPurpose::Verify],
        vec![KeyPurpose::AttestKey],
        vec![KeyPurpose::Sign, KeyPurpose::Verify],
        vec![KeyPurpose::AttestKey, KeyPurpose::Verify],
        vec![],
    ] {
        let params: Vec<_> = purposes.into_iter().map(KeyParam::Purpose).collect();
        check_mldsa_params(&params, SecurityLevel::TrustedEnvironment).unwrap();
    }
}

#[test]
fn test_asymmetric_attest_key_excludes_private_key_purposes() {
    for (algorithm, other_purpose) in [
        (Algorithm::Rsa, KeyPurpose::Sign),
        (Algorithm::Rsa, KeyPurpose::Decrypt),
        (Algorithm::Rsa, KeyPurpose::WrapKey),
        (Algorithm::Ec, KeyPurpose::Sign),
        (Algorithm::Ec, KeyPurpose::AgreeKey),
        (Algorithm::MlDsa, KeyPurpose::Sign),
    ] {
        for purposes in
            [[KeyPurpose::AttestKey, other_purpose], [other_purpose, KeyPurpose::AttestKey]]
        {
            let params = purposes.map(KeyParam::Purpose);
            let result = match algorithm {
                Algorithm::Rsa => check_rsa_params(&params),
                Algorithm::Ec => {
                    check_ec_params(EcCurve::P256, &params, SecurityLevel::TrustedEnvironment)
                        .map(|_| ())
                }
                Algorithm::MlDsa => check_mldsa_params(&params, SecurityLevel::TrustedEnvironment),
                _ => unreachable!(),
            };
            let error = result.expect_err("ATTEST_KEY must exclude other private-key purposes");
            assert!(
                matches!(error.kind(), crate::ErrorKind::Hal(ErrorCode::IncompatiblePurpose, _)),
                "unexpected error for {algorithm:?} {purposes:?}: {error:?}"
            );
        }
    }
}

#[test]
fn test_curve25519_signing_and_agreement_purposes_stay_separate() {
    for purpose in [KeyPurpose::Sign, KeyPurpose::AttestKey, KeyPurpose::AgreeKey] {
        let keygen_info = check_ec_gen_params(
            &[KeyParam::EcCurve(EcCurve::Curve25519), KeyParam::Purpose(purpose)],
            SecurityLevel::TrustedEnvironment,
        )
        .unwrap();
        match purpose {
            KeyPurpose::Sign | KeyPurpose::AttestKey => {
                assert!(matches!(keygen_info, KeyGenInfo::Ed25519));
            }
            KeyPurpose::AgreeKey => assert!(matches!(keygen_info, KeyGenInfo::X25519)),
            _ => unreachable!(),
        }
    }
    for signing_purpose in [KeyPurpose::Sign, KeyPurpose::AttestKey] {
        for purposes in
            [[signing_purpose, KeyPurpose::AgreeKey], [KeyPurpose::AgreeKey, signing_purpose]]
        {
            let params = purposes.map(KeyParam::Purpose);
            let error =
                check_ec_params(EcCurve::Curve25519, &params, SecurityLevel::TrustedEnvironment)
                    .expect_err("Curve25519 signing and key agreement cannot be combined");
            assert!(matches!(
                error.kind(),
                crate::ErrorKind::Hal(ErrorCode::IncompatiblePurpose, _)
            ));
        }
    }
}

#[test]
fn test_characteristics_invalid() {
    let tests = vec![
        (vec![KeyParam::UsageCountLimit(42), KeyParam::UsageCountLimit(43)], "duplicate value"),
        (vec![KeyParam::Nonce(vec![1, 2])], "not a valid key characteristic"),
    ];
    for (characteristics, msg) in tests {
        let result = crate::tag::characteristics_valid(&characteristics);
        expect_err!(result, msg);
    }
}

#[test]
fn test_legacy_serialization() {
    let tests = vec![(
        concat!(
            "00000000", // blob data size
            "03000000", // param count
            "15000000", // param size
            "02000010", // Tag::ALGORITHM = 268435458 = 0x10000002,
            "20000000", // Algorithm::AES
            "03000030", // Tag::KEY_SIZE = 805306371 = 0x30000003
            "00010000", // size = 0x00000100
            "fb010070", // Tag::TRUSTED_USER_PRESENCE_REQUIRED = 0x700001fb
            "01",       // True
        ),
        vec![
            KeyParam::Algorithm(Algorithm::Aes),
            KeyParam::KeySize(KeySizeInBits(256)),
            KeyParam::TrustedUserPresenceRequired,
        ],
    )];

    for (hex_data, want_params) in tests {
        let want_data = hex::decode(hex_data).unwrap();

        let got_data = legacy::serialize(&want_params).unwrap();
        assert_eq!(hex::encode(got_data), hex_data);

        let mut data = &want_data[..];
        let got_params = legacy::deserialize(&mut data).unwrap();
        assert!(data.is_empty(), "data left: {}", hex::encode(data));
        assert_eq!(got_params, want_params);
    }
}

#[test]
fn test_copyable_tags() {
    for tag in UNPOLICED_COPYABLE_TAGS {
        let info = info(*tag).unwrap();
        assert!(info.user_can_specify.0, "tag {tag:?} not listed as user-specifiable");
        assert!(
            info.characteristic == info::Characteristic::KeyMintEnforced
                || info.characteristic == info::Characteristic::KeystoreEnforced
                || info.characteristic == info::Characteristic::BothEnforced,
            "tag {:?} with unexpected characteristic {:?}",
            tag,
            info.characteristic
        );
    }
}

#[test]
fn test_luhn_checksum() {
    let tests = vec![(0, 0), (7992739871, 3), (735423462345, 6), (721367498765427, 4)];
    for (input, want) in tests {
        let got = luhn_checksum(input);
        assert_eq!(got, want, "mismatch for input {input}");
    }
}

#[test]
fn test_increment_imei() {
    let tests = vec![
        // Anything that's not ASCII digits gives empty vec.
        ("", ""),
        ("01", ""),
        ("01", ""),
        ("7576", ""),
        ("c328", ""),                 // Invalid UTF-8
        ("18446844073709551613", ""), // 20-digit and bigger than u64::MAX == 18_446_744_073_709_551_615
        // 721367498765404 => 721367498765412
        ("373231333637343938373635343034", "373231333637343938373635343132"),
        ("39393930", "3130303039"), // String gets longer
    ];
    for (input, want) in tests {
        let input_data = hex::decode(input).unwrap();
        let got = increment_imei(&input_data);
        assert_eq!(hex::encode(got), want, "mismatch for input IMEI {input}");
    }
}
