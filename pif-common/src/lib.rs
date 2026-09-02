use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const MAX_CATALOG_BYTES: usize = 64 * 1024;
pub const MAX_CATALOG_ENTRIES: usize = 64;
pub const MAX_PROP_BYTES: usize = 4 * 1024;
pub const MAX_PROFILE_BYTES: usize = 4 * 1024;
pub const MAX_VALUE_BYTES: usize = 126;
pub const PROFILE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceEntry {
    pub model: String,
    pub product: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PifProfile {
    pub version: u32,
    pub model: String,
    pub product: String,
    pub manufacturer: String,
    pub fingerprint: String,
    pub brand: String,
    pub device: String,
    pub release: String,
    pub id: String,
    pub incremental: String,
    pub build_type: String,
    pub tags: String,
    pub security_patch: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceProfile {
    fingerprint: String,
    manufacturer: String,
    model: String,
    security_patch: String,
}

#[derive(Debug, Clone, Copy)]
struct FingerprintParts<'a> {
    brand: &'a str,
    product: &'a str,
    device: &'a str,
    release: &'a str,
    id: &'a str,
    incremental: &'a str,
    build_type: &'a str,
    tags: &'a str,
}

impl DeviceEntry {
    pub fn validate(&self) -> Result<(), String> {
        validate_display_value("model", &self.model)?;
        validate_product(&self.product)
    }
}

impl PifProfile {
    pub fn from_source(selected: &DeviceEntry, contents: &[u8]) -> Result<Self, String> {
        selected.validate()?;
        let source = parse_source_profile(contents)?;
        if source.model != selected.model {
            return Err("profile MODEL does not match the selected catalog entry".to_string());
        }

        // Keep the parsed components independent from the source string so the
        // validated source can be moved into the stored profile below.
        let fingerprint_value = source.fingerprint.clone();
        let fingerprint = parse_fingerprint(&fingerprint_value)?;
        if fingerprint.product != selected.product {
            return Err("fingerprint PRODUCT does not match the selected product".to_string());
        }
        if source.manufacturer != "Google" || fingerprint.brand != "google" {
            return Err("PIF profile must describe a Google device".to_string());
        }
        if fingerprint.build_type != "user" || fingerprint.tags != "release-keys" {
            return Err("fingerprint must describe a user/release-keys build".to_string());
        }
        validate_security_patch_date(&source.security_patch)?;

        let profile = Self {
            version: PROFILE_VERSION,
            model: source.model,
            product: fingerprint.product.to_string(),
            manufacturer: source.manufacturer,
            fingerprint: source.fingerprint,
            brand: fingerprint.brand.to_string(),
            device: fingerprint.device.to_string(),
            release: fingerprint.release.to_string(),
            id: fingerprint.id.to_string(),
            incremental: fingerprint.incremental.to_string(),
            build_type: fingerprint.build_type.to_string(),
            tags: fingerprint.tags.to_string(),
            security_patch: source.security_patch,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != PROFILE_VERSION {
            return Err(format!("unsupported PIF profile version {}", self.version));
        }
        validate_display_value("model", &self.model)?;
        validate_product(&self.product)?;
        validate_display_value("manufacturer", &self.manufacturer)?;
        validate_security_patch_date(&self.security_patch)?;

        let parts = parse_fingerprint(&self.fingerprint)?;
        let expected = [
            ("brand", self.brand.as_str(), parts.brand),
            ("product", self.product.as_str(), parts.product),
            ("device", self.device.as_str(), parts.device),
            ("release", self.release.as_str(), parts.release),
            ("id", self.id.as_str(), parts.id),
            ("incremental", self.incremental.as_str(), parts.incremental),
            ("build_type", self.build_type.as_str(), parts.build_type),
            ("tags", self.tags.as_str(), parts.tags),
        ];
        for (name, actual, from_fingerprint) in expected {
            validate_component(name, actual)?;
            if actual != from_fingerprint {
                return Err(format!("stored {name} does not match fingerprint"));
            }
        }
        if self.manufacturer != "Google" || self.brand != "google" {
            return Err("stored PIF profile must describe a Google device".to_string());
        }
        if self.build_type != "user" || self.tags != "release-keys" {
            return Err("stored fingerprint must describe a user/release-keys build".to_string());
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<String, String> {
        self.validate()?;
        let json = serde_json::to_string(self)
            .map_err(|error| format!("failed to serialize PIF profile: {error}"))?;
        if json.len() > MAX_PROFILE_BYTES {
            return Err("serialized PIF profile exceeds the 4 KiB limit".to_string());
        }
        Ok(json)
    }

    pub fn from_json(contents: &[u8]) -> Result<Self, String> {
        if contents.len() > MAX_PROFILE_BYTES {
            return Err("PIF profile exceeds the 4 KiB limit".to_string());
        }
        let profile: Self = serde_json::from_slice(contents)
            .map_err(|error| format!("invalid PIF profile JSON: {error}"))?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn build_fields(&self) -> [(&'static str, &'_ str, BuildClass); 12] {
        [
            ("MANUFACTURER", &self.manufacturer, BuildClass::Build),
            ("MODEL", &self.model, BuildClass::Build),
            ("FINGERPRINT", &self.fingerprint, BuildClass::Build),
            ("BRAND", &self.brand, BuildClass::Build),
            ("PRODUCT", &self.product, BuildClass::Build),
            ("DEVICE", &self.device, BuildClass::Build),
            ("RELEASE", &self.release, BuildClass::Version),
            ("ID", &self.id, BuildClass::Build),
            ("INCREMENTAL", &self.incremental, BuildClass::Version),
            ("TYPE", &self.build_type, BuildClass::Build),
            ("TAGS", &self.tags, BuildClass::Build),
            ("SECURITY_PATCH", &self.security_patch, BuildClass::Version),
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildClass {
    Build,
    Version,
}

pub fn parse_catalog(contents: &[u8]) -> Result<Vec<DeviceEntry>, String> {
    if contents.len() > MAX_CATALOG_BYTES {
        return Err("PIF device catalog exceeds the 64 KiB limit".to_string());
    }
    let entries: Vec<DeviceEntry> = serde_json::from_slice(contents)
        .map_err(|error| format!("invalid PIF device catalog JSON: {error}"))?;
    if entries.is_empty() {
        return Err("PIF device catalog is empty".to_string());
    }
    if entries.len() > MAX_CATALOG_ENTRIES {
        return Err(format!(
            "PIF device catalog contains more than {MAX_CATALOG_ENTRIES} entries"
        ));
    }

    let mut products = BTreeSet::new();
    for entry in &entries {
        entry.validate()?;
        if !products.insert(entry.product.as_str()) {
            return Err(format!(
                "PIF device catalog contains duplicate product {}",
                entry.product
            ));
        }
    }
    Ok(entries)
}

pub fn validate_product(value: &str) -> Result<(), String> {
    validate_length_and_ascii("product", value)?;
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err("product must not be empty".to_string());
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err("product must start with a lowercase ASCII letter or digit".to_string());
    }
    if !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_') {
        return Err("product contains an unsupported character".to_string());
    }
    Ok(())
}

fn parse_source_profile(contents: &[u8]) -> Result<SourceProfile, String> {
    if contents.len() > MAX_PROP_BYTES {
        return Err("PIF source profile exceeds the 4 KiB limit".to_string());
    }
    let text = std::str::from_utf8(contents)
        .map_err(|error| format!("PIF source profile is not UTF-8: {error}"))?;
    if text.contains('\0') {
        return Err("PIF source profile contains NUL".to_string());
    }

    let mut fingerprint = None;
    let mut manufacturer = None;
    let mut model = None;
    let mut security_patch = None;
    let normalized = text.replace("\r\n", "\n");
    if normalized.contains('\r') {
        return Err("PIF source profile contains an invalid line ending".to_string());
    }
    for (index, line) in normalized.split('\n').enumerate() {
        if line.is_empty() && index + 1 == normalized.split('\n').count() {
            continue;
        }
        if line.is_empty() {
            return Err("PIF source profile contains an empty line".to_string());
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("PIF source profile line {} has no '='", index + 1))?;
        validate_length_and_ascii(key, value)?;
        let slot = match key {
            "FINGERPRINT" => &mut fingerprint,
            "MANUFACTURER" => &mut manufacturer,
            "MODEL" => &mut model,
            "SECURITY_PATCH" => &mut security_patch,
            _ => return Err(format!("PIF source profile contains unknown key {key}")),
        };
        if slot.replace(value.to_string()).is_some() {
            return Err(format!("PIF source profile contains duplicate key {key}"));
        }
    }

    let source = SourceProfile {
        fingerprint: fingerprint
            .ok_or_else(|| "PIF source profile lacks FINGERPRINT".to_string())?,
        manufacturer: manufacturer
            .ok_or_else(|| "PIF source profile lacks MANUFACTURER".to_string())?,
        model: model.ok_or_else(|| "PIF source profile lacks MODEL".to_string())?,
        security_patch: security_patch
            .ok_or_else(|| "PIF source profile lacks SECURITY_PATCH".to_string())?,
    };
    validate_display_value("MANUFACTURER", &source.manufacturer)?;
    validate_display_value("MODEL", &source.model)?;
    Ok(source)
}

fn parse_fingerprint(value: &str) -> Result<FingerprintParts<'_>, String> {
    validate_length_and_ascii("FINGERPRINT", value)?;
    let colon_parts: Vec<&str> = value.split(':').collect();
    if colon_parts.len() != 3 {
        return Err("fingerprint must contain exactly eight components".to_string());
    }
    let identity: Vec<&str> = colon_parts[0].split('/').collect();
    let build: Vec<&str> = colon_parts[1].split('/').collect();
    let variant: Vec<&str> = colon_parts[2].split('/').collect();
    if identity.len() != 3 || build.len() != 3 || variant.len() != 2 {
        return Err("fingerprint must contain exactly eight components".to_string());
    }
    let parts = FingerprintParts {
        brand: identity[0],
        product: identity[1],
        device: identity[2],
        release: build[0],
        id: build[1],
        incremental: build[2],
        build_type: variant[0],
        tags: variant[1],
    };
    for (name, part) in [
        ("brand", parts.brand),
        ("product", parts.product),
        ("device", parts.device),
        ("release", parts.release),
        ("id", parts.id),
        ("incremental", parts.incremental),
        ("build_type", parts.build_type),
        ("tags", parts.tags),
    ] {
        validate_component(name, part)?;
    }
    validate_product(parts.product)?;
    Ok(parts)
}

fn validate_component(name: &str, value: &str) -> Result<(), String> {
    validate_length_and_ascii(name, value)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'+' | b',')
    }) {
        return Err(format!("{name} contains an unsupported character"));
    }
    Ok(())
}

fn validate_display_value(name: &str, value: &str) -> Result<(), String> {
    validate_length_and_ascii(name, value)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b' ' | b'_' | b'.' | b'-' | b'+' | b'(' | b')')
    }) {
        return Err(format!("{name} contains an unsupported character"));
    }
    Ok(())
}

fn validate_length_and_ascii(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    if value.len() > MAX_VALUE_BYTES {
        return Err(format!("{name} exceeds the {MAX_VALUE_BYTES} byte limit"));
    }
    if value.trim() != value || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err(format!("{name} must be trimmed printable ASCII"));
    }
    Ok(())
}

fn validate_security_patch_date(value: &str) -> Result<(), String> {
    validate_length_and_ascii("SECURITY_PATCH", value)?;
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return Err("SECURITY_PATCH must use YYYY-MM-DD".to_string());
    }
    let year = value[0..4].parse::<u32>().map_err(|_| "invalid year")?;
    let month = value[5..7].parse::<u32>().map_err(|_| "invalid month")?;
    let day = value[8..10].parse::<u32>().map_err(|_| "invalid day")?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err("SECURITY_PATCH contains an invalid month".to_string()),
    };
    if year < 2000 || day == 0 || day > max_day {
        return Err("SECURITY_PATCH is not a valid calendar date".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROP: &str = "FINGERPRINT=google/oriole_beta/oriole:CANARY/ZP11.260717.006/16004061:user/release-keys\nMANUFACTURER=Google\nMODEL=Pixel 6\nSECURITY_PATCH=2026-08-05\n";

    fn selected() -> DeviceEntry {
        DeviceEntry {
            model: "Pixel 6".to_string(),
            product: "oriole_beta".to_string(),
        }
    }

    #[test]
    fn parses_catalog_and_rejects_duplicates_or_unknown_fields() {
        let catalog = br#"[{"model":"Pixel 6","product":"oriole_beta"}]"#;
        assert_eq!(parse_catalog(catalog).unwrap(), vec![selected()]);
        assert!(parse_catalog(
            br#"[{"model":"Pixel 6","product":"oriole_beta"},{"model":"Other","product":"oriole_beta"}]"#
        )
        .is_err());
        assert!(parse_catalog(
            br#"[{"model":"Pixel 6","product":"oriole_beta","url":"https://example.com"}]"#
        )
        .is_err());
    }

    #[test]
    fn catalog_enforces_entry_and_byte_limits() {
        let entries = (0..=MAX_CATALOG_ENTRIES)
            .map(|index| format!(r#"{{"model":"Pixel {index}","product":"pixel_{index}"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_catalog(format!("[{entries}]").as_bytes()).is_err());
        assert!(parse_catalog(&vec![b' '; MAX_CATALOG_BYTES + 1]).is_err());
    }

    #[test]
    fn product_validation_blocks_path_syntax_and_mixed_case() {
        for product in ["oriole_beta", "pixel10", "a_b"] {
            validate_product(product).unwrap();
        }
        for product in ["", "../oriole", "oriole.prop", "Pixel_6", "a-b", "_oriole"] {
            assert!(validate_product(product).is_err(), "{product}");
        }
    }

    #[test]
    fn source_profile_expands_all_fingerprint_fields() {
        let profile = PifProfile::from_source(&selected(), PROP.as_bytes()).unwrap();
        assert_eq!(profile.brand, "google");
        assert_eq!(profile.product, "oriole_beta");
        assert_eq!(profile.device, "oriole");
        assert_eq!(profile.release, "CANARY");
        assert_eq!(profile.id, "ZP11.260717.006");
        assert_eq!(profile.incremental, "16004061");
        assert_eq!(profile.build_type, "user");
        assert_eq!(profile.tags, "release-keys");
        assert_eq!(profile.build_fields().len(), 12);
    }

    #[test]
    fn source_profile_accepts_crlf_but_rejects_other_shape_changes() {
        PifProfile::from_source(&selected(), PROP.replace('\n', "\r\n").as_bytes()).unwrap();
        for malformed in [
            PROP.replace("MODEL=", "UNKNOWN="),
            format!("{PROP}MODEL=Pixel 6\n"),
            PROP.replace("MODEL=Pixel 6\n", ""),
            PROP.replace("MODEL=Pixel 6", "MODEL=Pixel 6\n\n"),
        ] {
            assert!(PifProfile::from_source(&selected(), malformed.as_bytes()).is_err());
        }
    }

    #[test]
    fn source_profile_requires_catalog_model_and_product_match() {
        assert!(PifProfile::from_source(
            &DeviceEntry {
                model: "Pixel 6 Pro".to_string(),
                product: "oriole_beta".to_string(),
            },
            PROP.as_bytes(),
        )
        .is_err());
        assert!(PifProfile::from_source(
            &DeviceEntry {
                model: "Pixel 6".to_string(),
                product: "raven_beta".to_string(),
            },
            PROP.as_bytes(),
        )
        .is_err());
    }

    #[test]
    fn source_profile_rejects_non_google_devices() {
        let non_google = PROP
            .replace("google/oriole_beta", "example/oriole_beta")
            .replace("MANUFACTURER=Google", "MANUFACTURER=Example");
        assert!(PifProfile::from_source(&selected(), non_google.as_bytes()).is_err());
    }

    #[test]
    fn source_profile_requires_exact_eight_part_release_fingerprint() {
        for fingerprint in [
            "google/oriole_beta/oriole:CANARY/ZP11.260717.006:user/release-keys",
            "google/oriole_beta/oriole/extra:CANARY/ZP11.260717.006/1:user/release-keys",
            "google/oriole_beta/oriole:CANARY/ZP11.260717.006/1:user/debug-keys",
            "google/oriole_beta/oriole:CANARY/ZP11.260717.006/1:userdebug/release-keys",
        ] {
            let malformed = PROP.replace(
                "google/oriole_beta/oriole:CANARY/ZP11.260717.006/16004061:user/release-keys",
                fingerprint,
            );
            assert!(PifProfile::from_source(&selected(), malformed.as_bytes()).is_err());
        }
    }

    #[test]
    fn validates_real_calendar_patch_dates() {
        let mut profile = PifProfile::from_source(&selected(), PROP.as_bytes()).unwrap();
        for valid in ["2024-02-29", "2026-08-05"] {
            profile.security_patch = valid.to_string();
            profile.validate().unwrap();
        }
        for invalid in ["2023-02-29", "2026-13-05", "2026-04-31", "1999-12-31"] {
            profile.security_patch = invalid.to_string();
            assert!(profile.validate().is_err(), "{invalid}");
        }
    }

    #[test]
    fn stored_json_rejects_unknown_or_inconsistent_fields() {
        let profile = PifProfile::from_source(&selected(), PROP.as_bytes()).unwrap();
        let json = profile.to_canonical_json().unwrap();
        assert_eq!(PifProfile::from_json(json.as_bytes()).unwrap(), profile);
        assert!(PifProfile::from_json(
            json.replace("\"brand\":\"google\"", "\"brand\":\"evil\"")
                .as_bytes()
        )
        .is_err());
        assert!(PifProfile::from_json(
            json.strip_suffix('}')
                .map(|prefix| format!("{prefix},\"extra\":true}}"))
                .unwrap()
                .as_bytes()
        )
        .is_err());
    }

    #[test]
    fn every_external_value_obeys_the_byte_limit() {
        let oversized = "A".repeat(MAX_VALUE_BYTES + 1);
        let malformed = PROP.replace("Pixel 6", &oversized);
        assert!(PifProfile::from_source(&selected(), malformed.as_bytes()).is_err());
    }
}
