//! Root-private staging of issued Keyboxes. Creation and listing never import keys.
use anyhow::{anyhow, bail, Context, Result};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};
use zeroize::Zeroizing;

const ROOT: &str = crate::root_path!("data/rkp-artifacts");
const MAX_ARTIFACTS: usize = 16;

#[derive(Serialize)]
pub struct Summary {
    pub id: String,
    pub created_at: u64,
    pub chain_subjects: Vec<String>,
}

fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("RKP result operations require root");
    }
    Ok(())
}

fn private_directory(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if meta.uid() != 0 || meta.mode() & 0o077 != 0 {
        bail!("RKP result directory must be root-owned and private");
    }
    Ok(file)
}

/// Storage readiness/capacity check performed BEFORE the signing request.
pub fn prepare() -> Result<()> {
    require_root()?;
    match fs::DirBuilder::new().mode(0o700).create(ROOT) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error).context("create RKP results directory"),
    }
    let _root = private_directory(Path::new(ROOT))?;
    if ids()?.len() >= MAX_ARTIFACTS {
        bail!("RKP result limit reached; remove unneeded staged results before issuing again");
    }
    Ok(())
}

pub fn validate_id(id: &str) -> Result<()> {
    if id.len() != 32
        || !id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        bail!("invalid RKP result ID");
    }
    Ok(())
}

fn ids() -> Result<Vec<String>> {
    let mut ids = Vec::new();
    for entry in fs::read_dir(ROOT)? {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("invalid RKP result entry"))?;
        validate_id(&name)?;
        if ids.len() >= MAX_ARTIFACTS {
            bail!("too many RKP results");
        }
        ids.push(name);
    }
    ids.sort();
    Ok(ids)
}

pub fn store_issued_keybox(xml: &[u8]) -> Result<String> {
    require_root()?;
    crate::local_rkp::validate_issued_xml(xml)?;
    prepare()?;
    let mut raw = [0; 16];
    SystemRandom::new()
        .fill(&mut raw)
        .map_err(|_| anyhow!("cannot allocate RKP result ID"))?;
    let id = hex::encode(raw);
    let directory = Path::new(ROOT).join(&id);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .context("reserve RKP result directory")?;
    let result = (|| -> Result<()> {
        let _directory = private_directory(&directory)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(directory.join("keybox.xml"))?;
        file.write_all(xml)?;
        file.sync_all()?;
        _directory.sync_all()?;
        File::open(ROOT)?.sync_all()?;
        Ok(())
    })();
    if let Err(error) = result {
        // Only this newly reserved, exact ID directory is removed on failed staging.
        let _ = fs::remove_dir_all(&directory);
        return Err(error).context("save private RKP result");
    }
    Ok(id)
}

fn open_result(id: &str) -> Result<(File, PathBuf)> {
    validate_id(id)?;
    let _root = private_directory(Path::new(ROOT))?;
    let directory = Path::new(ROOT).join(id);
    let _dir = private_directory(&directory)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(directory.join("keybox.xml"))?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
        || meta.len() > crate::keybox::MAX_KEYBOX_XML_BYTES as u64
    {
        bail!("RKP result file has unsafe type, owner, permissions or size");
    }
    Ok((file, directory))
}

fn read_result(file: File) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(crate::keybox::MAX_KEYBOX_XML_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > crate::keybox::MAX_KEYBOX_XML_BYTES {
        bail!("RKP result exceeds size limit");
    }
    Ok(bytes)
}

fn summary(id: &str) -> Result<Summary> {
    let (file, _) = open_result(id)?;
    let created_at = file
        .metadata()?
        .modified()?
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    let xml = read_result(file)?;
    let parsed = crate::keybox::KeyBox::from_xml_str(
        std::str::from_utf8(&xml).context("invalid RKP result encoding")?,
    )
    .map_err(|_| anyhow!("RKP result is not a valid Keybox"))?;
    let inspector = parsed.inspector();
    let chain = inspector.ec.context("RKP result has no EC chain")?;
    let chain_subjects: Vec<_> = chain
        .certificates
        .into_iter()
        .map(|cert| cert.subject)
        .collect();
    if chain_subjects.is_empty()
        || chain_subjects.len() > 8
        || chain_subjects
            .iter()
            .any(|subject| subject.len() > 512 || subject.chars().any(char::is_control))
    {
        bail!("RKP result metadata is out of bounds");
    }
    Ok(Summary {
        id: id.into(),
        created_at,
        chain_subjects,
    })
}

pub fn summary_json(id: &str) -> Result<String> {
    require_root()?;
    serde_json::to_string(&summary(id)?).context("encode public RKP result metadata")
}

pub fn list_json() -> Result<String> {
    require_root()?;
    #[derive(Serialize)]
    struct List {
        artifacts: Vec<Summary>,
    }
    // Listing an empty state is read-only; do not create storage just by opening UI.
    let artifacts = if !Path::new(ROOT).try_exists()? {
        Vec::new()
    } else {
        let _root = private_directory(Path::new(ROOT))?;
        let mut entries = ids()?
            .iter()
            .map(|id| summary(id))
            .collect::<Result<Vec<_>>>()?;
        entries.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        entries
    };
    serde_json::to_string(&List { artifacts }).context("encode RKP result list")
}

pub fn import(id: &str) -> Result<()> {
    require_root()?;
    let (file, _) = open_result(id)?;
    let xml = read_result(file)?;
    // Recheck dates/signatures/trust AND private-key matching when importing, not
    // just when issuing. Expired results can be listed, but cannot be installed.
    crate::local_rkp::validate_issued_xml(&xml)?;
    crate::keybox::install_keybox_xml(&xml).context("import issued RKP Keybox")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn private_directories_reject_links_files_and_broad_permissions() {
        let parent = tempfile::tempdir().unwrap();
        let private = parent.path().join("private");
        fs::DirBuilder::new().mode(0o700).create(&private).unwrap();
        let link = parent.path().join("link");
        symlink(&private, &link).unwrap();
        assert!(private_directory(&link).is_err());
        let file = parent.path().join("regular");
        fs::write(&file, b"not a directory").unwrap();
        assert!(private_directory(&file).is_err());
        fs::set_permissions(&private, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(private_directory(&private).is_err());
        // TempDir deletes these public test-only artifacts even on unwind.
    }

    #[test]
    fn reads_of_result_xml_are_bounded() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&vec![0; crate::keybox::MAX_KEYBOX_XML_BYTES + 1])
            .unwrap();
        use std::io::Seek;
        file.rewind().unwrap();
        assert!(read_result(file).is_err());
    }

    #[test]
    fn result_ids_cannot_escape_storage() {
        assert!(validate_id("0123456789abcdef0123456789abcdef").is_ok());
        for id in [
            "",
            "../test",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcdef/",
            "a.xml",
        ] {
            assert!(validate_id(id).is_err());
        }
    }
    #[test]
    fn metadata_contains_no_xml_keys_or_paths() {
        let value = serde_json::to_value(Summary {
            id: "a".repeat(32),
            created_at: 1,
            chain_subjects: vec!["CN=test".into()],
        })
        .unwrap();
        assert_eq!(value.as_object().unwrap().len(), 3);
        for key in ["keybox_xml", "private_key", "path"] {
            assert!(value.get(key).is_none());
        }
    }
}
