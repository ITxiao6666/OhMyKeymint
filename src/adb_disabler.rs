//! ADB Disabler settings shared by the WebUI command and module boot script.
//!
//! The values are deliberately persisted as a tiny, line-oriented file under
//! the existing OMK data directory.  The boot script can consume this without
//! needing a second parser or a shell-evaluated configuration.

use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

use anyhow::{anyhow, bail, Context, Result};

const STATE_PATH: &str = "/data/misc/keystore/omk/data/adb_disabler.conf";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    pub enabled: bool,
    pub dev_options: bool,
    pub usb_debug: bool,
    pub oem_unlock: bool,
}

impl Settings {
    pub fn from_tokens(tokens: &[String]) -> Result<Self> {
        if tokens.len() != 4 {
            bail!("ADB Disabler requires exactly four values: enabled dev_options usb_debug oem_unlock");
        }
        let parse = |value: &str| match value {
            "0" => Ok(false),
            "1" => Ok(true),
            _ => Err(anyhow!("ADB Disabler values must be 0 or 1")),
        };
        Ok(Self {
            enabled: parse(&tokens[0])?,
            dev_options: parse(&tokens[1])?,
            usb_debug: parse(&tokens[2])?,
            oem_unlock: parse(&tokens[3])?,
        })
    }
}

pub fn state_path() -> &'static str {
    STATE_PATH
}

pub fn read() -> Settings {
    let Ok(contents) = fs::read_to_string(STATE_PATH) else {
        return Settings {
            enabled: false,
            dev_options: true,
            usb_debug: true,
            oem_unlock: true,
        };
    };
    let values = contents.lines().map(str::to_string).collect::<Vec<_>>();
    Settings::from_tokens(&values).unwrap_or(Settings {
        enabled: false,
        dev_options: true,
        usb_debug: true,
        oem_unlock: true,
    })
}

pub fn persist(settings: Settings) -> Result<()> {
    let path = Path::new(STATE_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("failed to create OMK data directory")?;
    }
    let contents = format!(
        "{}\n{}\n{}\n{}\n",
        u8::from(settings.enabled),
        u8::from(settings.dev_options),
        u8::from(settings.usb_debug),
        u8::from(settings.oem_unlock)
    );
    let temporary = path.with_extension("conf.tmp");
    fs::write(&temporary, contents).context("failed to write ADB Disabler settings")?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).ok();
    fs::rename(&temporary, path).context("failed to install ADB Disabler settings")?;
    Ok(())
}

fn run_settings(args: &[&str]) -> Result<()> {
    let program = if Path::new("/system/bin/settings").exists() {
        "/system/bin/settings"
    } else {
        "settings"
    };
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("failed to execute {program}"))?;
    if status.success() {
        Ok(())
    } else {
        bail!("{program} exited with status {status}")
    }
}

fn run_resetprop(args: &[&str]) -> Result<()> {
    let command = crate::plat::resetprop::find_resetprop_command()?;
    let mut process = Command::new(&command.program);
    if let Some(prepend) = &command.prepend_arg {
        process.arg(prepend);
    }
    let status = process
        .args(args)
        .status()
        .context("failed to execute resetprop")?;
    if status.success() {
        Ok(())
    } else {
        bail!("resetprop exited with status {status}")
    }
}

/// Apply the selected switches immediately. The same values are replayed by
/// `template/service.sh` during every boot, matching specter's behavior.
pub fn apply(settings: Settings) -> Result<()> {
    persist(settings)?;
    if !settings.enabled {
        return Ok(());
    }

    if settings.dev_options {
        run_settings(&["put", "global", "development_settings_enabled", "0"])?;
        run_resetprop(&["-n", "persist.sys.development_settings_enabled", "0"])?;
        run_resetprop(&["-n", "ro.debuggable", "0"])?;
        run_resetprop(&["-n", "ro.force.debuggable", "0"])?;
    }

    if settings.usb_debug {
        run_settings(&["put", "global", "adb_enabled", "0"])?;
        run_resetprop(&["-n", "ro.adb.secure", "1"])?;
        run_resetprop(&["-n", "persist.sys.usb.config", "mtp"])?;
        run_resetprop(&["-n", "sys.usb.config", "mtp"])?;
        run_resetprop(&["-n", "service.adb.root", "0"])?;
        run_resetprop(&["-n", "init.svc.adbd", "stopped"])?;
        run_resetprop(&["-n", "init.svc_debug_pid.adbd", ""])?;
    }

    if settings.oem_unlock {
        run_resetprop(&["-n", "sys.oem_unlock_allowed", "0"])?;
        run_resetprop(&["-n", "ro.oem_unlock_supported", "0"])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Settings;

    #[test]
    fn parses_strict_boolean_tokens() {
        let values = ["1", "0", "1", "0"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        assert_eq!(
            Settings::from_tokens(&values).unwrap(),
            Settings {
                enabled: true,
                dev_options: false,
                usb_debug: true,
                oem_unlock: false,
            }
        );
    }

    #[test]
    fn rejects_unknown_tokens_or_arity() {
        let invalid = ["yes", "0", "0", "0"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        assert!(Settings::from_tokens(&invalid).is_err());
        assert!(Settings::from_tokens(&invalid[..3]).is_err());
    }
}
