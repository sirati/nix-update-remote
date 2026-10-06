use crate::{closure_signing, protocol};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub fn system(requested: &Path) -> Result<PathBuf, String> {
    let resolved = fs::canonicalize(requested).map_err(|error| error.to_string())?;
    if resolved != requested || !resolved.starts_with("/nix/store/") {
        return Err("system path is not canonical in the Nix store".into());
    }
    if !resolved.join("nixos-version").is_file() {
        return Err("system path is not a NixOS toplevel".into());
    }
    let switch = resolved.join("bin/switch-to-configuration");
    let metadata = fs::metadata(&switch).map_err(|_| "system activation program is missing")?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err("system activation program is not executable".into());
    }
    Ok(resolved)
}

pub fn closure(
    nix: &Path,
    system: &Path,
    static_keys: &[String],
    key_file: Option<&Path>,
) -> Result<(), String> {
    let mut keys = static_keys.to_vec();
    if let Some(path) = key_file {
        keys.extend(
            protocol::read_runtime_trusted_keys(path)?
                .lines()
                .map(str::to_owned),
        );
    }
    if keys.is_empty() {
        return Err("no trusted signing keys are configured".into());
    }
    // `nix store verify` counts content-addressed paths as signed, so it only
    // checks contents here; the update key signature is checked separately.
    checked(
        Command::new(nix)
            .args([
                "--extra-experimental-features",
                "nix-command",
                "store",
                "verify",
                "--recursive",
                "--no-trust",
            ])
            .arg(system),
        "verifying closure contents",
    )?;
    closure_signing::require_signed(nix, system, &keys)
}

pub fn checked(command: &mut Command, action: &str) -> Result<(), String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    command
        .status()
        .map_err(|error| error.to_string())?
        .success()
        .then_some(())
        .ok_or_else(|| format!("{action} failed"))
}
