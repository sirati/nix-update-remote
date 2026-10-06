//! Build, retain, sign and upload a generation in one operator transaction.
use crate::cancellation::ManagedCommand;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
struct Roots(PathBuf);
impl Drop for Roots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn build(
    nix: &Path,
    installable: &str,
    attribute: &str,
    root: &Path,
    impure: bool,
) -> Result<PathBuf, String> {
    eprintln!("Building {attribute}; retaining root {}", root.display());
    let mut command = Command::new(nix);
    command
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "build",
            "--out-link",
        ])
        .arg(root)
        .arg("--print-out-paths");
    if impure {
        command.arg("--impure");
    }
    let output = command
        .arg(format!("{installable}.config.{attribute}"))
        .managed_output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        return Err(format!("building {attribute} failed"));
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|e| e.to_string())?;
    let mut paths = text.lines();
    let path = paths.next().ok_or("build returned no artifact")?;
    if paths.next().is_some() || !path.starts_with("/nix/store/") {
        return Err("build returned invalid artifact paths".into());
    }
    Ok(path.into())
}
fn eval_bool(
    nix: &Path,
    expression: &str,
    apply: Option<&str>,
    impure: bool,
) -> Result<bool, String> {
    let mut command = Command::new(nix);
    command.args([
        "--extra-experimental-features",
        "nix-command flakes",
        "eval",
        "--json",
    ]);
    if impure {
        command.arg("--impure");
    }
    command.arg(expression);
    if let Some(apply) = apply {
        command.args(["--apply", apply]);
    }
    let output = command.managed_output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        return Err("evaluating optional artifact failed".into());
    }
    match std::str::from_utf8(&output.stdout)
        .map_err(|e| e.to_string())?
        .trim()
    {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err("optional artifact predicate must be boolean".into()),
    }
}
/// Splits `a.b.leaf` into the parent path and a leaf name that is safe to
/// quote into a Nix `?` test.
fn presence_probe(attribute: &str) -> Result<(String, String), String> {
    let (parent, leaf) = match attribute.rsplit_once('.') {
        Some((parent, leaf)) => (format!(".{parent}"), leaf),
        None => (String::new(), attribute),
    };
    if leaf.is_empty()
        || parent == "."
        || !leaf
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-'".contains(&b))
    {
        return Err("invalid optional artifact attribute".into());
    }
    Ok((parent, format!("v: v ? \"{leaf}\"")))
}
/// An optional artifact is built when its predicate holds, or, without a
/// predicate, when the configuration defines the attribute at all.
fn optional_enabled(
    nix: &Path,
    installable: &str,
    attribute: &str,
    enabled_attribute: Option<&str>,
    impure: bool,
) -> Result<bool, String> {
    if let Some(enabled) = enabled_attribute {
        return eval_bool(nix, &format!("{installable}.config.{enabled}"), None, impure);
    }
    let (parent, apply) = presence_probe(attribute)?;
    eval_bool(
        nix,
        &format!("{installable}.config{parent}"),
        Some(&apply),
        impure,
    )
}
pub fn deploy(args: &[String]) -> Result<(), String> {
    let mut installable = None;
    let mut nix = PathBuf::from("nix");
    let mut pass = Vec::new();
    let mut impure = false;
    let mut attributes = std::collections::BTreeMap::from([
        (
            "--image-attribute",
            "system.build.updateArtifacts.image".to_owned(),
        ),
        (
            "--config-attribute",
            "system.build.updateArtifacts.config".to_owned(),
        ),
        (
            "--rescue-attribute",
            "system.build.updateArtifacts.rescue".to_owned(),
        ),
        (
            "--signer-attribute",
            "system.build.updateArtifacts.signer".to_owned(),
        ),
        ("--system-attribute", "system.build.toplevel".to_owned()),
    ]);
    let mut signer_relative = "bin/update-artifact-sign".to_owned();
    let mut network_attribute = None;
    let mut network_enabled_attribute = None;
    let mut tools_attribute = None;
    let mut tools_enabled_attribute = None;
    let mut reboot = false;
    let mut external_signing = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--image-attribute" | "--config-attribute" | "--rescue-attribute"
            | "--signer-attribute" | "--system-attribute" => {
                attributes.insert(
                    arg.as_str(),
                    iter.next().ok_or("missing artifact attribute")?.clone(),
                );
            }
            "--signer-relative-path" => {
                signer_relative = iter.next().ok_or("missing signer relative path")?.clone()
            }
            "--network-attribute" => network_attribute = iter.next().cloned(),
            "--network-enabled-attribute" => network_enabled_attribute = iter.next().cloned(),
            "--tools-attribute" => tools_attribute = iter.next().cloned(),
            "--tools-enabled-attribute" => tools_enabled_attribute = iter.next().cloned(),
            "--installable" => installable = iter.next().cloned(),
            "--nix" => {
                nix = iter
                    .next()
                    .map(PathBuf::from)
                    .ok_or("missing nix executable")?
            }
            "--impure" => impure = true,
            "--reboot" => {
                reboot = true;
                pass.push(arg.clone());
            }
            "--sign-command" => {
                external_signing = true;
                pass.push(arg.clone());
                pass.push(iter.next().ok_or("missing signing command")?.clone());
            }
            "--sign-arg" | "--target" | "--signing-key" | "--key-command" | "--key-arg" | "--ssh-command"
            | "--ssh-arg" | "--sha512sum" | "--post-command" | "--post-arg"
            | "--remote-command" | "--remote-arg" => {
                pass.push(arg.clone());
                pass.push(
                    iter.next()
                        .ok_or("missing generation option value")?
                        .clone(),
                );
            }
            _ => return Err(format!("unknown generation option: {arg}")),
        }
    }
    let installable = installable.ok_or("missing installable")?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let roots = Roots(
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(format!(
                "system-update-roots-{}-{stamp}",
                std::process::id()
            )),
    );
    fs::create_dir(&roots.0).map_err(|e| e.to_string())?;
    fs::set_permissions(&roots.0, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    eprintln!(
        "Retaining registered GC roots in {} until update completion",
        roots.0.display()
    );
    for (option, attribute, name) in [
        ("--image", "--image-attribute", "image"),
        ("--config", "--config-attribute", "config"),
        ("--rescue", "--rescue-attribute", "rescue"),
        ("--signer", "--signer-attribute", "signer"),
    ] {
        if option == "--signer" && external_signing { continue; }
        let path = build(
            &nix,
            &installable,
            &attributes[attribute],
            &roots.0.join(name),
            impure,
        )?;
        pass.push(option.into());
        pass.push(
            if option == "--signer" {
                path.join(&signer_relative)
            } else {
                path
            }
            .to_string_lossy()
            .into_owned(),
        );
    }
    let toplevel = build(
        &nix,
        &installable,
        &attributes["--system-attribute"],
        &roots.0.join("system"),
        impure,
    )?;
    for (option, name) in [("--kernel", "kernel"), ("--initrd", "initrd")] {
        pass.push(option.into());
        pass.push(toplevel.join(name).to_string_lossy().into_owned());
    }
    if reboot {
        pass.push("--wait-system".into());
        pass.push(toplevel.to_string_lossy().into_owned());
    }
    for (option, name, attribute, enabled_attribute) in [
        ("--network", "network", network_attribute, network_enabled_attribute),
        ("--tools", "tools", tools_attribute, tools_enabled_attribute),
    ] {
        let Some(attribute) = attribute else { continue };
        if optional_enabled(
            &nix,
            &installable,
            &attribute,
            enabled_attribute.as_deref(),
            impure,
        )? {
            let path = build(&nix, &installable, &attribute, &roots.0.join(name), impure)?;
            pass.push(option.into());
            pass.push(path.to_string_lossy().into_owned());
        }
    }
    crate::artifact_client::deploy(&pass)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presence_probe_quotes_only_plain_leaf_names() {
        assert_eq!(
            presence_probe("system.build.nmblRescueTools").unwrap(),
            (".system.build".into(), "v: v ? \"nmblRescueTools\"".into())
        );
        assert_eq!(
            presence_probe("toplevel").unwrap(),
            (String::new(), "v: v ? \"toplevel\"".into())
        );
        for bad in ["", "system.build.", ".x", "a.b\"c", "a.${x}", "a.b c"] {
            assert!(presence_probe(bad).is_err(), "{bad}");
        }
    }
}
