//! Public configuration adapter. Providers remain external executables; this
//! updater does not depend on a particular secret manager or boot format.
use crate::cancellation::ManagedCommand;
use serde::Deserialize;
use std::{collections::BTreeMap, fs, process::Command};
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    host: String,
    target: String,
    public_key: String,
    backend: String,
    arguments: Vec<String>,
    session_environment: String,
    session_command: Vec<String>,
    authentication_command: Vec<String>,
    ssh_arguments: Vec<String>,
    copy_ssh_arguments: Vec<String>,
    reboot: bool,
}
fn checked(command: &mut Command) -> Result<(), String> {
    if command.managed_status().map_err(|e| e.to_string())?.success() { Ok(()) }
    else { Err("configured update failed".into()) }
}
fn substitute(value: &str, replacements: &BTreeMap<&str, String>) -> String {
    replacements.iter().fold(value.to_owned(), |v, (key, replacement)| v.replace(key, replacement))
}
fn expanded(values: &[String], replacements: &BTreeMap<&str, String>) -> Vec<String> {
    values.iter().map(|v| substitute(v, replacements)).collect()
}
// Nix parses NIX_SSHOPTS as shell words, but never executes this string.
fn quote(value: &str) -> String { format!("'{}'", value.replace('\'', "'\\''")) }
struct PublicKey(std::path::PathBuf);
impl Drop for PublicKey { fn drop(&mut self) { let _ = fs::remove_file(&self.0); if let Some(parent) = self.0.parent() { let _ = fs::remove_dir(parent); } } }
pub fn deploy(args: &[String]) -> Result<(), String> {
    let mut values = BTreeMap::new();
    let mut no_reboot = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" => { println!("configured-deploy --installable FLAKE#CONFIG --plan FILE [--target-host update@HOST] [--ssh-port PORT] [--known-hosts FILE] [--no-reboot]"); return Ok(()); }
            "--no-reboot" => no_reboot = true,
            "--installable" | "--plan" | "--nix" | "--target-host" | "--ssh-port" | "--known-hosts" => { values.insert(arg.as_str(), iter.next().ok_or("missing configured update option value")?.clone()); }
            _ => return Err(format!("unknown configured update option {arg}")),
        }
    }
    let get = |key: &str| values.get(key).map(String::as_str).ok_or_else(|| format!("missing {key}"));
    let installable = get("--installable")?;
    let nix = values.get("--nix").map(String::as_str).unwrap_or("nix");
    let result = Command::new(nix).args(["eval", "--impure", "--json", &format!("{installable}.config"), "--apply", &format!("c: (import {}) c", get("--plan")?)]).managed_output().map_err(|e| e.to_string())?;
    if !result.status.success() {
        use std::io::Write;
        let _ = std::io::stderr().write_all(&result.stderr);
        return Err("reading update configuration failed".into());
    }
    let plan: Plan = serde_json::from_slice(&result.stdout).map_err(|e| e.to_string())?;
    if !matches!(plan.backend.as_str(), "deploy" | "deploy-generation") { return Err("unsupported update backend".into()); }
    if plan.session_environment.is_empty() { return Err("missing provider session environment".into()); }
    let target = values.get("--target-host").unwrap_or(&plan.target);
    if !target.starts_with("update@") || target.chars().any(char::is_whitespace) || target.matches('@').count() != 1 { return Err("configured updates require the restricted update account".into()); }
    let (user, host) = target.split_once('@').ok_or("invalid update target")?;
    if host.is_empty() || host.starts_with('-') { return Err("invalid update target".into()); }
    let target = format!("{user}@{}", host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host));
    if plan.public_key.lines().count() != 1 || !(plan.public_key.starts_with("ssh-") || plan.public_key.starts_with("ecdsa-")) { return Err("invalid configured update public key".into()); }
    let known_hosts = values.get("--known-hosts").map(|path| {
        let path = fs::canonicalize(path).map_err(|e| format!("cannot read verified known-hosts file: {e}"))?;
        if !path.is_file() { return Err("known-hosts must be a regular file".to_owned()); }
        Ok(path)
    }).transpose()?;
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut replacements = BTreeMap::from([("{installable}", installable.to_owned()), ("{host}", plan.host.clone()), ("{target}", target.clone())]);
    if !plan.session_command.is_empty() && std::env::var_os(&plan.session_environment).is_none() {
        let session = expanded(&plan.session_command, &replacements);
        let (command, arguments) = session.split_first().ok_or("missing provider session command")?;
        return checked(Command::new(command).args(arguments).arg(&executable).arg("configured-deploy").args(args));
    }
    // Only a public SSH key is materialized, in a visible checkout directory.
    // Private signing material remains in the configured streaming provider.
    let root = std::env::current_dir().map_err(|e| e.to_string())?.join("system-update-public-keys");
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let path = root.join(format!("{}.pub", std::process::id()));
    let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&path).map_err(|e| e.to_string())?;
    let key = PublicKey(path);
    use std::io::Write;
    file.write_all(format!("{}\n", plan.public_key).as_bytes()).map_err(|e| e.to_string())?;
    replacements.insert("{publicKey}", key.0.to_string_lossy().into_owned());
    let auth = expanded(&plan.authentication_command, &replacements);
    let (command, arguments) = auth.split_first().ok_or("missing update authentication command")?;
    let mut ssh_arguments = expanded(&plan.ssh_arguments, &replacements);
    let mut copy_arguments = expanded(&plan.copy_ssh_arguments, &replacements);
    if let Some(path) = known_hosts {
        let option = format!("UserKnownHostsFile={}", path.display());
        ssh_arguments.extend(["-o".into(), option.clone()]);
        copy_arguments.extend(["-o".into(), option]);
    }
    if let Some(port) = values.get("--ssh-port") {
        if port.parse::<u16>().ok().filter(|p| *p != 0).is_none() { return Err("invalid SSH port".into()); }
        ssh_arguments.extend(["-p".into(), port.clone()]);
        copy_arguments.extend(["-p".into(), port.clone()]);
    }
    let mut child = Command::new(command);
    child.args(arguments).arg(&executable).arg(&plan.backend).args(expanded(&plan.arguments, &replacements));
    for argument in ssh_arguments { child.arg("--ssh-arg").arg(argument); }
    if plan.reboot && !no_reboot { child.arg("--reboot"); }
    child.env("NIX_SSHOPTS", copy_arguments.iter().map(|v| quote(v)).collect::<Vec<_>>().join(" "));
    checked(&mut child)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn substitutions_preserve_argument_boundaries() {
        let map = BTreeMap::from([("{target}", "update@::1".to_owned())]);
        assert_eq!(expanded(&["--destination".into(), "{target}".into()], &map), ["--destination", "update@::1"]);
        assert_eq!(quote("a'b"), "'a'\\''b'");
    }
}
