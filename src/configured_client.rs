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
    /// Obtains the operator's approval of the logins before each connection;
    /// see `--login-approval-command`. Empty: none.
    #[serde(default)]
    login_approval_command: Vec<String>,
    /// Reports a failed update to the operator as soon as it is known; the
    /// reason is appended as the last argument. Empty: none.
    #[serde(default)]
    failure_command: Vec<String>,
    /// Reports what an update that succeeded left broken; the text is
    /// appended as the last argument. Empty: none.
    #[serde(default)]
    warning_command: Vec<String>,
    /// Reports each stage of the update as it starts, and the upload's
    /// percentage; `--text TEXT` and `--percent N` are appended. Empty: none.
    #[serde(default)]
    progress_command: Vec<String>,
    /// Asks the operator to confirm a deployment from a working tree with
    /// uncommitted changes; `--reason TEXT` and one `--item FILE` per dirty
    /// file are appended, and only exit status 0 confirms. Empty: ask on
    /// the terminal.
    #[serde(default)]
    confirm_command: Vec<String>,
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
/// The backend options that report a failed update through the plan's reporter.
fn reporter_arguments(kind: &str, command: &[String], replacements: &BTreeMap<&str, String>) -> Vec<String> {
    let command = expanded(command, replacements);
    let Some((program, arguments)) = command.split_first() else { return Vec::new() };
    let mut options = vec![format!("--{kind}-command"), program.clone()];
    for argument in arguments { options.extend([format!("--{kind}-arg"), argument.clone()]); }
    options
}
struct PublicKey(std::path::PathBuf);
impl Drop for PublicKey { fn drop(&mut self) { let _ = fs::remove_file(&self.0); if let Some(parent) = self.0.parent() { let _ = fs::remove_dir(parent); } } }
/// The operator's options, or `None` for `--help`. A wrapper fixes some of
/// them and appends the operator's own; a second copy of any is refused, so
/// none replaces the wrapper's.
fn parse(args: &[String]) -> Result<Option<(BTreeMap<&str, String>, bool)>, String> {
    let mut values = BTreeMap::new();
    let mut no_reboot = false;
    let mut once = crate::options::Once::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        once.take(arg, &[])?;
        match arg.as_str() {
            "--help" => { println!("configured-deploy --installable FLAKE#CONFIG --plan FILE [--target-host update@HOST] [--ssh-port PORT] [--known-hosts FILE] [--git GIT] [--no-reboot]"); return Ok(None); }
            "--no-reboot" => no_reboot = true,
            "--installable" | "--plan" | "--nix" | "--git" | "--target-host" | "--ssh-port" | "--known-hosts" => { values.insert(arg.as_str(), iter.next().ok_or("missing configured update option value")?.clone()); }
            _ => return Err(format!("unknown configured update option {arg}")),
        }
    }
    Ok(Some((values, no_reboot)))
}
pub fn deploy(args: &[String]) -> Result<(), String> {
    let Some((values, no_reboot)) = parse(args)? else { return Ok(()) };
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
    // Before anything is signed: a deployment from uncommitted changes is
    // allowed, but only with the operator's explicit confirmation.
    if let Some(source) = local_flake_dir(installable) {
        let git = values.get("--git").map(String::as_str).unwrap_or("git");
        confirm_dirty_tree(&plan.host, &dirtiness(git, &source), &expanded(&plan.confirm_command, &replacements))?;
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
    let approval = expanded(&plan.login_approval_command, &replacements);
    if let Some((program, arguments)) = approval.split_first() {
        child.arg("--login-approval-command").arg(program);
        for argument in arguments { child.arg("--login-approval-arg").arg(argument); }
    }
    child.args(reporter_arguments("failure", &plan.failure_command, &replacements));
    // Only closure switches commit with warnings.
    if plan.backend == "deploy" {
        child.args(reporter_arguments("warning", &plan.warning_command, &replacements));
        child.args(reporter_arguments("progress", &plan.progress_command, &replacements));
    }
    for argument in ssh_arguments { child.arg("--ssh-arg").arg(argument); }
    if plan.reboot && !no_reboot { child.arg("--reboot"); }
    child.env("NIX_SSHOPTS", copy_arguments.iter().map(|v| quote(v)).collect::<Vec<_>>().join(" "));
    checked(&mut child)
}
/// How a local flake's source is taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fetch {
    /// `path:`: the whole directory, untracked and ignored files included.
    Path,
    /// `git+file:`, or a plain path in a git tree: the tracked files only.
    Git,
}

/// The local directory a flake installable builds from, if it names one,
/// and how its source is taken.
fn local_flake_dir(installable: &str) -> Option<(std::path::PathBuf, Fetch)> {
    let reference = installable.split_once('#').map_or(installable, |(reference, _)| reference);
    let reference = reference.split_once('?').map_or(reference, |(reference, _)| reference);
    let (path, fetch) = [("path:", Fetch::Path), ("git+file://", Fetch::Git), ("git+file:", Fetch::Git)]
        .iter()
        .find_map(|(scheme, fetch)| reference.strip_prefix(scheme).map(|path| (path, *fetch)))
        .unwrap_or((reference, Fetch::Git));
    let local = path.is_empty() || path == "." || path == ".." || path.starts_with("./")
        || path.starts_with("../") || path.starts_with('/');
    local.then(|| (std::path::PathBuf::from(if path.is_empty() { "." } else { path }), fetch))
}

/// Whether the build takes anything no commit holds.
#[derive(Debug, PartialEq, Eq)]
enum Dirtiness {
    Clean,
    Dirty(Vec<String>),
    /// It cannot be told: the deployment needs the same confirmation.
    Unknown(String),
}

/// What a build from `source` takes that no commit holds: tracked files with
/// uncommitted changes, staged or not, and for a `path:` flake also every
/// untracked and ignored file, since it copies the whole directory. A tree
/// git cannot read, such as a `path:` flake outside any repository, is
/// unknown, never clean.
fn dirtiness(git: &str, (directory, fetch): &(std::path::PathBuf, Fetch)) -> Dirtiness {
    let untracked: &[&str] = match fetch {
        Fetch::Git => &["--untracked-files=no"],
        Fetch::Path => &["--untracked-files=all", "--ignored=matching"],
    };
    let output = match Command::new(git)
        .arg("-C").arg(directory)
        .args(["status", "--porcelain=v1", "-z"])
        .args(untracked)
        .stdin(std::process::Stdio::null())
        .managed_output()
    {
        Ok(output) => output,
        Err(error) => return Dirtiness::Unknown(format!("running {git}: {error}")),
    };
    if !output.status.success() {
        return Dirtiness::Unknown(format!(
            "{git} status failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    match parse_porcelain(&output.stdout) {
        Ok(files) if files.is_empty() => Dirtiness::Clean,
        Ok(files) => Dirtiness::Dirty(files),
        Err(error) => Dirtiness::Unknown(error),
    }
}

/// File names of `git status --porcelain=v1 -z` entries. A rename or copy
/// is followed by its source, which is not listed again. An entry of
/// another shape is an error, never skipped.
fn parse_porcelain(output: &[u8]) -> Result<Vec<String>, String> {
    const STATUS: &[u8] = b" MTADRCU?!";
    let mut files = Vec::new();
    if output.is_empty() {
        return Ok(files);
    }
    let body = output.strip_suffix(b"\0").ok_or("git status output is not NUL-terminated")?;
    let mut entries = body.split(|byte| *byte == 0);
    while let Some(entry) = entries.next() {
        if entry.len() < 4 || entry[2] != b' ' || !STATUS.contains(&entry[0]) || !STATUS.contains(&entry[1]) {
            return Err(format!("unexpected git status entry {:?}", String::from_utf8_lossy(entry)));
        }
        files.push(String::from_utf8_lossy(&entry[3..]).into_owned());
        if matches!(entry[0], b'R' | b'C') || matches!(entry[1], b'R' | b'C') {
            entries.next().filter(|source| !source.is_empty()).ok_or("git status names a rename without its source")?;
        }
    }
    Ok(files)
}

const RED: &str = "\x1b[1;31m";
const RESET: &str = "\x1b[0m";

/// Lets a deployment from a dirty tree, or one whose tree cannot be
/// checked, go ahead only when the operator confirms it, naming every dirty
/// file.
fn confirm_dirty_tree(host: &str, dirtiness: &Dirtiness, command: &[String]) -> Result<(), String> {
    let (reason, files) = match dirtiness {
        Dirtiness::Clean => return Ok(()),
        Dirtiness::Dirty(files) => (
            format!(
                "{host} is about to be deployed from a working tree with {} uncommitted change{}. \
                 The build includes them, and no commit records them.",
                files.len(),
                if files.len() == 1 { "" } else { "s" }
            ),
            files.as_slice(),
        ),
        Dirtiness::Unknown(error) => (
            format!(
                "{host} is about to be deployed from a working tree that cannot be checked for \
                 uncommitted changes ({error}). The build may include changes no commit records."
            ),
            &[][..],
        ),
    };
    eprintln!("{RED}WARNING: {reason}{RESET}");
    for file in files {
        eprintln!("{RED}  {file}{RESET}");
    }
    let confirmed = match command.split_first() {
        Some((program, arguments)) => Command::new(program)
            .args(arguments)
            .arg("--reason")
            .arg(&reason)
            .args(files.iter().flat_map(|file| ["--item", file.as_str()]))
            .stdin(std::process::Stdio::null())
            .managed_status()
            .is_ok_and(|status| status.success()),
        None => confirm_on_terminal(),
    };
    if confirmed { Ok(()) } else { Err("the deployment from a dirty or unchecked tree was not confirmed".into()) }
}

/// Asks on the controlling terminal; without one nothing is confirmed.
fn confirm_on_terminal() -> bool {
    use std::io::{BufRead, Write};
    let Ok(terminal) = fs::OpenOptions::new().read(true).write(true).open("/dev/tty") else {
        eprintln!("nix-update-remote: no terminal to confirm the deployment from a dirty tree");
        return false;
    };
    let mut writer = &terminal;
    let _ = write!(writer, "{RED}Deploy these uncommitted changes? Type yes to confirm: {RESET}");
    let _ = writer.flush();
    let mut answer = String::new();
    std::io::BufReader::new(&terminal).read_line(&mut answer).is_ok() && answer.trim() == "yes"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_local_flakes_have_a_tree_to_check() {
        for (installable, expected) in [
            (".#nixosConfigurations.ns1", Some((".", Fetch::Git))),
            ("#ns1", Some((".", Fetch::Git))),
            ("./sub#a", Some(("./sub", Fetch::Git))),
            ("/home/op/flake#a", Some(("/home/op/flake", Fetch::Git))),
            ("path:/home/op/flake?dir=x#a", Some(("/home/op/flake", Fetch::Path))),
            ("path:.#a", Some((".", Fetch::Path))),
            ("git+file:///home/op/flake#a", Some(("/home/op/flake", Fetch::Git))),
            ("github:sirati/x#a", None),
            ("nixpkgs#hello", None),
        ] {
            assert_eq!(
                local_flake_dir(installable),
                expected.map(|(directory, fetch)| (std::path::PathBuf::from(directory), fetch)),
                "{installable}"
            );
        }
    }

    #[test]
    fn porcelain_lists_each_dirty_file_once() {
        let output = b" M nix-secrets.toml\0M  server/a.nix\0R  new.nix\0old.nix\0A  added file.nix\0?? new.nix\0!! result\0";
        assert_eq!(
            parse_porcelain(output).unwrap(),
            ["nix-secrets.toml", "server/a.nix", "new.nix", "added file.nix", "new.nix", "result"]
        );
        assert!(parse_porcelain(b"").unwrap().is_empty());
    }

    #[test]
    fn unparsable_porcelain_is_an_error_not_a_clean_tree() {
        for output in [
            &b"M\0"[..],
            b" M a.nix",
            b"XY a.nix\0",
            b" Ma.nix\0",
            b"R  new.nix\0",
            b"garbage that is no status\0",
        ] {
            assert!(parse_porcelain(output).is_err(), "{:?}", String::from_utf8_lossy(output));
        }
    }

    #[test]
    fn a_tree_that_cannot_be_checked_needs_the_same_confirmation() {
        let source = (std::env::temp_dir(), Fetch::Git);
        assert!(matches!(dirtiness("/nonexistent/git", &source), Dirtiness::Unknown(_)), "git missing");
        // A git that fails, and one whose output cannot be parsed.
        let unknown = Dirtiness::Unknown("git status failed".into());
        assert!(confirm_dirty_tree("ns1", &unknown, &["/nonexistent/confirmer".into()]).is_err());
        let directory = std::env::temp_dir().join(format!("nur-unknown-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let fake = |name: &str, body: &str| {
            let script = directory.join(name);
            fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
            script.to_string_lossy().into_owned()
        };
        let failing = fake("failing-git", "echo 'fatal: not a git repository' >&2; exit 128");
        assert!(matches!(dirtiness(&failing, &source), Dirtiness::Unknown(e) if e.contains("not a git repository")));
        let garbled = fake("garbled-git", "printf 'what is this'");
        assert!(matches!(dirtiness(&garbled, &source), Dirtiness::Unknown(_)));
        let record = directory.join("arguments");
        let confirmer = fake("confirm", &format!("printf '%s\\n' \"$@\" > {}; exit 0", record.display()));
        assert_eq!(confirm_dirty_tree("ns1", &dirtiness(&failing, &source), &[confirmer]), Ok(()));
        let arguments = fs::read_to_string(&record).unwrap();
        assert!(arguments.contains("cannot be checked") && arguments.contains("not a git repository"), "{arguments}");
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn a_dirty_tree_deploys_only_after_confirmation() {
        let files = Dirtiness::Dirty(vec!["nix-secrets.toml".to_owned(), "server/a.nix".to_owned()]);
        assert_eq!(confirm_dirty_tree("ns1", &Dirtiness::Clean, &["/nonexistent".into()]), Ok(()), "a clean tree asks nothing");
        let directory = std::env::temp_dir().join(format!("nur-confirm-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let record = directory.join("arguments");
        // A confirmer that records its arguments and answers with its exit status.
        let confirmer = |code: i32| {
            let script = directory.join(format!("confirm-{code}"));
            fs::write(&script, format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nexit {code}\n", record.display())).unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
            vec![script.to_string_lossy().into_owned(), "procedure-confirm".into()]
        };
        assert_eq!(confirm_dirty_tree("ns1", &files, &confirmer(0)), Ok(()));
        let arguments = fs::read_to_string(&record).unwrap();
        let lines: Vec<_> = arguments.lines().collect();
        assert_eq!(lines[0], "procedure-confirm");
        assert_eq!(lines[1], "--reason");
        assert!(lines[2].starts_with("ns1 is about to be deployed") && lines[2].contains("2 uncommitted changes"), "{arguments}");
        assert_eq!(&lines[3..], ["--item", "nix-secrets.toml", "--item", "server/a.nix"]);
        assert!(confirm_dirty_tree("ns1", &files, &confirmer(1)).is_err(), "a refusal stops the update");
        assert!(confirm_dirty_tree("ns1", &files, &["/nonexistent/confirmer".into()]).is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn a_real_git_tree_reports_what_its_flake_kind_deploys() {
        let git = std::env::var("NIX_UPDATE_TEST_GIT").unwrap_or_else(|_| "git".into());
        let directory = std::env::temp_dir().join(format!("nur-dirty-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let run = |args: &[&str]| {
            assert!(Command::new(&git).arg("-C").arg(&directory)
                .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"])
                .args(args).status().unwrap().success(), "{args:?}");
        };
        let git_flake = (directory.clone(), Fetch::Git);
        let path_flake = (directory.clone(), Fetch::Path);
        // Not a repository: nothing tells what the build takes.
        assert!(matches!(dirtiness(&git, &path_flake), Dirtiness::Unknown(_)));
        run(&["init", "-q"]);
        fs::write(directory.join("flake.nix"), "{}\n").unwrap();
        fs::write(directory.join(".gitignore"), "secret.key\n").unwrap();
        run(&["add", "flake.nix", ".gitignore"]);
        run(&["commit", "-q", "-m", "init"]);
        assert_eq!(dirtiness(&git, &git_flake), Dirtiness::Clean);
        assert_eq!(dirtiness(&git, &path_flake), Dirtiness::Clean);
        fs::write(directory.join("untracked.nix"), "{}\n").unwrap();
        fs::write(directory.join("secret.key"), "x\n").unwrap();
        assert_eq!(dirtiness(&git, &git_flake), Dirtiness::Clean, "a git flake builds no untracked file");
        assert_eq!(
            dirtiness(&git, &path_flake),
            Dirtiness::Dirty(vec!["untracked.nix".into(), "secret.key".into()]),
            "a path: flake copies untracked and ignored files"
        );
        fs::write(directory.join("flake.nix"), "{ }\n").unwrap();
        assert_eq!(dirtiness(&git, &git_flake), Dirtiness::Dirty(vec!["flake.nix".into()]));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn no_option_is_taken_twice() {
        let args = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let fixed = ["--installable", ".#nixosConfigurations.ns1", "--nix", "/nix/store/n/bin/nix", "--plan", "/nix/store/p"];
        let given = args(&[&fixed[..], &["--target-host", "update@ns1", "--no-reboot"]].concat());
        let (values, no_reboot) = parse(&given).unwrap().unwrap();
        assert_eq!(values["--installable"], ".#nixosConfigurations.ns1");
        assert!(no_reboot);
        for extra in [
            &["--installable", "path:/tmp/evil#ns1"][..],
            &["--nix", "/tmp/nix"],
            &["--plan", "/tmp/plan.nix"],
            &["--git", "/a", "--git", "/b"],
            &["--target-host", "update@a", "--target-host", "update@b"],
            &["--no-reboot", "--no-reboot"],
            &["--installable=path:/tmp/evil#ns1"],
            &["--git=/bin/true"],
        ] {
            assert!(parse(&args(&[&fixed[..], extra].concat())).is_err(), "{extra:?}");
        }
    }

    #[test]
    fn substitutions_preserve_argument_boundaries() {
        let map = BTreeMap::from([("{target}", "update@::1".to_owned())]);
        assert_eq!(expanded(&["--destination".into(), "{target}".into()], &map), ["--destination", "update@::1"]);
        assert_eq!(quote("a'b"), "'a'\\''b'");
    }
    #[test]
    fn the_failure_reporter_reaches_the_backend_with_the_host_substituted() {
        let map = BTreeMap::from([("{host}", "ns1".to_owned())]);
        let plan = ["/nix-secrets".to_owned(), "procedure-step-failed".into(), "--label".into(), "update {host}".into(), "--reason".into()];
        assert_eq!(
            reporter_arguments("failure", &plan, &map),
            ["--failure-command", "/nix-secrets", "--failure-arg", "procedure-step-failed", "--failure-arg", "--label", "--failure-arg", "update ns1", "--failure-arg", "--reason"]
        );
        assert!(reporter_arguments("failure", &[], &map).is_empty());
        assert_eq!(reporter_arguments("warning", &["/w".to_owned(), "{host}".into()], &map), ["--warning-command", "/w", "--warning-arg", "ns1"]);
        assert_eq!(reporter_arguments("progress", &["/p".to_owned(), "{host}".into()], &map), ["--progress-command", "/p", "--progress-arg", "ns1"]);
    }
}
