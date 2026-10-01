use rustix::process::{Pid, Signal, kill_process};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

// An assertion failure must not leave the operator process behind.
struct TestProcess(Child);
impl std::ops::Deref for TestProcess {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}
impl std::ops::DerefMut for TestProcess {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}
impl Drop for TestProcess {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_some() {
            return;
        }
        if let Some(pid) = Pid::from_raw(self.0.id() as i32) {
            let _ = kill_process(pid, Signal::TERM);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.0.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Fixture {
    root: PathBuf,
    helper: PathBuf,
    cleanup_root: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.cleanup_root);
    }
}
impl Fixture {
    fn new(label: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("updater-cancel-{label}-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let source = root.join("helper.rs");
        let helper = root.join("helper");
        fs::write(&source,r#"
use std::{fs,env,process::Command,thread,time::Duration,io::Read};
fn main(){
 let a:Vec<String>=env::args().collect();
 if a.get(1).is_some_and(|x|x=="auth") {let s=Command::new(&a[2]).args(&a[3..]).status().unwrap();std::process::exit(s.code().unwrap_or(1));}
 if a.get(1).is_some_and(|x|x=="sign") {
  let mut input=String::new();std::io::stdin().read_to_string(&mut input).unwrap();
  let input:serde_json::Value=serde_json::from_str(&input).unwrap();
  let signatures:Vec<_>=input["artifacts"].as_array().unwrap().iter().map(|a|serde_json::json!({"role":a["role"],"sha512":a["sha512"],"size":a["size"],"signature_base64":"YQ=="})).collect();
  println!("{}",serde_json::json!({"signatures":signatures}));return;
 }
 if a.get(1).is_some_and(|x|x=="block") {
  let child=Command::new(&a[0]).arg("linger").spawn().unwrap();
  while !std::path::Path::new("linger-ready").exists(){thread::sleep(Duration::from_millis(1));}
  fs::write("children",format!("{} {}",std::process::id(),child.id())).unwrap();
  loop{thread::sleep(Duration::from_secs(1));}
 }
 if a.get(1).is_some_and(|x|x=="linger") {
  let cancelled=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
  if env::var_os("IGNORE_TERM").is_some(){signal_hook::flag::register(signal_hook::consts::SIGTERM,cancelled.clone()).unwrap();}
  fs::write("linger-ready",b"ready").unwrap();
  loop{
   if cancelled.load(std::sync::atomic::Ordering::SeqCst) && !fs::read_dir(".").unwrap().flatten().any(|e|e.file_name().to_string_lossy().starts_with("system-update-")) {
    fs::write("guards-lost-before-terminal",b"unsafe").unwrap();
   }
   thread::sleep(Duration::from_millis(1));}}
 if a.iter().any(|x|x=="eval") {print!("{}",fs::read_to_string("plan.json").unwrap());return;}
 if a.iter().any(|x|x=="build") {
  let source=if a.last().unwrap().ends_with(".toplevel"){env::var("FIXTURE_TOPLEVEL").unwrap()}else{env::var("FIXTURE_ARTIFACT").unwrap()};
  if let Some(i)=a.iter().position(|x|x=="--out-link"){std::os::unix::fs::symlink(&source,&a[i+1]).unwrap();}
  println!("{source}");return;
 }
 if PathHack::hash(&a[0]){println!("{}  ignored","a".repeat(128));return;}
 std::process::exit(37);
}
struct PathHack;impl PathHack{fn hash(x:&str)->bool{x.ends_with("hash")}}
"#).unwrap();
        let dependencies = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let signal_hook = fs::read_dir(&dependencies)
            .unwrap()
            .map(Result::unwrap)
            .map(|e| e.path())
            .find(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("libsignal_hook-")
                    && p.extension().is_some_and(|e| e == "rlib")
            })
            .unwrap();
        let serde_json = fs::read_dir(&dependencies)
            .unwrap()
            .map(Result::unwrap)
            .map(|e| e.path())
            .find(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("libserde_json-")
                    && p.extension().is_some_and(|e| e == "rlib")
            })
            .unwrap();
        let mut compiler =
            Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()));
        // The release package dependencies contain LLVM bitcode for LTO.
        if !cfg!(debug_assertions) {
            compiler.args(["-C", "lto"]);
        }
        let status = compiler
            .args(["--edition=2024", "-C", "panic=abort", "--extern"])
            .arg(format!("signal_hook={}", signal_hook.display()))
            .arg("--extern")
            .arg(format!("serde_json={}", serde_json.display()))
            .arg("-L")
            .arg(format!("dependency={}", dependencies.display()))
            .arg(&source)
            .arg("-o")
            .arg(&helper)
            .status()
            .unwrap();
        assert!(status.success());
        symlink(&helper, root.join("hash")).unwrap();
        Self {
            cleanup_root: root.clone(),
            root,
            helper,
        }
    }
    fn command(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nix-update-remote"));
        let toplevel = std::env::var_os("NIX_UPDATE_CANCELLATION_TOPLEVEL").unwrap_or_else(|| {
            fs::canonicalize("/run/current-system")
                .unwrap()
                .into_os_string()
        });
        let artifact = std::env::var_os("NIX_UPDATE_ARTIFACT_TEST_SOURCE").unwrap_or_else(|| {
            fs::canonicalize("/run/current-system/kernel")
                .unwrap()
                .into_os_string()
        });
        c.current_dir(&self.root)
            .env("FIXTURE_TOPLEVEL", toplevel)
            .env("FIXTURE_ARTIFACT", artifact)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        c
    }
}
fn running(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
        s.rsplit_once(") ")
            .is_some_and(|(_, tail)| !tail.starts_with('Z'))
    })
}
fn cancel(child: &mut Child, root: &Path, signal: Signal) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !root.join("children").exists() {
        assert!(
            Instant::now() < deadline,
            "fixture did not reach blocked signing"
        );
        assert!(child.try_wait().unwrap().is_none());
        std::thread::sleep(Duration::from_millis(20));
    }
    if root.join("expect-blocked-upload").exists() {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !fs::read_to_string(format!("/proc/{}/wchan", child.id()))
            .is_ok_and(|s| s.contains("pipe_write"))
        {
            assert!(
                Instant::now() < deadline,
                "uploader did not block on the non-reading consumer pipe"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    if root.join("expect-blocked-signer").exists() {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let blocked = fs::read_dir(format!("/proc/{}/task", child.id()))
                .unwrap()
                .flatten()
                .any(|task| {
                    fs::read_to_string(task.path().join("wchan"))
                        .is_ok_and(|s| s.contains("pipe_write"))
                });
            if blocked {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "signer input writer did not block"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let pids: Vec<u32> = fs::read_to_string(root.join("children"))
        .unwrap()
        .split_whitespace()
        .map(|x| x.parse().unwrap())
        .collect();
    kill_process(Pid::from_raw(child.id() as i32).unwrap(), signal).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < deadline, "cancel did not finish");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(!status.success());
    assert!(
        !root.join("guards-lost-before-terminal").exists(),
        "guards were removed while a group member was still alive"
    );
    for pid in pids {
        assert!(!running(pid), "owned child {pid} survived cancellation");
    }
    for entry in fs::read_dir(root).unwrap() {
        let e = entry.unwrap();
        let n = e.file_name().to_string_lossy().into_owned();
        assert!(
            !n.starts_with("system-update-roots-") && !n.starts_with("system-update-")
                || n == "system-update-public-keys",
            "temporary transaction leaked: {n}"
        );
    }
    if root.join("system-update-public-keys").exists() {
        assert_eq!(
            fs::read_dir(root.join("system-update-public-keys"))
                .unwrap()
                .count(),
            0,
            "public key leaked"
        );
    }
}
fn configured(signal: Signal, label: &str) {
    let f = Fixture::new(label);
    let plan = serde_json::json!({"host":"fixture","target":"update@fixture","publicKey":"ssh-ed25519 AAAA public-fixture","backend":"deploy-generation","arguments":["--installable","{installable}","--target","{target}","--nix",f.helper,"--sha512sum",f.root.join("hash"),"--sign-command",f.helper,"--sign-arg","block"],"sessionEnvironment":"TEST_SESSION","sessionCommand":[],"authenticationCommand":[f.helper,"auth"],"sshArguments":[],"copySshArguments":[],"reboot":false});
    fs::write(f.root.join("plan.json"), plan.to_string()).unwrap();
    let mut child = TestProcess(
        f.command()
            .env("IGNORE_TERM", "1")
            .args([
                "configured-deploy",
                "--installable",
                "fixture#host",
                "--nix",
            ])
            .arg(&f.helper)
            .args(["--plan", "unused"])
            .spawn()
            .unwrap(),
    );
    cancel(&mut child, &f.root, signal);
}
#[test]
fn sigint_cleans_nested_public_key_artifacts_roots_and_children() {
    configured(Signal::INT, "int");
}
#[test]
fn sigterm_cleans_nested_public_key_artifacts_roots_and_children() {
    configured(Signal::TERM, "term");
}
#[test]
fn ordinary_failed_provider_cleans_artifacts() {
    let f = Fixture::new("failure");
    let mut c = f.command();
    c.args([
        "deploy-artifact",
        "--target",
        "update@fixture",
        "--sign-command",
    ])
    .arg(&f.helper)
    .arg("--sha512sum")
    .arg(f.root.join("hash"));
    for role in ["--image", "--config", "--kernel", "--initrd", "--rescue"] {
        c.arg(role).arg(
            std::env::var_os("NIX_UPDATE_ARTIFACT_TEST_SOURCE").unwrap_or_else(|| {
                fs::canonicalize("/run/current-system/kernel")
                    .unwrap()
                    .into_os_string()
            }),
        );
    }
    assert!(!c.status().unwrap().success());
    assert!(!fs::read_dir(&f.root).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("system-update-")
    }));
}

#[test]
fn sigterm_unblocks_actual_bundle_pipe_to_nonreading_consumer_and_reaps_children() {
    let f = Fixture::new("blocked-upload");
    fs::write(f.root.join("expect-blocked-upload"), b"required").unwrap();
    let image = f.root.join("large-image");
    fs::File::create(&image)
        .unwrap()
        .set_len(32 * 1024 * 1024)
        .unwrap();
    let artifact = std::env::var_os("NIX_UPDATE_ARTIFACT_TEST_SOURCE").unwrap_or_else(|| {
        fs::canonicalize("/run/current-system/kernel")
            .unwrap()
            .into_os_string()
    });
    let mut c = f.command();
    c.env("IGNORE_TERM", "1")
        .args([
            "deploy-artifact",
            "--target",
            "update@fixture",
            "--sign-command",
        ])
        .arg(&f.helper)
        .args(["--sign-arg", "sign", "--sha512sum"])
        .arg(f.root.join("hash"))
        .arg("--ssh-command")
        .arg(&f.helper)
        .args(["--ssh-arg", "block", "--image"])
        .arg(&image);
    for role in ["--config", "--kernel", "--initrd", "--rescue"] {
        c.arg(role).arg(&artifact);
    }
    let mut child = TestProcess(c.spawn().unwrap());
    cancel(&mut child, &f.root, Signal::TERM);
}

#[test]
fn sigint_joins_blocked_signing_writer_before_cleaning_artifacts() {
    let mut f = Fixture::new("blocked-signing");
    let original = f.root.clone();
    while f.root.as_os_str().len() < 3000 {
        f.root = f.root.join("long-public-fixture-path-segment");
        fs::create_dir(&f.root).unwrap();
    }
    fs::write(f.root.join("expect-blocked-signer"), b"required").unwrap();
    let input = f.root.join("mutable-artifact");
    fs::write(&input, b"public test input").unwrap();
    let mut c = f.command();
    c.env("IGNORE_TERM", "1")
        .args([
            "deploy-artifact",
            "--target",
            "update@fixture",
            "--sign-command",
        ])
        .arg(&f.helper)
        .args(["--sign-arg", "block", "--sha512sum"])
        .arg(original.join("hash"));
    for role in ["--image", "--config", "--kernel", "--initrd", "--rescue"] {
        c.arg(role).arg(&input);
    }
    let mut child = TestProcess(c.spawn().unwrap());
    cancel(&mut child, &f.root, Signal::INT);
    f.root = original;
}
