//! What the update does now, for the operator: each stage as it starts, and
//! the closure upload with its percentage.
//!
//! A configured reporter (such as a procedure step in the operator's TUI)
//! receives `--text TEXT` and, for the upload, `--percent N` appended to its
//! arguments. Reports run one at a time on their own thread, so a slow
//! reporter never holds up the update; of several upload reports waiting,
//! only the newest is sent, while no stage report is ever left out.
//! Reporting never changes the outcome.
use crate::cancellation::ManagedCommand;
use crate::protocol;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The least time between two upload reports.
const UPLOAD_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// Reports of the same kind replace each other while they wait.
    pub kind: &'static str,
    pub text: String,
    pub percent: Option<u8>,
}

pub struct Reporter {
    sender: Option<mpsc::Sender<Report>>,
    worker: Option<JoinHandle<()>>,
}

impl Reporter {
    /// Reports through `command` with `args`; without a command, reports
    /// only reach stderr.
    pub fn new(command: Option<PathBuf>, args: Vec<String>) -> Self {
        Self::with(move |report: &Report| {
            if let Some(command) = &command {
                let mut invocation = Command::new(command);
                invocation
                    .args(&args)
                    .arg("--text")
                    .arg(protocol::one_line(&report.text));
                if let Some(percent) = report.percent {
                    invocation.arg("--percent").arg(percent.to_string());
                }
                let status = invocation.stdin(Stdio::null()).managed_status();
                if !status.is_ok_and(|status| status.success()) {
                    eprintln!("nix-update-remote: the progress reporter did not confirm the report");
                }
            }
        })
    }

    pub fn with(mut deliver: impl FnMut(&Report) + Send + 'static) -> Self {
        let (sender, reports) = mpsc::channel::<Report>();
        let worker = std::thread::spawn(move || {
            let mut last_upload: Option<Instant> = None;
            let mut next = None;
            loop {
                let mut report = match next.take() {
                    Some(report) => report,
                    None => match reports.recv() {
                        Ok(report) => report,
                        Err(_) => return,
                    },
                };
                // A newer report of the same kind replaces a waiting one.
                while let Ok(newer) = reports.try_recv() {
                    if newer.kind == report.kind {
                        report = newer;
                    } else {
                        next = Some(newer);
                        break;
                    }
                }
                if report.kind == "upload" && next.is_none() {
                    if let Some(wait) = last_upload
                        .map(|at| UPLOAD_INTERVAL.saturating_sub(at.elapsed()))
                        .filter(|wait| !wait.is_zero())
                    {
                        match reports.recv_timeout(wait) {
                            Ok(newer) if newer.kind == report.kind => {
                                next = Some(newer);
                                continue;
                            }
                            Ok(other) => next = Some(other),
                            Err(mpsc::RecvTimeoutError::Timeout) => {}
                            Err(mpsc::RecvTimeoutError::Disconnected) => {}
                        }
                    }
                }
                if report.kind == "upload" {
                    last_upload = Some(Instant::now());
                }
                deliver(&report);
            }
        });
        Self {
            sender: Some(sender),
            worker: Some(worker),
        }
    }

    pub fn report(&self, kind: &'static str, text: impl Into<String>, percent: Option<u8>) {
        let text = text.into();
        if kind != "upload" || percent.is_none() {
            eprintln!("nix-update-remote: {text}");
        }
        if let Some(sender) = &self.sender {
            let _ = sender.send(Report { kind, text, percent });
        }
    }

    pub fn stage(&self, stage: protocol::Stage) {
        self.report(stage.word(), stage.describe(), None);
    }
}

impl Drop for Reporter {
    /// Every report is delivered before the update ends.
    fn drop(&mut self) {
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Nix activity types of `--log-format internal-json`.
const ACT_COPY_PATH: u64 = 100;
const ACT_COPY_PATHS: u64 = 103;
const RES_PROGRESS: u64 = 105;
const RES_SET_EXPECTED: u64 = 106;

/// The progress of a `nix copy`, from its internal-json log.
#[derive(Debug, Default)]
pub struct Upload {
    /// Running `copying N paths` activities: paths done and expected.
    paths: BTreeMap<u64, (u64, u64)>,
    /// Bytes expected by the `copying N paths` activities.
    expected_bytes: u64,
    /// Every path copy: bytes done and expected.
    copies: BTreeMap<u64, (u64, u64)>,
    kinds: BTreeMap<u64, u64>,
}

impl Upload {
    /// Takes one stderr line of `nix copy --log-format internal-json`.
    /// Returns what a person should see of it, and whether the progress
    /// changed.
    pub fn line(&mut self, line: &str) -> (Option<String>, bool) {
        let Some(json) = line.strip_prefix("@nix ") else {
            return (Some(line.to_owned()), false);
        };
        let Ok(event) = serde_json::from_str::<serde_json::Value>(json) else {
            return (Some(line.to_owned()), false);
        };
        let number = |value: &serde_json::Value| value.as_u64().unwrap_or(0);
        let id = number(&event["id"]);
        let field = |index: usize| number(&event["fields"][index]);
        match event["action"].as_str() {
            Some("msg") => {
                // Errors, warnings and notices, as Nix prints them by default.
                let shown = number(&event["level"]) <= 3;
                (shown.then(|| event["msg"].as_str().unwrap_or_default().to_owned()), false)
            }
            Some("start") => {
                let kind = number(&event["type"]);
                self.kinds.insert(id, kind);
                if kind == ACT_COPY_PATH {
                    self.copies.insert(id, (0, 0));
                    return (None, true);
                }
                (None, false)
            }
            Some("stop") => match self.kinds.remove(&id) {
                Some(ACT_COPY_PATH) => {
                    if let Some(copy) = self.copies.get_mut(&id) {
                        copy.0 = copy.1.max(copy.0);
                    }
                    (None, true)
                }
                _ => (None, false),
            },
            Some("result") => match (self.kinds.get(&id).copied(), number(&event["type"])) {
                (Some(ACT_COPY_PATHS), RES_SET_EXPECTED) if field(0) == ACT_COPY_PATH => {
                    self.expected_bytes += field(1);
                    (None, true)
                }
                (Some(ACT_COPY_PATHS), RES_PROGRESS) => {
                    self.paths.insert(id, (field(0), field(1)));
                    (None, true)
                }
                (Some(ACT_COPY_PATH), RES_PROGRESS) => {
                    self.copies.insert(id, (field(0), field(1)));
                    (None, true)
                }
                _ => (None, false),
            },
            _ => (None, false),
        }
    }

    fn bytes(&self) -> u64 {
        self.copies.values().map(|(done, _)| done).sum()
    }

    /// Paths copied and expected.
    fn path_counts(&self) -> (u64, u64) {
        self.paths
            .values()
            .fold((0, 0), |(done, expected), (d, e)| (done + d, expected + e))
    }

    pub fn percent(&self) -> u8 {
        let (done, expected) = self.path_counts();
        let fraction = if self.expected_bytes > 0 {
            self.bytes() as f64 / self.expected_bytes as f64
        } else if expected > 0 {
            done as f64 / expected as f64
        } else {
            0.0
        };
        (fraction * 100.0).clamp(0.0, 100.0) as u8
    }

    /// `uploading the closure: 45% (153 of 340 paths, 367.2 of 812.0 MiB)`.
    pub fn text(&self) -> String {
        let (done, expected) = self.path_counts();
        let mib = |bytes: u64| bytes as f64 / (1024.0 * 1024.0);
        if expected == 0 {
            return "uploading the closure".into();
        }
        let mut text = format!(
            "uploading the closure: {}% ({done} of {expected} paths",
            self.percent()
        );
        if self.expected_bytes > 0 {
            text.push_str(&format!(
                ", {:.1} of {:.1} MiB",
                mib(self.bytes().min(self.expected_bytes)),
                mib(self.expected_bytes)
            ));
        }
        text.push(')');
        text
    }
}

/// Runs `nix copy` (or another Nix command that copies paths) and reports
/// its progress while it runs. Nix's own messages still reach stderr.
pub fn copy(command: &mut Command, action: &str, reporter: &Reporter) -> Result<(), String> {
    command
        .arg("--log-format")
        .arg("internal-json")
        .stdin(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command.managed_spawn().map_err(|e| e.to_string())?;
    let stderr = child.stderr.take().ok_or("missing Nix log pipe")?;
    let mut upload = Upload::default();
    follow_log(stderr, &mut upload, &mut |upload| {
        reporter.report("upload", upload.text(), Some(upload.percent()));
    });
    let status = child.wait().map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("{action} failed"));
    }
    let (done, expected) = upload.path_counts();
    let text = if expected == 0 {
        "uploaded the closure: every path was already on the host".to_owned()
    } else {
        format!(
            "uploaded the closure: 100% ({done} of {expected} paths, {:.1} MiB)",
            upload.expected_bytes as f64 / (1024.0 * 1024.0)
        )
    };
    reporter.report("upload", text, Some(100));
    Ok(())
}

fn follow_log(stderr: impl Read, upload: &mut Upload, changed: &mut dyn FnMut(&Upload)) {
    let mut last = None;
    for line in BufReader::new(stderr).split(b'\n') {
        let Ok(line) = line else { break };
        let line = String::from_utf8_lossy(&line);
        let (shown, progressed) = upload.line(&line);
        if let Some(shown) = shown {
            eprintln!("{shown}");
        }
        if progressed {
            let now = (upload.path_counts(), upload.percent());
            if last != Some(now) {
                last = Some(now);
                changed(upload);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn upload_progress_follows_paths_and_bytes() {
        let mut upload = Upload::default();
        for line in [
            r#"@nix {"action":"start","id":1,"level":0,"parent":0,"text":"","type":103}"#,
            r#"@nix {"action":"stop","id":1}"#,
            r#"@nix {"action":"start","id":2,"level":3,"parent":0,"text":"copying 2 paths","type":103}"#,
            r#"@nix {"action":"result","fields":[100,4000],"id":2,"type":106}"#,
            r#"@nix {"action":"result","fields":[0,2,1,0],"id":2,"type":105}"#,
            r#"@nix {"action":"start","fields":["/nix/store/a","daemon","ssh-ng://h"],"id":3,"level":3,"parent":0,"text":"copying path","type":100}"#,
            r#"@nix {"action":"result","fields":[1000,3000,0,0],"id":3,"type":105}"#,
        ] {
            assert_eq!(upload.line(line).0, None, "{line}");
        }
        assert_eq!(upload.percent(), 25);
        assert_eq!(upload.text(), "uploading the closure: 25% (0 of 2 paths, 0.0 of 0.0 MiB)");
        upload.line(r#"@nix {"action":"stop","id":3}"#);
        upload.line(r#"@nix {"action":"result","fields":[1,2,0,0],"id":2,"type":105}"#);
        assert_eq!(upload.percent(), 75);
        assert!(upload.text().starts_with("uploading the closure: 75% (1 of 2 paths"));
        // Nix's messages still reach the operator; other lines pass as they are.
        assert_eq!(
            upload.line(r#"@nix {"action":"msg","level":0,"msg":"error: cannot connect"}"#).0.as_deref(),
            Some("error: cannot connect")
        );
        assert_eq!(upload.line(r#"@nix {"action":"msg","level":5,"msg":"debug"}"#).0, None);
        assert_eq!(upload.line("plain").0.as_deref(), Some("plain"));
    }

    #[test]
    fn stage_reports_are_never_coalesced_and_upload_reports_are() {
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let seen = delivered.clone();
        let reporter = Reporter::with(move |report: &Report| {
            std::thread::sleep(Duration::from_millis(20));
            seen.lock().unwrap().push((report.kind, report.percent));
        });
        for percent in 0..=100 {
            reporter.report("upload", "uploading", Some(percent));
        }
        reporter.stage(protocol::Stage::Verifying);
        reporter.stage(protocol::Stage::Activating);
        drop(reporter);
        let delivered = delivered.lock().unwrap();
        assert!(delivered.len() < 20, "{delivered:?}");
        assert!(delivered.contains(&("upload", Some(100))), "{delivered:?}");
        assert_eq!(
            delivered[delivered.len() - 2..],
            [("verifying", None), ("activating", None)]
        );
    }

    /// A real `nix copy` between two stores reports its paths and bytes.
    #[test]
    fn a_real_nix_copy_reports_its_progress() {
        let nix = std::env::var("NIX_UPDATE_TEST_NIX").unwrap_or_else(|_| "nix".into());
        let temp = std::env::temp_dir().join(format!(
            "upload-progress-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&temp).unwrap();
        struct Guard(PathBuf);
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = Command::new("chmod").arg("-R").arg("u+w").arg(&self.0).status();
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _guard = Guard(temp.clone());
        let source = format!("local?root={}", temp.join("source").display());
        let fixture = temp.join("fixture");
        std::fs::write(&fixture, vec![b'x'; 256 * 1024]).unwrap();
        let output = Command::new(&nix)
            .args(["--extra-experimental-features", "nix-command", "--option", "build-users-group", "", "--store", &source])
            .args(["store", "add-path", "--name", "upload-progress-test"])
            .arg(&fixture)
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let path = String::from_utf8(output.stdout).unwrap().trim().to_owned();
        let reports = Arc::new(Mutex::new(Vec::new()));
        let seen = reports.clone();
        let reporter = Reporter::with(move |report: &Report| seen.lock().unwrap().push(report.clone()));
        let mut command = Command::new(&nix);
        command
            .args(["--extra-experimental-features", "nix-command", "--option", "build-users-group", "", "--store", &source])
            .args(["copy", "--no-check-sigs", "--to"])
            .arg(format!("file://{}", temp.join("cache").display()))
            .arg(&path);
        copy(&mut command, "copying closure", &reporter).unwrap();
        drop(reporter);
        let reports = reports.lock().unwrap();
        // Paths and bytes come from Nix's own progress events.
        let last = reports.last().unwrap();
        assert_eq!(
            (last.text.as_str(), last.percent),
            ("uploaded the closure: 100% (1 of 1 paths, 0.3 MiB)", Some(100)),
            "{reports:?}"
        );
    }
}
