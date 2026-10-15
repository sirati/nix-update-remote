//! The transaction host on the running NixOS system.
use crate::cancellation::ManagedCommand;
use crate::transaction::{Action, Events, Host, Journal, UnitState};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const KEEPALIVE: Duration = Duration::from_secs(20);
const SWITCH_LOCK: &str = "/run/nixos/switch-to-configuration.lock";
const LOCK_WAIT: Duration = Duration::from_secs(600);
const WATCH_INTERVAL: Duration = Duration::from_secs(2);

/// Units that failed since `baseline`, belong to the running system and
/// have no job left: a unit restarted by the switch may fail while it is
/// stopped and still have its start job queued.
pub fn settled_failures(
    failed: &BTreeSet<String>,
    baseline: &BTreeSet<String>,
    states: &[UnitState],
    jobs: &BTreeSet<String>,
) -> BTreeSet<String> {
    states
        .iter()
        .filter(|state| {
            state.loaded
                && failed.contains(&state.id)
                && !baseline.contains(&state.id)
                && !jobs.contains(&state.id)
        })
        .map(|state| state.id.clone())
        .collect()
}

pub struct SystemHost<'a> {
    pub nix_env: &'a Path,
    pub profile: &'a Path,
    pub systemctl: &'a Path,
    pub state_dir: &'a Path,
    /// Where the journal's phase is published to the update account.
    pub phase_file: &'a Path,
    pub ssh_ports: &'a [u16],
    pub health_units: &'a [String],
    pub settle: Duration,
    pub health_timeout: Duration,
}

impl SystemHost<'_> {
    fn journal_path(&self) -> PathBuf {
        self.state_dir.join("transaction.json")
    }

    /// Makes the published phase match the journal again, after a daemon
    /// that stopped between the two.
    pub fn republish_phase(&self) -> Result<(), String> {
        self.publish_phase(self.read_journal()?.map(|journal| journal.phase))
    }

    /// Publishes the phase of the journal, and nothing else of it, to the
    /// update account, which may not read the journal; `None` removes it.
    fn publish_phase(&self, phase: Option<crate::transaction::Phase>) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;
        let Some(phase) = phase else {
            return match fs::remove_file(self.phase_file) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    Err(format!("removing {}: {error}", self.phase_file.display()))
                }
                _ => Ok(()),
            };
        };
        let temporary = self.phase_file.with_extension("new");
        let error = |e: std::io::Error| format!("publishing the update phase in {}: {e}", self.phase_file.display());
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o640)
            .open(&temporary)
            .map_err(error)?;
        // Readable, never writable, by the update group.
        file.set_permissions(fs::Permissions::from_mode(0o640)).map_err(error)?;
        file.write_all(format!("{}\n", phase.word()).as_bytes()).map_err(error)?;
        fs::rename(&temporary, self.phase_file).map_err(error)
    }

    fn systemctl_lines(&self, args: &[&str]) -> Result<Vec<String>, String> {
        let output = Command::new(self.systemctl)
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .output()
            .map_err(|e| format!("running systemctl: {e}"))?;
        if !output.status.success() {
            return Err(format!("systemctl {} failed: {}", args.join(" "), output.status));
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_owned)
            .collect())
    }

    fn jobs(&self) -> Result<BTreeSet<String>, String> {
        Ok(self
            .systemctl_lines(&["list-jobs", "--plain", "--no-legend", "--no-pager", "--full"])?
            .iter()
            .filter_map(|line| line.split_whitespace().nth(1).map(str::to_owned))
            .collect())
    }

    fn unit_list(&self, args: &[&str]) -> Result<BTreeSet<String>, String> {
        let mut all = vec!["list-units", "--plain", "--no-legend", "--no-pager", "--full"];
        all.extend_from_slice(args);
        Ok(self
            .systemctl_lines(&all)?
            .iter()
            .filter_map(|line| line.split_whitespace().next().map(str::to_owned))
            .collect())
    }

    fn systemctl_on(
        &self,
        verb: &str,
        units: &BTreeSet<String>,
        events: &mut dyn Events,
        timeout: Option<Duration>,
    ) -> Result<(), String> {
        if units.is_empty() {
            return Ok(());
        }
        let status = polled(
            Command::new(self.systemctl).arg(verb).arg("--").args(units),
            &format!("systemctl {verb}"),
            events,
            timeout,
            None,
        )?;
        if status.success() {
            Ok(())
        } else {
            Err(format!(
                "systemctl {verb} {} failed: {status}",
                units.iter().cloned().collect::<Vec<_>>().join(" ")
            ))
        }
    }
}

/// Waits for `command` while telling the client it is still alive and,
/// with `announce`, when that system becomes the current one.
fn polled(
    command: &mut Command,
    phase: &str,
    events: &mut dyn Events,
    timeout: Option<Duration>,
    announce: Option<&Path>,
) -> Result<ExitStatus, String> {
    polled_watching(command, phase, events, timeout, announce, &mut || None)
}

/// As [`polled`]; once the system is announced, `watch` runs every few
/// seconds and a reason it returns ends the command.
fn polled_watching(
    command: &mut Command,
    phase: &str,
    events: &mut dyn Events,
    timeout: Option<Duration>,
    announce: Option<&Path>,
    watch: &mut dyn FnMut() -> Option<String>,
) -> Result<ExitStatus, String> {
    let mut last_watch = Instant::now();
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .managed_spawn()
        .map_err(|e| format!("{phase}: {e}"))?;
    let start = Instant::now();
    let mut last = start;
    let mut announced = false;
    loop {
        if let Some(system) = announce {
            if !announced && fs::read_link("/run/current-system").is_ok_and(|p| p == system) {
                // Progress means /etc and current-system are installed, not
                // that start jobs succeeded.
                events.activated(system);
                announced = true;
            }
        }
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Ok(status);
        }
        if announced && last_watch.elapsed() >= WATCH_INTERVAL {
            last_watch = Instant::now();
            if let Some(reason) = watch() {
                let _ = child.kill();
                let _ = child.wait();
                return Err(reason);
            }
        }
        if timeout.is_some_and(|limit| start.elapsed() >= limit) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{phase} did not finish within {}s", timeout.unwrap().as_secs()));
        }
        if last.elapsed() >= KEEPALIVE {
            events.waiting(phase);
            last = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Ports from `/proc/net/tcp`-format text that are in the LISTEN state.
pub fn listening_ports(table: &str) -> BTreeSet<u16> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let local = fields.nth(1)?;
            let state = fields.nth(1)?;
            let port = local.rsplit_once(':')?.1;
            (state == "0A").then(|| u16::from_str_radix(port, 16).ok()).flatten()
        })
        .collect()
}

/// `systemctl show` output: one block per unit.
pub fn parse_unit_states(text: &str) -> Vec<UnitState> {
    text.split("\n\n")
        .filter_map(|block| {
            let mut id = None;
            let mut load = None;
            let mut active = None;
            for line in block.lines() {
                match line.split_once('=') {
                    Some(("Id", value)) => id = Some(value.to_owned()),
                    Some(("LoadState", value)) => load = Some(value.to_owned()),
                    Some(("ActiveState", value)) => active = Some(value.to_owned()),
                    _ => {}
                }
            }
            Some(UnitState {
                id: id?,
                loaded: load? == "loaded",
                active: active?,
            })
        })
        .collect()
}

impl Host for SystemHost<'_> {
    fn boot_id(&self) -> Result<String, String> {
        fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map(|id| id.trim().to_owned())
            .map_err(|e| format!("reading the boot id: {e}"))
    }

    fn current_system(&self) -> Option<PathBuf> {
        fs::read_link("/run/current-system").ok()
    }

    fn profile_target(&self) -> Result<Option<PathBuf>, String> {
        match fs::read_link(self.profile) {
            Ok(target) => Ok(Some(target)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("reading the system profile: {error}")),
        }
    }

    fn set_profile(&mut self, system: &Path) -> Result<(), String> {
        crate::verify::checked(
            Command::new(self.nix_env)
                .arg("--profile")
                .arg(self.profile)
                .arg("--set")
                .arg(system),
            "setting system profile",
        )
    }

    fn restore_profile(&mut self, target: Option<&Path>) -> Result<(), String> {
        let Some(target) = target else {
            return match fs::remove_file(self.profile) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.to_string()),
                _ => Ok(()),
            };
        };
        // Replace the link atomically, as nix-env does.
        let name = self.profile.file_name().ok_or("profile has no name")?;
        let temporary = self
            .profile
            .with_file_name(format!(".{}-restore-{}", name.to_string_lossy(), std::process::id()));
        let _ = fs::remove_file(&temporary);
        symlink(target, &temporary).map_err(|e| e.to_string())?;
        fs::rename(&temporary, self.profile).map_err(|e| {
            let _ = fs::remove_file(&temporary);
            e.to_string()
        })
    }

    fn switch(
        &mut self,
        system: &Path,
        action: Action,
        watch: Option<&BTreeSet<String>>,
        events: &mut dyn Events,
    ) -> Result<Option<i32>, String> {
        // A failure must be seen twice in a row before it ends the switch.
        let mut seen: Option<BTreeSet<String>> = None;
        let mut check = || {
            let baseline = watch?;
            let failed = self.failed_units().ok()?;
            let candidates: BTreeSet<String> = failed.difference(baseline).cloned().collect();
            if candidates.is_empty() {
                seen = None;
                return None;
            }
            let states = self.unit_states(&candidates).ok()?;
            let jobs = self.jobs().ok()?;
            let now = settled_failures(&failed, baseline, &states, &jobs);
            let confirmed = !now.is_empty() && seen.as_ref() == Some(&now);
            seen = (!now.is_empty()).then(|| now.clone());
            confirmed.then(|| {
                format!(
                    "units failed during activation: {}",
                    now.into_iter().collect::<Vec<_>>().join(", ")
                )
            })
        };
        polled_watching(
            Command::new(system.join("bin/switch-to-configuration")).arg(action.name()),
            &format!("switch-to-configuration {}", action.name()),
            events,
            None,
            watch.map(|_| system),
            &mut check,
        )
        .map(|status| status.code())
    }

    fn wait_switch_lock(&mut self, events: &mut dyn Events) -> Result<(), String> {
        let start = Instant::now();
        let mut last = start;
        loop {
            let file = match fs::File::open(SWITCH_LOCK) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(format!("opening {SWITCH_LOCK}: {error}")),
            };
            if rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).is_ok() {
                // Closing the file releases the lock for our own switch.
                return Ok(());
            }
            if start.elapsed() >= LOCK_WAIT {
                return Err("another switch-to-configuration is still running".into());
            }
            if last.elapsed() >= KEEPALIVE {
                events.waiting("waiting for another switch-to-configuration");
                last = Instant::now();
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    fn failed_units(&self) -> Result<BTreeSet<String>, String> {
        self.unit_list(&["--failed", "--all"])
    }

    fn running_services(&self) -> Result<BTreeSet<String>, String> {
        self.unit_list(&["--type=service", "--state=running"])
    }

    fn unit_states(&self, units: &BTreeSet<String>) -> Result<Vec<UnitState>, String> {
        if units.is_empty() {
            return Ok(Vec::new());
        }
        let mut args = vec!["show", "--property=Id,LoadState,ActiveState", "--no-pager", "--"];
        args.extend(units.iter().map(String::as_str));
        Ok(parse_unit_states(&self.systemctl_lines(&args)?.join("\n")))
    }

    fn reset_failed(&mut self, units: &BTreeSet<String>) -> Result<(), String> {
        let mut args = vec!["reset-failed", "--"];
        args.extend(units.iter().map(String::as_str));
        self.systemctl_lines(&args).map(drop)
    }

    fn restart_units(
        &mut self,
        units: &BTreeSet<String>,
        events: &mut dyn Events,
    ) -> Result<(), String> {
        self.systemctl_on("restart", units, events, Some(self.health_timeout))
    }

    fn run_health_units(
        &mut self,
        skip: &BTreeSet<String>,
        events: &mut dyn Events,
    ) -> Result<(), String> {
        let units: BTreeSet<String> = self
            .health_units
            .iter()
            .filter(|unit| !skip.contains(*unit))
            .cloned()
            .collect();
        self.systemctl_on("start", &units, events, Some(self.health_timeout))
    }

    fn settle(&mut self, events: &mut dyn Events) {
        let start = Instant::now();
        while start.elapsed() < self.settle {
            std::thread::sleep(Duration::from_millis(250));
        }
        events.waiting("checking the system health");
    }

    fn ssh_missing(&self) -> Result<Vec<u16>, String> {
        if self.ssh_ports.is_empty() {
            return Ok(Vec::new());
        }
        let mut listening = BTreeSet::new();
        for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
            if let Ok(text) = fs::read_to_string(table) {
                listening.extend(listening_ports(&text));
            }
        }
        Ok(self
            .ssh_ports
            .iter()
            .copied()
            .filter(|port| !listening.contains(port))
            .collect())
    }

    fn write_journal(&mut self, journal: &Journal) -> Result<(), String> {
        fs::create_dir_all(self.state_dir).map_err(|e| e.to_string())?;
        let path = self.journal_path();
        let temporary = path.with_extension("json.new");
        let bytes = serde_json::to_vec(journal).map_err(|e| e.to_string())?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&temporary, &path).map_err(|e| e.to_string())?;
        fs::File::open(self.state_dir)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| e.to_string())?;
        self.publish_phase(Some(journal.phase))
    }

    fn read_journal(&self) -> Result<Option<Journal>, String> {
        match fs::read(self.journal_path()) {
            Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| e.to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    fn clear_journal(&mut self) -> Result<(), String> {
        match fs::remove_file(self.journal_path()) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.to_string()),
            _ => fs::File::open(self.state_dir)
                .and_then(|dir| dir.sync_all())
                .or_else(|e| if e.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(e) })
                .map_err(|e| e.to_string())
                .and_then(|()| self.publish_phase(None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_listening_sockets_count() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue\n\
           0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000\n\
           1: 0100007F:1F90 0100007F:D2F0 01 00000000:00000000 00:00000000 00000000\n";
        assert_eq!(listening_ports(table), BTreeSet::from([22]));
        let table6 = "  sl  local_address                         remote_address                        st\n\
           0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 0\n";
        assert_eq!(listening_ports(table6), BTreeSet::from([22]));
    }

    #[test]
    fn unit_states_parse_per_block() {
        let states = parse_unit_states(
            "ActiveState=failed\nLoadState=not-found\nId=gone.service\n\nId=a.service\nLoadState=loaded\nActiveState=active\n",
        );
        assert_eq!(
            states,
            [
                UnitState { id: "gone.service".into(), loaded: false, active: "failed".into() },
                UnitState { id: "a.service".into(), loaded: true, active: "active".into() },
            ]
        );
    }

    #[test]
    fn journal_survives_a_daemon_restart_and_the_profile_link_is_restored() {
        let directory = std::env::temp_dir().join(format!("nur-host-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let profile = directory.join("system");
        symlink("system-1-link", &profile).unwrap();
        let state = directory.join("state");
        let mut host = SystemHost {
            nix_env: Path::new("/nonexistent"),
            profile: &profile,
            systemctl: Path::new("/nonexistent"),
            state_dir: &state,
            phase_file: &directory.join("transaction-phase"),
            ssh_ports: &[],
            health_units: &[],
            settle: Duration::ZERO,
            health_timeout: Duration::ZERO,
        };
        let journal = Journal {
            boot_id: "b".into(),
            previous_system: "/nix/store/a".into(),
            previous_profile: host.profile_target().unwrap(),
            new_system: "/nix/store/b".into(),
            phase: crate::transaction::Phase::Committing,
            failed_before: BTreeSet::new(),
            running_before: BTreeSet::from(["sshd.service".to_owned()]),
        };
        let phase = directory.join("transaction-phase");
        host.write_journal(&Journal { phase: crate::transaction::Phase::Activating, ..journal.clone() }).unwrap();
        assert_eq!(fs::read_to_string(&phase).unwrap(), "activating\n");
        host.write_journal(&journal).unwrap();
        assert_eq!(host.read_journal().unwrap(), Some(journal));
        // The update account reads the phase and nothing else of the journal.
        assert_eq!(fs::read_to_string(&phase).unwrap(), "committing\n");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&phase).unwrap().permissions().mode() & 0o777, 0o640);
        assert_eq!(fs::metadata(state.join("transaction.json")).unwrap().permissions().mode() & 0o077, 0);
        fs::remove_file(&phase).unwrap();
        host.republish_phase().unwrap();
        assert_eq!(fs::read_to_string(&phase).unwrap(), "committing\n", "a lost phase is published again");
        fs::remove_file(&profile).unwrap();
        symlink("system-2-link", &profile).unwrap();
        host.restore_profile(Some(Path::new("system-1-link"))).unwrap();
        assert_eq!(fs::read_link(&profile).unwrap(), Path::new("system-1-link"));
        host.restore_profile(None).unwrap();
        assert!(fs::symlink_metadata(&profile).is_err());
        host.clear_journal().unwrap();
        assert_eq!(host.read_journal().unwrap(), None);
        assert!(!phase.exists(), "no phase without a transaction");
        fs::write(&phase, "committing\n").unwrap();
        host.republish_phase().unwrap();
        assert!(!phase.exists(), "a stale phase is removed");
        fs::remove_dir_all(&directory).unwrap();
    }
}

#[cfg(test)]
mod watch_tests {
    use super::*;

    #[test]
    fn only_settled_failures_of_the_new_system_end_a_switch() {
        let set = |units: &[&str]| units.iter().map(|u| u.to_string()).collect::<BTreeSet<_>>();
        let state = |id: &str, loaded| UnitState { id: id.into(), loaded, active: "failed".into() };
        let failed = set(&["new.service", "restarting.service", "gone.service", "old.service"]);
        let states = [
            state("new.service", true),
            state("restarting.service", true),
            state("gone.service", false),
            state("old.service", true),
        ];
        assert_eq!(
            settled_failures(&failed, &set(&["old.service"]), &states, &set(&["restarting.service"])),
            set(&["new.service"])
        );
    }
}
