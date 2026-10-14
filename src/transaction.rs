//! A system switch as a recoverable transaction.
//!
//! The new system is activated with `switch-to-configuration test` first, so
//! the profile and the bootloader still name the previous system while it is
//! unproven. Only after activation succeeded and the health gate passed are
//! the profile and the bootloader committed. Any failure on the way restores
//! the previous system: the profile link, the bootloader entry when it was
//! touched, and the running system, which is then verified.
//!
//! A journal written before the first change survives a daemon restart, so
//! an interrupted switch is rolled back when the daemon starts again.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// Only the running system may have changed.
    Activating,
    /// The profile and the bootloader may name the new system.
    Committing,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub boot_id: String,
    pub previous_system: PathBuf,
    /// Where the system profile link pointed, such as `system-12-link`.
    pub previous_profile: Option<PathBuf>,
    pub new_system: PathBuf,
    pub phase: Phase,
    pub failed_before: BTreeSet<String>,
    pub running_before: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Test,
    Boot,
}

impl Action {
    pub fn name(self) -> &'static str {
        match self {
            Action::Test => "test",
            Action::Boot => "boot",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitState {
    pub id: String,
    pub loaded: bool,
    pub active: String,
}

/// Progress of one transaction, sent to the client as it happens.
pub trait Events {
    /// The new system is installed as `/run/current-system`.
    fn activated(&mut self, system: &Path);
    /// The new system failed; the rollback starts now.
    fn failed(&mut self, reason: &str);
    /// Still working; keeps a waiting client from timing out.
    fn waiting(&mut self, phase: &str);
    /// Something the operator must see that does not fail the update.
    fn warning(&mut self, text: &str);
}

/// What the transaction needs from the host. The daemon implements it on the
/// real system; tests simulate a host.
pub trait Host {
    fn boot_id(&self) -> Result<String, String>;
    fn current_system(&self) -> Option<PathBuf>;
    fn profile_target(&self) -> Result<Option<PathBuf>, String>;
    fn set_profile(&mut self, system: &Path) -> Result<(), String>;
    fn restore_profile(&mut self, target: Option<&Path>) -> Result<(), String>;
    /// Runs `switch-to-configuration`; `Ok(None)` when it died by a signal.
    /// With `watch`, the activation of the new system is announced, and a
    /// unit of it that fails and stays failed, compared with the units
    /// failed before (`watch`), ends the switch at once with `Err`: a switch
    /// blocked on other units would otherwise hide the failure.
    fn switch(
        &mut self,
        system: &Path,
        action: Action,
        watch: Option<&BTreeSet<String>>,
        events: &mut dyn Events,
    ) -> Result<Option<i32>, String>;
    fn wait_switch_lock(&mut self, events: &mut dyn Events) -> Result<(), String>;
    fn failed_units(&self) -> Result<BTreeSet<String>, String>;
    fn running_services(&self) -> Result<BTreeSet<String>, String>;
    fn unit_states(&self, units: &BTreeSet<String>) -> Result<Vec<UnitState>, String>;
    fn reset_failed(&mut self, units: &BTreeSet<String>) -> Result<(), String>;
    fn restart_units(
        &mut self,
        units: &BTreeSet<String>,
        events: &mut dyn Events,
    ) -> Result<(), String>;
    /// Starts the configured health units and waits for them.
    fn run_health_units(
        &mut self,
        skip: &BTreeSet<String>,
        events: &mut dyn Events,
    ) -> Result<(), String>;
    /// Gives units that fail shortly after their start time to do so.
    fn settle(&mut self, events: &mut dyn Events);
    /// SSH ports that are configured but not listening.
    fn ssh_missing(&self) -> Result<Vec<u16>, String>;
    fn write_journal(&mut self, journal: &Journal) -> Result<(), String>;
    fn read_journal(&self) -> Result<Option<Journal>, String>;
    fn clear_journal(&mut self) -> Result<(), String>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The new system is healthy; `warnings` name what was already broken.
    Committed { warnings: Vec<String> },
    /// The new system failed; the previous one is restored and verified.
    RolledBack { failure: String, detail: String },
    /// The new system failed and the rollback could not be verified.
    RollbackFailed { failure: String, problems: String },
}

fn exit_text(action: Action, code: Option<i32>) -> String {
    match code {
        Some(code) => format!("switch-to-configuration {} exited with status {code}", action.name()),
        None => format!("switch-to-configuration {} was killed by a signal", action.name()),
    }
}

fn list(units: &BTreeSet<String>) -> String {
    units.iter().cloned().collect::<Vec<_>>().join(", ")
}

/// Switches to `new`. `Err` means nothing changed on the host.
pub fn update(host: &mut dyn Host, new: &Path, events: &mut dyn Events) -> Result<Outcome, String> {
    let previous = host
        .current_system()
        .ok_or("cannot read the current system")?;
    let mut journal = Journal {
        boot_id: host.boot_id()?,
        previous_system: previous,
        previous_profile: host.profile_target()?,
        new_system: new.to_owned(),
        phase: Phase::Activating,
        failed_before: host.failed_units()?,
        running_before: host.running_services()?,
    };
    host.wait_switch_lock(events)?;
    host.write_journal(&journal)
        .map_err(|error| format!("cannot record the update journal: {error}"))?;

    // A non-zero exit only says that some unit failed. The health gate
    // decides whether anything regressed; a unit that was already broken
    // before the update is a warning, not a reason to roll back.
    let mut warnings = Vec::new();
    let failure = match host.switch(new, Action::Test, Some(&journal.failed_before), events) {
        Ok(Some(code)) => {
            let exit = (code != 0).then(|| exit_text(Action::Test, Some(code)));
            match health(host, &journal, new, events) {
                Ok(found) => {
                    warnings.extend(exit);
                    warnings.extend(found);
                    None
                }
                Err(problem) => Some(match exit {
                    Some(exit) => format!("{exit}; {problem}"),
                    None => problem,
                }),
            }
        }
        Ok(None) => Some(with_failed_units(host, &journal, exit_text(Action::Test, None))),
        Err(error) => Some(format!("activating the new system failed: {error}")),
    };
    if let Some(failure) = failure {
        events.failed(&failure);
        return Ok(rollback(host, &journal, failure, events));
    }

    journal.phase = Phase::Committing;
    let commit = host
        .write_journal(&journal)
        .map_err(|error| format!("cannot record the update journal: {error}"))
        .and_then(|()| host.set_profile(new).map_err(|e| format!("setting the system profile failed: {e}")))
        .and_then(|()| match host.switch(new, Action::Boot, None, events) {
            Ok(Some(0)) => Ok(()),
            Ok(code) => Err(format!("installing the bootloader failed: {}", exit_text(Action::Boot, code))),
            Err(error) => Err(format!("installing the bootloader failed: {error}")),
        });
    if let Err(failure) = commit {
        events.failed(&failure);
        return Ok(rollback(host, &journal, failure, events));
    }
    if let Err(error) = host.clear_journal() {
        // A stale journal would roll back this healthy system at the next
        // daemon start; say so loudly instead of failing a good update.
        eprintln!("nix-update-remote: cannot clear the committed update journal: {error}");
    }
    for warning in &warnings {
        events.warning(warning);
    }
    Ok(Outcome::Committed { warnings })
}

/// Units of the running system that failed since the update began. A unit
/// that failed while it was stopped and is gone now is no regression.
fn new_failures(host: &dyn Host, before: &BTreeSet<String>) -> Result<BTreeSet<String>, String> {
    let failed = host.failed_units()?;
    let new: BTreeSet<String> = failed.difference(before).cloned().collect();
    if new.is_empty() {
        return Ok(new);
    }
    Ok(host
        .unit_states(&new)?
        .into_iter()
        .filter(|state| state.loaded)
        .map(|state| state.id)
        .collect())
}

fn with_failed_units(host: &dyn Host, journal: &Journal, reason: String) -> String {
    match new_failures(host, &journal.failed_before) {
        Ok(new) => {
            if new.is_empty() {
                reason
            } else {
                format!("{reason}; failed units: {}", list(&new))
            }
        }
        Err(_) => reason,
    }
}

/// The health gate of the new system: returns warnings, or the regression.
fn health(
    host: &mut dyn Host,
    journal: &Journal,
    new: &Path,
    events: &mut dyn Events,
) -> Result<Vec<String>, String> {
    host.settle(events);
    let mut problems = Vec::new();
    if host.current_system().as_deref() != Some(new) {
        problems.push("the new system did not become the current system".to_owned());
    }
    if let Err(error) = host.run_health_units(&journal.failed_before, events) {
        problems.push(format!("health check failed: {error}"));
    }
    match new_failures(host, &journal.failed_before) {
        Ok(new) => {
            if !new.is_empty() {
                problems.push(format!("failed units: {}", list(&new)));
            }
        }
        Err(error) => problems.push(format!("cannot list failed units: {error}")),
    }
    match host.ssh_missing() {
        Ok(missing) if missing.is_empty() => {}
        Ok(missing) => problems.push(format!("sshd is not listening on port {missing:?}")),
        Err(error) => problems.push(format!("cannot check sshd: {error}")),
    }
    if problems.is_empty() {
        Ok(still_failed(host, journal))
    } else {
        Err(format!("the new system is unhealthy: {}", problems.join("; ")))
    }
}

/// Units that were already failed before the update and still are.
fn still_failed(host: &dyn Host, journal: &Journal) -> Vec<String> {
    let Ok(failed) = host.failed_units() else { return Vec::new() };
    let old: BTreeSet<String> = failed.intersection(&journal.failed_before).cloned().collect();
    host.unit_states(&old)
        .unwrap_or_default()
        .into_iter()
        .filter(|state| state.loaded)
        .map(|state| format!("{} was already failed before the update and still is", state.id))
        .collect()
}

/// Restores the system recorded in `journal` and verifies it.
pub fn rollback(
    host: &mut dyn Host,
    journal: &Journal,
    failure: String,
    events: &mut dyn Events,
) -> Outcome {
    let previous = &journal.previous_system;
    let mut problems = Vec::new();
    if let Err(error) = host.wait_switch_lock(events) {
        problems.push(error);
    }
    match host.profile_target() {
        Ok(target) if target == journal.previous_profile => {}
        _ => {
            if let Err(error) = host.restore_profile(journal.previous_profile.as_deref()) {
                problems.push(format!("restoring the system profile failed: {error}"));
            }
        }
    }
    // Status 4 only says that some unit failed; verification below decides
    // whether that is new.
    match host.switch(previous, Action::Test, None, events) {
        Ok(Some(_)) => {}
        Ok(None) => problems.push(format!("reactivating the previous system failed: {}", exit_text(Action::Test, None))),
        Err(error) => problems.push(format!("reactivating the previous system failed: {error}")),
    }
    if journal.phase == Phase::Committing {
        match host.switch(previous, Action::Boot, None, events) {
            Ok(Some(0)) => {}
            Ok(code) => problems.push(format!("restoring the bootloader failed: {}", exit_text(Action::Boot, code))),
            Err(error) => problems.push(format!("restoring the bootloader failed: {error}")),
        }
    }
    repair(host, journal, events);
    host.settle(events);
    problems.extend(verify_restored(host, journal));
    if let Err(error) = host.clear_journal() {
        problems.push(format!("cannot clear the update journal: {error}"));
    }
    if problems.is_empty() {
        Outcome::RolledBack {
            failure,
            detail: format!("previous system {} restored and verified", previous.display()),
        }
    } else {
        Outcome::RollbackFailed {
            failure,
            problems: problems.join("; "),
        }
    }
}

/// Units of the previous system that the failed switch left down: units that
/// failed since the update began, and services that ran before it.
fn repair(host: &mut dyn Host, journal: &Journal, events: &mut dyn Events) {
    let Ok(failed) = host.failed_units() else { return };
    let new_failures: BTreeSet<_> = failed.difference(&journal.failed_before).cloned().collect();
    let candidates: BTreeSet<_> = new_failures.union(&journal.running_before).cloned().collect();
    let Ok(states) = host.unit_states(&candidates) else { return };
    let mut reset = BTreeSet::new();
    let mut restart = BTreeSet::new();
    for state in states {
        if new_failures.contains(&state.id) {
            // Units of the failed generation only need their state cleared.
            reset.insert(state.id.clone());
            if state.loaded {
                restart.insert(state.id);
            }
        } else if state.loaded && !state.id.contains('@') && !is_up(&state.active) {
            restart.insert(state.id);
        }
    }
    if !reset.is_empty() {
        let _ = host.reset_failed(&reset);
    }
    if !restart.is_empty() {
        let _ = host.restart_units(&restart, events);
    }
}

fn is_up(active: &str) -> bool {
    matches!(active, "active" | "activating" | "reloading")
}

fn verify_restored(host: &mut dyn Host, journal: &Journal) -> Vec<String> {
    let mut problems = Vec::new();
    if host.current_system().as_deref() != Some(journal.previous_system.as_path()) {
        problems.push("the previous system is not the current system".into());
    }
    match host.profile_target() {
        Ok(target) if target == journal.previous_profile => {}
        _ => problems.push("the system profile does not name the previous generation".into()),
    }
    match new_failures(host, &journal.failed_before) {
        Ok(loaded) => {
            if !loaded.is_empty() {
                problems.push(format!("units still failed: {}", list(&loaded)));
            }
        }
        Err(error) => problems.push(format!("cannot list failed units: {error}")),
    }
    match host.unit_states(&journal.running_before) {
        Ok(states) => {
            let down: BTreeSet<String> = states
                .into_iter()
                .filter(|s| s.loaded && !s.id.contains('@') && !is_up(&s.active))
                .map(|s| s.id)
                .collect();
            if !down.is_empty() {
                problems.push(format!("previously running services are down: {}", list(&down)));
            }
        }
        Err(error) => problems.push(format!("cannot read unit states: {error}")),
    }
    match host.ssh_missing() {
        Ok(missing) if missing.is_empty() => {}
        Ok(missing) => problems.push(format!("sshd is not listening on port {missing:?}")),
        Err(error) => problems.push(format!("cannot check sshd: {error}")),
    }
    problems
}

/// Rolls back a switch that a previous daemon left unfinished.
pub fn recover(host: &mut dyn Host, events: &mut dyn Events) -> Option<(Journal, Outcome)> {
    let journal = match host.read_journal() {
        Ok(Some(journal)) => journal,
        Ok(None) => return None,
        Err(error) => {
            eprintln!("nix-update-remote: discarding unreadable update journal: {error}");
            let _ = host.clear_journal();
            return None;
        }
    };
    if host.boot_id().ok().as_deref() != Some(journal.boot_id.as_str()) {
        // The bootloader chose the system at boot; the profile and the
        // bootloader only name the new system once it passed its health gate.
        eprintln!("nix-update-remote: discarding the update journal of an earlier boot");
        let _ = host.clear_journal();
        return None;
    }
    if let Err(error) = host.wait_switch_lock(events) {
        eprintln!("nix-update-remote: {error}");
    }
    let current = host.current_system();
    if current.as_deref() != Some(journal.previous_system.as_path())
        && current.as_deref() != Some(journal.new_system.as_path())
    {
        eprintln!("nix-update-remote: another switch replaced the interrupted update; not rolling back");
        let _ = host.clear_journal();
        return None;
    }
    let failure = format!(
        "the update daemon was interrupted while switching to {}",
        journal.new_system.display()
    );
    let outcome = rollback(host, &journal, failure, events);
    Some((journal, outcome))
}

#[cfg(test)]
pub(crate) mod fake;
#[cfg(test)]
mod tests;
