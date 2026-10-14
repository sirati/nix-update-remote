//! A simulated host for transaction tests: systems define units, some of
//! which fail; switching, the profile, the bootloader entry and the journal
//! behave like their NixOS counterparts.
use super::{Action, Events, Host, Journal, UnitState};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Clone, Default)]
pub struct System {
    pub units: BTreeSet<String>,
    /// Units that fail when this system starts them.
    pub failing: BTreeSet<String>,
    /// Units that fail only after the switch returned.
    pub failing_later: BTreeSet<String>,
    /// Units that fail when they are stopped.
    pub fails_on_stop: BTreeSet<String>,
    /// Its switch blocks on a unit that waits, like a secret waiter.
    pub blocks: bool,
    /// Unchanged units that switching to this system leaves as they are.
    pub untouched: BTreeSet<String>,
    pub test_exit: i32,
    pub boot_exit: i32,
    pub health_fails: bool,
    pub sshd: bool,
}

#[derive(Default)]
pub struct FakeHost {
    pub systems: BTreeMap<PathBuf, System>,
    pub current: PathBuf,
    pub profile: Option<PathBuf>,
    pub links: BTreeMap<PathBuf, PathBuf>,
    pub boot_entry: Option<PathBuf>,
    /// Unit id -> (loaded, active state).
    pub units: BTreeMap<String, (bool, String)>,
    pub journal: Option<Journal>,
    pub boot_id: String,
    pub journal_write_fails: bool,
    /// Systems whose `test` exits before it activates anything.
    pub never_activates: BTreeSet<PathBuf>,
    pub log: Vec<String>,
}

pub fn path(name: &str) -> PathBuf {
    PathBuf::from(format!("/nix/store/{name}"))
}

pub fn system(units: &[&str]) -> System {
    System {
        units: units.iter().map(|u| u.to_string()).collect(),
        sshd: true,
        ..System::default()
    }
}

impl FakeHost {
    /// A host running `old`, with profile generation 1 and its boot entry.
    pub fn running(old: (&str, System), new: (&str, System)) -> Self {
        let mut host = FakeHost {
            boot_id: "boot-a".into(),
            ..FakeHost::default()
        };
        host.systems.insert(path(old.0), old.1);
        host.systems.insert(path(new.0), new.1);
        host.links.insert("system-1-link".into(), path(old.0));
        host.profile = Some("system-1-link".into());
        host.boot_entry = Some(path(old.0));
        host.activate(&path(old.0));
        host.log.clear();
        host
    }

    fn activate(&mut self, system: &Path) {
        let leaving = self.systems.get(&self.current).cloned().unwrap_or_default();
        self.current = system.to_owned();
        let defined = self.systems[system].clone();
        for unit in leaving.fails_on_stop.difference(&defined.units) {
            self.units.insert(unit.clone(), (false, "failed".into()));
        }
        self.units.retain(|id, (loaded, active)| {
            *loaded = defined.units.contains(id);
            *loaded || active == "failed"
        });
        for unit in &defined.units {
            if defined.untouched.contains(unit) && self.units.contains_key(unit) {
                continue;
            }
            let failed = defined.failing.contains(unit);
            self.units.insert(
                unit.clone(),
                (true, if failed { "failed" } else { "active" }.into()),
            );
        }
    }

    /// Redefines and reactivates a system.
    pub fn activate_for_test(&mut self, path: &Path, system: System) {
        self.systems.insert(path.to_owned(), system);
        self.activate(path);
        self.log.clear();
    }

    pub fn profile_system(&self) -> Option<PathBuf> {
        self.profile.as_ref().map(|link| self.links[link].clone())
    }

    fn current_def(&self) -> &System {
        &self.systems[&self.current]
    }
}

impl Host for FakeHost {
    fn boot_id(&self) -> Result<String, String> {
        Ok(self.boot_id.clone())
    }
    fn current_system(&self) -> Option<PathBuf> {
        Some(self.current.clone())
    }
    fn profile_target(&self) -> Result<Option<PathBuf>, String> {
        Ok(self.profile.clone())
    }
    fn set_profile(&mut self, system: &Path) -> Result<(), String> {
        let link = PathBuf::from(format!("system-{}-link", self.links.len() + 1));
        self.links.insert(link.clone(), system.to_owned());
        self.profile = Some(link);
        self.log.push(format!("profile {}", system.display()));
        Ok(())
    }
    fn restore_profile(&mut self, target: Option<&Path>) -> Result<(), String> {
        self.profile = target.map(Path::to_owned);
        self.log.push("restore profile".into());
        Ok(())
    }
    fn switch(
        &mut self,
        system: &Path,
        action: Action,
        watch: Option<&BTreeSet<String>>,
        events: &mut dyn Events,
    ) -> Result<Option<i32>, String> {
        self.log.push(format!("{} {}", action.name(), system.display()));
        let definition = self.systems[system].clone();
        match action {
            Action::Test => {
                if self.never_activates.contains(system) {
                    return Ok(Some(definition.test_exit));
                }
                self.activate(system);
                if watch.is_some() {
                    events.activated(system);
                }
                if definition.blocks && !definition.failing.is_empty() {
                    if watch.is_some() {
                        return Err(format!("units failed during activation: {}", definition.failing.iter().cloned().collect::<Vec<_>>().join(", ")));
                    }
                    panic!("the switch blocks forever on a waiter");
                }
                Ok(Some(if definition.failing.is_empty() { definition.test_exit } else { 4 }))
            }
            Action::Boot => {
                // A failing installer may already have written part of it.
                self.boot_entry = Some(system.to_owned());
                Ok(Some(definition.boot_exit))
            }
        }
    }
    fn wait_switch_lock(&mut self, _: &mut dyn Events) -> Result<(), String> {
        Ok(())
    }
    fn failed_units(&self) -> Result<BTreeSet<String>, String> {
        Ok(self
            .units
            .iter()
            .filter(|(_, (_, active))| active == "failed")
            .map(|(id, _)| id.clone())
            .collect())
    }
    fn running_services(&self) -> Result<BTreeSet<String>, String> {
        Ok(self
            .units
            .iter()
            .filter(|(_, (_, active))| active == "active")
            .map(|(id, _)| id.clone())
            .collect())
    }
    fn unit_states(&self, units: &BTreeSet<String>) -> Result<Vec<UnitState>, String> {
        Ok(units
            .iter()
            .map(|id| {
                let (loaded, active) = self
                    .units
                    .get(id)
                    .cloned()
                    .unwrap_or((false, "inactive".into()));
                UnitState { id: id.clone(), loaded, active }
            })
            .collect())
    }
    fn reset_failed(&mut self, units: &BTreeSet<String>) -> Result<(), String> {
        for unit in units {
            if self.units.get(unit).is_some_and(|(loaded, _)| !loaded) {
                self.units.remove(unit);
            }
        }
        Ok(())
    }
    fn restart_units(&mut self, units: &BTreeSet<String>, _: &mut dyn Events) -> Result<(), String> {
        self.log.push(format!("restart {}", units.iter().cloned().collect::<Vec<_>>().join(",")));
        let failing = self.current_def().failing.clone();
        for unit in units {
            if let Some((true, active)) = self.units.get_mut(unit) {
                *active = if failing.contains(unit) { "failed" } else { "active" }.into();
            }
        }
        Ok(())
    }
    fn run_health_units(&mut self, _: &BTreeSet<String>, _: &mut dyn Events) -> Result<(), String> {
        if self.current_def().health_fails {
            Err("lifecycle-health-app.service failed".into())
        } else {
            Ok(())
        }
    }
    fn settle(&mut self, _: &mut dyn Events) {
        for unit in self.current_def().failing_later.clone() {
            self.units.insert(unit, (true, "failed".into()));
        }
    }
    fn ssh_missing(&self) -> Result<Vec<u16>, String> {
        Ok(if self.current_def().sshd { vec![] } else { vec![22] })
    }
    fn write_journal(&mut self, journal: &Journal) -> Result<(), String> {
        if self.journal_write_fails {
            return Err("read-only file system".into());
        }
        self.log.push(format!("journal {:?}", journal.phase));
        self.journal = Some(journal.clone());
        Ok(())
    }
    fn read_journal(&self) -> Result<Option<Journal>, String> {
        Ok(self.journal.clone())
    }
    fn clear_journal(&mut self) -> Result<(), String> {
        self.log.push("clear journal".into());
        self.journal = None;
        Ok(())
    }
}

/// Records what a client would have been told.
#[derive(Default)]
pub struct Recorder(pub Vec<String>);

impl Events for Recorder {
    fn activated(&mut self, system: &Path) {
        self.0.push(format!("ACTIVATED {}", system.display()));
    }
    fn failed(&mut self, reason: &str) {
        self.0.push(format!("FAILED {reason}"));
    }
    fn waiting(&mut self, _: &str) {}
    fn warning(&mut self, text: &str) {
        self.0.push(format!("WARNING {text}"));
    }
}
