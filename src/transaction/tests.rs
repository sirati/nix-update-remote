use super::fake::{FakeHost, Recorder, path, system};
use super::*;

fn old() -> (&'static str, fake::System) {
    ("old", system(&["sshd.service", "app.service", "pre-broken.service"]))
}

fn host_with(new: fake::System) -> FakeHost {
    let (name, mut old) = old();
    old.failing.insert("pre-broken.service".into());
    old.test_exit = 0;
    let mut host = FakeHost::running((name, old), ("new", new));
    // The previous system reports status 4 for its own broken unit.
    host.systems.get_mut(&path("old")).unwrap().test_exit = 4;
    host
}

fn new_system() -> fake::System {
    system(&["sshd.service", "app.service", "pre-broken.service", "extra.service"])
}

/// The host runs, boots and names the previous system everywhere.
fn assert_restored(host: &FakeHost) {
    assert_eq!(host.current, path("old"));
    assert_eq!(host.profile_system(), Some(path("old")));
    assert_eq!(host.profile, Some("system-1-link".into()));
    assert_eq!(host.boot_entry, Some(path("old")));
    assert_eq!(host.journal, None);
    assert_eq!(host.units["app.service"], (true, "active".into()));
}

fn run(host: &mut FakeHost) -> (Outcome, Recorder) {
    let mut events = Recorder::default();
    let outcome = update(host, &path("new"), &mut events).unwrap();
    (outcome, events)
}

#[test]
fn healthy_update_commits_profile_and_bootloader_only_after_the_health_gate() {
    let mut host = host_with(new_system());
    let (outcome, events) = run(&mut host);
    assert_eq!(outcome, Outcome::Committed { warnings: Vec::new() });
    assert_eq!(events.0, [format!("ACTIVATED {}", path("new").display())]);
    assert_eq!(host.current, path("new"));
    assert_eq!(host.profile_system(), Some(path("new")));
    assert_eq!(host.boot_entry, Some(path("new")));
    assert_eq!(host.journal, None);
    let new = path("new").display().to_string();
    assert_eq!(
        host.log,
        [
            "journal Activating".to_owned(),
            format!("test {new}"),
            "journal Committing".into(),
            format!("profile {new}"),
            format!("boot {new}"),
            "clear journal".into(),
        ]
    );
}

#[test]
fn activation_exit_4_rolls_back_and_reports_the_failed_units_first() {
    let mut new = new_system();
    new.failing.insert("extra.service".into());
    let mut host = host_with(new);
    let (outcome, events) = run(&mut host);
    let Outcome::RolledBack { failure, detail } = outcome else {
        panic!("not rolled back: {outcome:?}")
    };
    assert!(failure.contains("exited with status 4"), "{failure}");
    assert!(failure.contains("extra.service"), "{failure}");
    assert!(detail.contains("restored and verified"), "{detail}");
    assert_restored(&host);
    // The failed generation's unit no longer lingers as failed.
    assert!(!host.units.contains_key("extra.service"));
    // The client hears of the failure before the rollback starts.
    assert!(events.0[1].starts_with("FAILED "), "{:?}", events.0);
    let old = path("old").display().to_string();
    let rollback = host.log.iter().position(|e| *e == format!("test {old}")).unwrap();
    assert!(host.log[..rollback].iter().all(|e| !e.starts_with("profile") && !e.starts_with("boot")));
}

#[test]
fn unit_failing_shortly_after_the_switch_rolls_back() {
    let mut new = new_system();
    new.failing_later.insert("app.service".into());
    let mut host = host_with(new);
    let (outcome, _) = run(&mut host);
    assert!(
        matches!(&outcome, Outcome::RolledBack { failure, .. } if failure.contains("failed units: app.service")),
        "{outcome:?}"
    );
    assert_restored(&host);
}

#[test]
fn failed_health_unit_rolls_back() {
    let mut new = new_system();
    new.health_fails = true;
    let mut host = host_with(new);
    let (outcome, _) = run(&mut host);
    assert!(
        matches!(&outcome, Outcome::RolledBack { failure, .. } if failure.contains("health check failed")),
        "{outcome:?}"
    );
    assert_restored(&host);
}

#[test]
fn sshd_not_listening_rolls_back() {
    let mut new = new_system();
    new.sshd = false;
    let mut host = host_with(new);
    let (outcome, _) = run(&mut host);
    assert!(
        matches!(&outcome, Outcome::RolledBack { failure, .. } if failure.contains("sshd")),
        "{outcome:?}"
    );
    assert_restored(&host);
}

#[test]
fn failures_that_predate_the_update_do_not_block_it() {
    let mut host = host_with(new_system());
    host.systems.get_mut(&path("new")).unwrap().failing_later.insert("pre-broken.service".into());
    let (outcome, _) = run(&mut host);
    assert!(matches!(outcome, Outcome::Committed { .. }), "{outcome:?}");
}

#[test]
fn bootloader_failure_restores_the_profile_and_the_boot_entry() {
    let mut new = new_system();
    new.boot_exit = 1;
    let mut host = host_with(new);
    let (outcome, events) = run(&mut host);
    assert!(
        matches!(&outcome, Outcome::RolledBack { failure, .. } if failure.contains("installing the bootloader failed")),
        "{outcome:?}"
    );
    assert!(events.0.iter().any(|e| e.starts_with("FAILED installing the bootloader")));
    assert_restored(&host);
}

#[test]
fn unverifiable_rollback_is_reported_as_failed() {
    let mut new = new_system();
    new.failing.insert("extra.service".into());
    let mut host = host_with(new);
    // The previous system cannot bring sshd back either.
    host.systems.get_mut(&path("old")).unwrap().sshd = false;
    let (outcome, _) = run(&mut host);
    assert!(
        matches!(&outcome, Outcome::RollbackFailed { problems, .. } if problems.contains("sshd")),
        "{outcome:?}"
    );
    assert_eq!(host.current, path("old"));
}

#[test]
fn rollback_restarts_services_the_failed_switch_left_down() {
    let mut new = new_system();
    new.failing.insert("app.service".into());
    let mut host = host_with(new);
    // app is unchanged between the generations, so switching back alone
    // would leave it failed.
    host.systems.get_mut(&path("old")).unwrap().untouched.insert("app.service".into());
    let (outcome, _) = run(&mut host);
    assert!(matches!(outcome, Outcome::RolledBack { .. }), "{outcome:?}");
    assert!(host.log.iter().any(|e| e == "restart app.service"), "{:?}", host.log);
    assert_restored(&host);
}

#[test]
fn unrecordable_journal_rejects_before_any_change() {
    let mut host = host_with(new_system());
    host.journal_write_fails = true;
    let mut events = Recorder::default();
    assert!(update(&mut host, &path("new"), &mut events).is_err());
    assert!(events.0.is_empty());
    assert_restored(&host);
    assert!(host.log.is_empty(), "{:?}", host.log);
}

#[test]
fn interrupted_switch_is_rolled_back_when_the_daemon_starts() {
    let mut host = host_with(new_system());
    let journal = Journal {
        boot_id: "boot-a".into(),
        previous_system: path("old"),
        previous_profile: Some("system-1-link".into()),
        new_system: path("new"),
        phase: Phase::Committing,
        failed_before: ["pre-broken.service".to_owned()].into(),
        running_before: ["app.service".to_owned(), "sshd.service".to_owned()].into(),
    };
    // The daemon died after it set the profile and while the bootloader
    // was being installed.
    host.journal = Some(journal);
    let mut events = Recorder::default();
    host.switch(&path("new"), Action::Test, None, &mut events).unwrap();
    host.set_profile(&path("new")).unwrap();
    host.boot_entry = Some(path("new"));
    let (_, outcome) = recover(&mut host, &mut events).unwrap();
    assert!(
        matches!(&outcome, Outcome::RolledBack { failure, .. } if failure.contains("interrupted")),
        "{outcome:?}"
    );
    assert_restored(&host);
}

#[test]
fn recovery_ignores_journals_of_other_boots_and_foreign_switches() {
    let mut host = host_with(new_system());
    let journal = Journal {
        boot_id: "boot-before-reboot".into(),
        previous_system: path("old"),
        previous_profile: Some("system-1-link".into()),
        new_system: path("new"),
        phase: Phase::Activating,
        failed_before: BTreeSet::new(),
        running_before: BTreeSet::new(),
    };
    host.journal = Some(journal.clone());
    let mut events = Recorder::default();
    assert!(recover(&mut host, &mut events).is_none());
    assert_eq!(host.journal, None);
    assert!(!host.log.iter().any(|e| e.starts_with("test")));

    // Someone else switched to a third system after the daemon died.
    host.systems.insert(path("third"), new_system());
    host.switch(&path("third"), Action::Test, None, &mut events).unwrap();
    host.journal = Some(Journal { boot_id: "boot-a".into(), ..journal });
    host.log.clear();
    assert!(recover(&mut host, &mut events).is_none());
    assert_eq!(host.current, path("third"));
    assert_eq!(host.log, ["clear journal"]);
}

#[test]
fn a_unit_failing_while_the_switch_waits_ends_it_and_rolls_back() {
    // Without the watch the switch would wait forever on its secret waiter,
    // and the secret step would have to run for the failure to show.
    let mut new = new_system();
    new.blocks = true;
    new.failing.insert("extra.service".into());
    let mut host = host_with(new);
    let (outcome, events) = run(&mut host);
    assert!(
        matches!(&outcome, Outcome::RolledBack { failure, .. } if failure.contains("extra.service")),
        "{outcome:?}"
    );
    assert!(events.0[1].starts_with("FAILED "), "{:?}", events.0);
    assert_restored(&host);
}

#[test]
fn a_removed_unit_that_failed_while_stopping_does_not_block_the_update() {
    let mut host = host_with(new_system());
    let old = host.systems.get_mut(&path("old")).unwrap();
    old.units.insert("legacy.service".into());
    old.fails_on_stop.insert("legacy.service".into());
    let old = old.clone();
    host.activate_for_test(&path("old"), old);
    let (outcome, _) = run(&mut host);
    assert!(matches!(outcome, Outcome::Committed { .. }), "{outcome:?}");
}

#[test]
fn a_unit_already_broken_before_the_update_commits_it_with_a_warning() {
    // switch-to-configuration exits 4 because the old breakage persists;
    // nothing regressed, so the update stands and the operator is told.
    let mut new = new_system();
    new.failing.insert("pre-broken.service".into());
    let mut host = host_with(new);
    let (outcome, events) = run(&mut host);
    let Outcome::Committed { warnings } = outcome else { panic!("rolled back: {outcome:?}") };
    assert_eq!(
        warnings,
        [
            "switch-to-configuration test exited with status 4".to_owned(),
            "pre-broken.service was already failed before the update and still is".into(),
        ]
    );
    assert!(events.0.iter().any(|e| e == "WARNING pre-broken.service was already failed before the update and still is"));
    assert!(!events.0.iter().any(|e| e.starts_with("FAILED")));
    assert_eq!(host.current, path("new"));
    assert_eq!(host.profile_system(), Some(path("new")));
    assert_eq!(host.boot_entry, Some(path("new")));
}

#[test]
fn a_switch_that_never_activated_the_new_system_rolls_back() {
    // A non-zero exit before activation leaves the old system running; the
    // update must not commit a system that never ran.
    let mut host = host_with(new_system());
    host.systems.get_mut(&path("new")).unwrap().test_exit = 100;
    host.never_activates.insert(path("new"));
    let (outcome, _) = run(&mut host);
    assert!(
        matches!(&outcome, Outcome::RolledBack { failure, .. } if failure.contains("did not become the current system")),
        "{outcome:?}"
    );
    assert_restored(&host);
}

#[test]
fn each_stage_is_announced_as_it_starts() {
    use Stage::*;
    let (outcome, events) = run(&mut host_with(new_system()));
    assert!(matches!(outcome, Outcome::Committed { .. }), "{outcome:?}");
    assert_eq!(events.1, [Activating, HealthGate, Committing]);
    let mut failing = new_system();
    failing.health_fails = true;
    let (_, events) = run(&mut host_with(failing));
    assert_eq!(events.1, [Activating, HealthGate, RollingBack]);
    let mut unbootable = new_system();
    unbootable.boot_exit = 1;
    let (_, events) = run(&mut host_with(unbootable));
    assert_eq!(events.1, [Activating, HealthGate, Committing, RollingBack]);
}
