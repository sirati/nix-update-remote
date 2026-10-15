//! Whether a `switch-to-configuration` holds its lock.
//!
//! The lock is never taken here: `switch-to-configuration` locks it
//! non-blocking and dies when it cannot ("Could not acquire lock"), so even
//! a short probe could kill an operator's `nixos-rebuild`. `/proc/locks`
//! names the holder's device and inode instead.
use crate::transaction::Events;
use std::path::Path;
use std::time::{Duration, Instant};

/// Device and inode of every lock in `/proc/locks` text.
fn locked_inodes(text: &str) -> impl Iterator<Item = (u32, u32, u64)> + '_ {
    text.lines().filter_map(|line| {
        // `1: FLOCK  ADVISORY  WRITE 2410 00:1a:12345 0 EOF`, and a blocked
        // waiter's `1: -> FLOCK  ADVISORY  WRITE …`.
        let id = line.split_whitespace().filter(|f| *f != "->").nth(5)?;
        let mut id = id.split(':');
        let major = u32::from_str_radix(id.next()?, 16).ok()?;
        let minor = u32::from_str_radix(id.next()?, 16).ok()?;
        let inode = id.next()?.parse().ok()?;
        Some((major, minor, inode))
    })
}

/// Whether `locks` lists a lock on device `major:minor`, inode `inode`.
fn held_in(locks: &str, major: u32, minor: u32, inode: u64) -> bool {
    locked_inodes(locks).any(|id| id == (major, minor, inode))
}

/// Whether some process holds a lock on `lock`. A missing lock file is not
/// held.
pub fn held(lock: &Path) -> Result<bool, String> {
    let stat = match rustix::fs::stat(lock) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(error) => return Err(format!("{}: {error}", lock.display())),
    };
    let locks = std::fs::read_to_string("/proc/locks").map_err(|e| format!("/proc/locks: {e}"))?;
    Ok(held_in(&locks, rustix::fs::major(stat.st_dev), rustix::fs::minor(stat.st_dev), stat.st_ino))
}

/// Waits until nobody holds `lock`, for at most `limit`.
pub fn wait_released(
    lock: &Path,
    limit: Duration,
    poll: Duration,
    keepalive: Duration,
    events: &mut dyn Events,
) -> Result<(), String> {
    let start = Instant::now();
    let mut last = start;
    while held(lock)? {
        if start.elapsed() >= limit {
            return Err("another switch-to-configuration is still running".into());
        }
        if last.elapsed() >= keepalive {
            events.waiting("waiting for another switch-to-configuration");
            last = Instant::now();
        }
        std::thread::sleep(poll);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::{FlockOperation, flock};

    struct Quiet;
    impl Events for Quiet {
        fn activated(&mut self, _: &Path) {}
        fn failed(&mut self, _: &str) {}
        fn waiting(&mut self, _: &str) {}
        fn warning(&mut self, _: &str) {}
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("nur-switch-lock-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("switch-to-configuration.lock")
    }

    #[test]
    fn proc_locks_name_the_held_inode() {
        let locks = "1: FLOCK  ADVISORY  WRITE 2410 00:1a:12345 0 EOF\n\
                     1: -> FLOCK  ADVISORY  WRITE 2411 00:1a:777 0 EOF\n\
                     2: POSIX  ADVISORY  READ 99 fd:01:42 0 EOF\n";
        assert!(held_in(locks, 0, 0x1a, 12345));
        assert!(held_in(locks, 0xfd, 1, 42));
        assert!(held_in(locks, 0, 0x1a, 777));
        assert!(!held_in(locks, 0, 0x1a, 12346));
        assert!(!held_in(locks, 0, 0x1b, 12345));
        assert!(!held_in("", 0, 0x1a, 12345));
    }

    #[test]
    fn waits_for_the_holder_and_gives_up_after_the_limit() {
        let lock = scratch("wait");
        let poll = Duration::from_millis(10);
        assert_eq!(wait_released(&lock, Duration::ZERO, poll, poll, &mut Quiet), Ok(()), "missing lock");
        let file = std::fs::File::create(&lock).unwrap();
        assert!(!held(&lock).unwrap());
        flock(&file, FlockOperation::NonBlockingLockExclusive).unwrap();
        assert!(held(&lock).unwrap());
        assert!(wait_released(&lock, Duration::from_millis(50), poll, poll, &mut Quiet).is_err());
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(file);
        });
        assert_eq!(wait_released(&lock, Duration::from_secs(10), poll, poll, &mut Quiet), Ok(()));
        release.join().unwrap();
        std::fs::remove_dir_all(lock.parent().unwrap()).unwrap();
    }

    const RACE: &str = "NIX_UPDATE_TEST_SWITCH_LOCK";

    /// An operator's switch-to-configuration takes the lock non-blocking
    /// while the updater waits: it must never find the lock taken. It runs
    /// in its own process: any other test's fork would otherwise hold a copy
    /// of its locked descriptor until the child execs.
    #[test]
    fn waiting_never_takes_the_lock_from_a_concurrent_switch() {
        let lock = scratch("race");
        std::fs::File::create(&lock).unwrap();
        let mut switch = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "switch_lock::tests::concurrent_switch", "--ignored", "--quiet"])
            .env(RACE, &lock)
            .spawn()
            .unwrap();
        let status = loop {
            if let Some(status) = switch.try_wait().unwrap() {
                break status;
            }
            // Mostly free; returns at once either way.
            let _ = wait_released(&lock, Duration::ZERO, Duration::ZERO, Duration::MAX, &mut Quiet);
        };
        std::fs::remove_dir_all(lock.parent().unwrap()).unwrap();
        assert!(status.success(), "the wait took the switch lock from a concurrent switch");
    }

    /// The operator's side of the race above; does nothing on its own.
    #[test]
    #[ignore = "run by waiting_never_takes_the_lock_from_a_concurrent_switch"]
    fn concurrent_switch() {
        let Some(lock) = std::env::var_os(RACE) else { return };
        let start = Instant::now();
        let mut refused = 0;
        while start.elapsed() < Duration::from_secs(2) {
            let file = std::fs::File::open(&lock).unwrap();
            match flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => drop(file),
                Err(_) => refused += 1,
            }
        }
        assert_eq!(refused, 0, "switch-to-configuration found the lock taken {refused} times");
    }
}
