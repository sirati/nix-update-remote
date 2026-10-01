//! Cooperative operator cancellation. Signal callbacks never touch files.
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid};
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    iterator::Signals,
};
use std::{
    collections::BTreeSet,
    io::{self, Read},
    ops::{Deref, DerefMut},
    os::unix::{fs::MetadataExt, process::CommandExt},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

struct Context {
    cancelled: AtomicBool,
    groups: Mutex<BTreeSet<i32>>,
    deadline: Mutex<Option<Instant>>,
}
static CONTEXT: OnceLock<Arc<Context>> = OnceLock::new();
fn interrupted() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "operator update cancelled")
}
fn signal(group: i32, value: Signal) {
    if let Some(pid) = Pid::from_raw(group) {
        let _ = kill_process_group(pid, value);
    }
}
fn live_members(group: i32) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        // An unavailable process inventory cannot prove terminal state.
        return vec![0];
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let pid = entry.file_name().to_string_lossy().parse::<u32>().ok()?;
            let stat = std::fs::read_to_string(entry.path().join("stat")).ok()?;
            let (_, tail) = stat.rsplit_once(") ")?;
            let mut fields = tail.split_whitespace();
            let state = fields.next()?;
            let _parent = fields.next()?;
            if fields.next()?.parse::<i32>().ok()? == group && state != "Z" && state != "X" {
                Some(pid)
            } else {
                None
            }
        })
        .collect()
}
fn cooperative_member(group: i32) -> bool {
    let Ok(own) = std::fs::metadata("/proc/self/exe") else {
        return true;
    };
    live_members(group).iter().any(|pid| {
        std::fs::metadata(format!("/proc/{pid}/exe"))
            .is_ok_and(|exe| exe.dev() == own.dev() && exe.ino() == own.ino())
    })
}
pub fn install() -> io::Result<()> {
    let mut signals = Signals::new([SIGINT, SIGTERM])?;
    let context = Arc::new(Context {
        cancelled: AtomicBool::new(false),
        groups: Mutex::new(BTreeSet::new()),
        deadline: Mutex::new(None),
    });
    CONTEXT
        .set(context.clone())
        .map_err(|_| io::Error::other("cancellation already installed"))?;
    thread::Builder::new()
        .name("operator-cancellation".into())
        .spawn(move || {
            if signals.forever().next().is_some() {
                *context.deadline.lock().unwrap() = Some(Instant::now() + Duration::from_secs(5));
                context.cancelled.store(true, Ordering::SeqCst);
                for &group in context.groups.lock().unwrap().iter() {
                    signal(group, Signal::TERM);
                }
                // Cooperative children get time to release their own guards first.
                thread::sleep(Duration::from_secs(5));
                for &group in context.groups.lock().unwrap().iter() {
                    if !cooperative_member(group) {
                        signal(group, Signal::KILL);
                    }
                }
                // Nested copies of this binary must unwind after their providers
                // have been forced down, before an outer wrapper can be killed.
                thread::sleep(Duration::from_secs(3));
                for &group in context.groups.lock().unwrap().iter() {
                    signal(group, Signal::KILL);
                }
            }
        })?;
    Ok(())
}
fn cancelled() -> bool {
    CONTEXT
        .get()
        .is_some_and(|c| c.cancelled.load(Ordering::SeqCst))
}

pub struct ManagedChild {
    child: Child,
    group: i32,
    reaped: bool,
}
impl Deref for ManagedChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.child
    }
}
impl DerefMut for ManagedChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}
impl ManagedChild {
    fn unregister(&self) {
        if let Some(context) = CONTEXT.get() {
            context.groups.lock().unwrap().remove(&self.group);
        }
    }
    fn ready(&self, nohang: bool) -> io::Result<bool> {
        let mut options = WaitIdOptions::EXITED | WaitIdOptions::NOWAIT;
        if nohang {
            options |= WaitIdOptions::NOHANG;
        }
        loop {
            match waitid(WaitId::Pid(Pid::from_raw(self.group).unwrap()), options) {
                Ok(value) => return Ok(value.is_some()),
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }
    fn collect(&mut self) -> io::Result<ExitStatus> {
        // Keep the group leader unreaped until all signalling is finished;
        // its PID cannot be reused for an unrelated process group meanwhile.
        let was_cancelled = cancelled();
        if was_cancelled {
            let deadline = CONTEXT
                .get()
                .and_then(|c| *c.deadline.lock().unwrap())
                .unwrap();
            while !live_members(self.group).is_empty() {
                let grace = if cooperative_member(self.group) {
                    deadline + Duration::from_secs(3)
                } else {
                    deadline
                };
                if Instant::now() >= grace {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
        signal(self.group, Signal::KILL);
        // SIGKILL delivery is asynchronous. Keep the leader PID reserved and
        // the transaction guards alive until every remaining member is terminal.
        // A task stuck in uninterruptible I/O therefore retains its artifacts;
        // deleting them while that task still owns descriptors is unsafe.
        while !live_members(self.group).is_empty() {
            thread::sleep(Duration::from_millis(20));
        }
        self.unregister();
        let status = self.child.wait();
        self.reaped = status.is_ok();
        if was_cancelled {
            Err(interrupted())
        } else {
            status
        }
    }
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        self.ready(false)?;
        self.collect()
    }
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.ready(true)? {
            self.collect().map(Some)
        } else {
            Ok(None)
        }
    }
    pub fn kill(&mut self) -> io::Result<()> {
        if !self.reaped {
            signal(self.group, Signal::KILL);
        }
        Ok(())
    }
}
impl Drop for ManagedChild {
    fn drop(&mut self) {
        if !self.reaped {
            signal(self.group, Signal::TERM);
            let deadline = Instant::now() + Duration::from_secs(5);
            while !self.ready(true).unwrap_or(true) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
            if !self.ready(true).unwrap_or(false) {
                signal(self.group, Signal::KILL);
            }
            let _ = self.wait();
        }
        self.unregister();
    }
}

pub trait ManagedCommand {
    fn managed_spawn(&mut self) -> io::Result<ManagedChild>;
    fn managed_status(&mut self) -> io::Result<ExitStatus>;
    fn managed_output(&mut self) -> io::Result<Output>;
    fn managed_output_inherit_stderr(&mut self) -> io::Result<Output>;
}
impl ManagedCommand for Command {
    fn managed_spawn(&mut self) -> io::Result<ManagedChild> {
        let context = CONTEXT.get();
        let mut groups = context.map(|c| c.groups.lock().unwrap());
        if cancelled() {
            return Err(interrupted());
        }
        self.process_group(0);
        let child = self.spawn()?;
        let group = i32::try_from(child.id()).map_err(io::Error::other)?;
        if let Some(groups) = groups.as_mut() {
            groups.insert(group);
        }
        Ok(ManagedChild {
            child,
            group,
            reaped: false,
        })
    }
    fn managed_status(&mut self) -> io::Result<ExitStatus> {
        self.managed_spawn()?.wait()
    }
    fn managed_output_inherit_stderr(&mut self) -> io::Result<Output> {
        let mut child = self
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .managed_spawn()?;
        let mut stream = child.stdout.take().unwrap();
        let reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes)?;
            Ok::<_, io::Error>(bytes)
        });
        let status = child.wait();
        let stdout = reader
            .join()
            .map_err(|_| io::Error::other("stdout reader failed"))??;
        Ok(Output {
            status: status?,
            stdout,
            stderr: Vec::new(),
        })
    }
    fn managed_output(&mut self) -> io::Result<Output> {
        let mut child = self
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .managed_spawn()?;
        let out = child.stdout.take().unwrap();
        let err = child.stderr.take().unwrap();
        fn read(mut stream: impl Read + Send + 'static) -> thread::JoinHandle<io::Result<Vec<u8>>> {
            thread::spawn(move || {
                let mut bytes = Vec::new();
                stream.read_to_end(&mut bytes)?;
                Ok(bytes)
            })
        }
        let stdout = read(out);
        let stderr = read(err);
        let status = child.wait();
        // Join both pumps before propagating either reader error.
        let stdout = stdout
            .join()
            .map_err(|_| io::Error::other("stdout reader failed"));
        let stderr = stderr
            .join()
            .map_err(|_| io::Error::other("stderr reader failed"));
        Ok(Output {
            status: status?,
            stdout: stdout??,
            stderr: stderr??,
        })
    }
}
