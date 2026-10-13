//! The operator's approval of SSH logins, obtained before a connection.
//!
//! An operator authentication provider that asks a person for each login
//! signature would keep the connection waiting while the server counts its
//! LoginGraceTime. `--login-approval-command` names a provider command that
//! obtains the approval instead, before any connection that needs a
//! signature. It exits zero once the following logins are approved, and
//! returns at once while an earlier approval still covers them. The updater
//! runs it before every connection and stops its own clocks meanwhile.
use crate::cancellation::ManagedCommand;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LoginApproval {
    command: Option<String>,
    args: Vec<String>,
}

impl LoginApproval {
    /// Takes `--login-approval-command` and `--login-approval-arg`; returns
    /// whether `option` was one of them.
    pub fn parse<'a>(
        &mut self,
        option: &str,
        values: &mut impl Iterator<Item = &'a String>,
    ) -> Result<bool, String> {
        match option {
            "--login-approval-command" => {
                self.command = Some(
                    values
                        .next()
                        .ok_or("missing login approval command")?
                        .clone(),
                )
            }
            "--login-approval-arg" => self.args.push(
                values
                    .next()
                    .ok_or("missing login approval argument")?
                    .clone(),
            ),
            _ => return Ok(false),
        }
        Ok(true)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.command.is_none() && !self.args.is_empty() {
            return Err("login approval arguments require --login-approval-command".into());
        }
        Ok(())
    }

    /// The options again, for a command that passes them on.
    pub fn arguments(&self) -> Vec<String> {
        let mut arguments = Vec::new();
        if let Some(command) = &self.command {
            arguments.extend(["--login-approval-command".into(), command.clone()]);
        }
        for arg in &self.args {
            arguments.extend(["--login-approval-arg".into(), arg.clone()]);
        }
        arguments
    }

    /// Obtains the approval before a connection and returns how long that
    /// took, which no deadline of the caller may count.
    pub fn before_connecting(&self) -> Result<Duration, String> {
        let Some(command) = &self.command else {
            return Ok(Duration::ZERO);
        };
        let started = Instant::now();
        let status = Command::new(command)
            .args(&self.args)
            .stdin(Stdio::null())
            .managed_status()
            .map_err(|error| format!("login approval: {error}"))?;
        if !status.success() {
            return Err("the operator did not approve the SSH login".into());
        }
        Ok(started.elapsed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(args: &[&str]) -> Result<LoginApproval, String> {
        let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
        let mut approval = LoginApproval::default();
        let mut iter = args.iter();
        while let Some(option) = iter.next() {
            if !approval.parse(option, &mut iter)? {
                return Err(format!("unknown {option}"));
            }
        }
        approval.validate().map(|()| approval)
    }

    #[test]
    fn options_round_trip_and_arguments_need_a_command() {
        let approval = parsed(&[
            "--login-approval-command",
            "nix-secrets",
            "--login-approval-arg",
            "approve-ssh-login",
        ])
        .unwrap();
        assert_eq!(
            approval.arguments(),
            [
                "--login-approval-command",
                "nix-secrets",
                "--login-approval-arg",
                "approve-ssh-login"
            ]
        );
        assert!(parsed(&["--login-approval-arg", "x"]).is_err());
        assert!(parsed(&["--login-approval-command"]).is_err());
        assert_eq!(
            LoginApproval::default().before_connecting().unwrap(),
            Duration::ZERO
        );
    }

    #[test]
    fn a_refused_approval_stops_and_the_wait_is_measured() {
        let refused = parsed(&["--login-approval-command", "false"]).unwrap();
        assert!(refused.before_connecting().is_err());
        let slow = parsed(&[
            "--login-approval-command",
            "sleep",
            "--login-approval-arg",
            "0.3",
        ])
        .unwrap();
        assert!(slow.before_connecting().unwrap() >= Duration::from_millis(300));
    }
}
