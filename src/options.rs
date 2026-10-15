//! Command-line options that take effect once.
use std::collections::BTreeSet;

/// Refuses a second occurrence of every option but the `repeatable` ones. A
/// later copy would otherwise replace what an earlier one set, such as a
/// wrapper's fixed `--installable` or a plan's `--target`.
#[derive(Default)]
pub struct Once(BTreeSet<String>);

impl Once {
    pub fn take(&mut self, option: &str, repeatable: &[&str]) -> Result<(), String> {
        if repeatable.contains(&option) || self.0.insert(option.to_owned()) {
            Ok(())
        } else {
            Err(format!("option {option} is given more than once"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_repeatable_options_may_come_twice() {
        let mut once = Once::default();
        assert!(once.take("--target", &["--ssh-arg"]).is_ok());
        assert!(once.take("--ssh-arg", &["--ssh-arg"]).is_ok());
        assert!(once.take("--ssh-arg", &["--ssh-arg"]).is_ok());
        assert!(once.take("--target", &["--ssh-arg"]).unwrap_err().contains("--target"));
    }
}
