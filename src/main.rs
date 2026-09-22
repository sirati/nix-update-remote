#![forbid(unsafe_code)]

mod authorized_keys;
mod client;
mod daemon;
mod protocol;
mod ssh_login;
mod verify;

use std::env;
use std::process::ExitCode;

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("deploy") => client::deploy(&args[1..]),
        Some("daemon") => daemon::run(&args[1..]),
        Some("authorized-keys") => authorized_keys::run(&args[1..]),
        Some("-c") => ssh_login::run(&args[1..]),
        _ => Err("usage: nix-update-remote deploy ... | daemon ...".into()),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("nix-update-remote: {error}");
            ExitCode::FAILURE
        }
    }
}
