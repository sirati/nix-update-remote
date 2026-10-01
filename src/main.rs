#![forbid(unsafe_code)]

mod cancellation;
mod artifact;
mod artifact_client;
mod external_signing;
mod authorized_keys;
mod client;
mod configured_client;
mod keygen;
mod daemon;
mod generation_client;
mod protocol;
mod report_queue;
mod ssh_login;
mod verify;

use std::env;
use std::process::ExitCode;

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if matches!(args.first().map(String::as_str), Some("deploy" | "configured-deploy" | "deploy-artifact" | "deploy-generation")) {
        cancellation::install().map_err(|e| e.to_string())?;
    }
    match args.first().map(String::as_str) {
        Some("deliver-reports") => report_queue::deliver(&args[1..]),
        Some("run-hook") => report_queue::run_hook(&args[1..]),
        Some("deploy-generation") => generation_client::deploy(&args[1..]),
        Some("deploy-artifact") => artifact_client::deploy(&args[1..]),
        Some("install-erofs") => artifact::install(&args[1..]),
        Some("extract-bootstrap") => artifact::extract_bootstrap(&args[1..]),
        Some("prepare-erofs") => artifact::prepare(&args[1..]),
        Some("activate-erofs") => artifact::activate(&args[1..]),
        Some("keygen") => keygen::generate(&args[1..]),
        Some("configured-deploy") => configured_client::deploy(&args[1..]),
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
