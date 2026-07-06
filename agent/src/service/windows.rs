use crate::agent;
use crate::config;
use crate::init_logging;
use anyhow::{bail, Context, Result};
use clap::Parser;
use std::ffi::OsString;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::info;
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

const SERVICE_NAME: &str = "netflowAgent";

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        eprintln!("netflowAgent service error: {e:#}");
    }
}

fn run_service() -> Result<()> {
    #[derive(Parser, Debug)]
    #[command(name = "netflowAgent")]
    struct ServiceCli {
        #[arg(short, long, default_value = "config.toml")]
        config: String,
        #[arg(long, hide = true)]
        run_as_service: bool,
    }

    let cli = ServiceCli::parse();
    let cfg = config::load(&cli.config)
        .with_context(|| format!("loading config from {}", cli.config))?;

    let _log_guard = init_logging(
        &cfg.logging.level,
        cfg.logging.file.as_deref(),
        false,
    );

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_flag = shutdown.clone();

    let status_handle = service_control_handler::register(SERVICE_NAME, move |control_event| {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                shutdown_flag.store(true, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    info!(config = %cli.config, "Windows service started");

    let result = agent::run(&cfg, shutdown);

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    result
}

pub fn run_dispatcher() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("starting Windows service dispatcher")
}

pub fn install_service(config_path: &str) -> Result<()> {
    let exe = std::env::current_exe().context("resolving executable path")?;
    // sc.exe: exe path + arguments must be one quoted binPath value (space after '=').
    let bin_inner = format!(
        "\\\"{}\\\" --run-as-service --config \\\"{}\\\"",
        exe.display(),
        config_path,
    );
    let bin_path_arg = format!("binPath= \"{bin_inner}\"");

    let output = Command::new("sc.exe")
        .args([
            "create",
            SERVICE_NAME,
            &bin_path_arg,
            "start= auto",
            "DisplayName= \"netflowAgent NetFlow Export\"",
        ])
        .output()
        .context("running sc.exe create")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!("sc.exe create failed: {stdout}{stderr}");
    }

    let _ = Command::new("sc.exe")
        .args([
            "description",
            SERVICE_NAME,
            "Exports host network flows as NetFlow v9 to nfcapd collector",
        ])
        .output();

    println!(
        "Service '{SERVICE_NAME}' installed. Start: sc start {SERVICE_NAME}",
    );
    Ok(())
}

pub fn uninstall_service() -> Result<()> {
    let _ = Command::new("sc.exe")
        .args(["stop", SERVICE_NAME])
        .output();

    let output = Command::new("sc.exe")
        .args(["delete", SERVICE_NAME])
        .output()
        .context("running sc.exe delete")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!("sc.exe delete failed: {stdout}{stderr}");
    }

    println!("Service '{SERVICE_NAME}' uninstalled.");
    Ok(())
}
