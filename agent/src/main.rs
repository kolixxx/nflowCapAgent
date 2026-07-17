mod agent;
mod capture;
mod config;
mod export;
mod flow;
#[cfg(windows)]
mod service;

use anyhow::Context;
use clap::Parser;
use std::fs::OpenOptions;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser, Debug)]
#[command(
    name = "netflowAgent",
    version,
    about = "Host NetFlow/IPFIX export agent"
)]
struct Cli {
    /// Path to config.toml
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Validate config and exit
    #[arg(long)]
    check_config: bool,

    /// List Npcap/libpcap devices and exit
    #[arg(long)]
    list_devices: bool,

    /// Run as Windows service (used by Service Control Manager)
    #[arg(long, hide = true)]
    run_as_service: bool,

    /// Install Windows service (requires Administrator)
    #[arg(long)]
    install_service: bool,

    /// Remove Windows service (requires Administrator)
    #[arg(long)]
    uninstall_service: bool,
}

struct LogGuards {
    _file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    #[cfg(windows)]
    if cli.run_as_service {
        return service::run_dispatcher();
    }

    #[cfg(not(windows))]
    if cli.run_as_service {
        anyhow::bail!("--run-as-service is only supported on Windows");
    }

    #[cfg(windows)]
    if cli.install_service {
        return service::install_service(&cli.config);
    }

    #[cfg(windows)]
    if cli.uninstall_service {
        return service::uninstall_service();
    }

    #[cfg(not(windows))]
    if cli.install_service || cli.uninstall_service {
        anyhow::bail!("--install-service and --uninstall-service are only supported on Windows");
    }

    if cli.list_devices {
        return list_devices();
    }

    let cfg = config::load(&cli.config)
        .with_context(|| format!("loading config from {}", cli.config))?;

    let _log_guard = init_logging(
        &cfg.logging.level,
        cfg.logging.file.as_deref(),
        true,
    );

    info!(
        target = %format!("{}:{}", cfg.collector.host, cfg.collector.port),
        export = %cfg.export.format,
        interface = %cfg.capture.interface,
        os = %std::env::consts::OS,
        version = env!("CARGO_PKG_VERSION"),
        "netflowAgent starting"
    );

    if cli.check_config {
        info!("config OK");
        return Ok(());
    }

    agent::run(&cfg, Arc::new(AtomicBool::new(false)))
}

fn list_devices() -> anyhow::Result<()> {
    let devices = pcap::Device::list().context("listing capture devices")?;
    for d in devices {
        println!(
            "{} | {}",
            d.name,
            d.desc.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}

pub(crate) fn init_logging(
    level: &str,
    file: Option<&str>,
    console: bool,
) -> LogGuards {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let use_ansi =
        console && !cfg!(windows) && std::env::var_os("NO_COLOR").is_none();

    let mut file_guard = None;
    let registry = tracing_subscriber::registry().with(filter);

    if let Some(file_path) = file {
        let path = Path::new(file_path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(log_file) => {
                let (writer, guard) = tracing_appender::non_blocking(log_file);
                file_guard = Some(guard);

                if console {
                    registry
                        .with(fmt::layer().with_ansi(use_ansi))
                        .with(fmt::layer().with_writer(writer).with_ansi(false))
                        .init();
                } else {
                    registry
                        .with(fmt::layer().with_writer(writer).with_ansi(false))
                        .init();
                }
            }
            Err(e) => {
                eprintln!(
                    "warning: cannot open log file {}: {e} (logging to console only)",
                    path.display()
                );
                if console {
                    registry.with(fmt::layer().with_ansi(use_ansi)).init();
                } else {
                    registry.with(fmt::layer().with_ansi(false)).init();
                }
            }
        }
    } else if console {
        registry.with(fmt::layer().with_ansi(use_ansi)).init();
    } else {
        registry.with(fmt::layer().with_ansi(false)).init();
    }

    LogGuards {
        _file_guard: file_guard,
    }
}
