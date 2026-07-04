mod agent;
mod capture;
mod config;
mod export;
mod flow;

use anyhow::Context;
use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "netflowAgent", about = "Host NetFlow export agent")]
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
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.list_devices {
        return list_devices();
    }

    let cfg = config::load(&cli.config)
        .with_context(|| format!("loading config from {}", cli.config))?;

    init_logging(&cfg.logging.level);

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

    agent::run(&cfg)
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

fn init_logging(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_new(level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    // Windows cmd.exe does not render ANSI colors; plain text is readable.
    let use_ansi = !cfg!(windows) && std::env::var_os("NO_COLOR").is_none();

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(use_ansi)
        .init();
}
