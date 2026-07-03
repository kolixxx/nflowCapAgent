use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub collector: CollectorConfig,
    pub export: ExportConfig,
    pub capture: CaptureConfig,
    pub flow: FlowConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CollectorConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExportConfig {
    pub format: String,
    pub observation_domain_id: u32,
    pub source_id: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CaptureConfig {
    pub interface: String,
    pub promiscuous: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FlowConfig {
    pub active_timeout_secs: u32,
    pub inactive_timeout_secs: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file: Option<String>,
}

pub fn load(path: impl AsRef<Path>) -> Result<Config> {
    let text = fs::read_to_string(path.as_ref())
        .with_context(|| format!("reading {}", path.as_ref().display()))?;
    let cfg: Config = toml::from_str(&text).context("parsing TOML config")?;
    validate(&cfg)?;
    Ok(cfg)
}

fn validate(cfg: &Config) -> Result<()> {
    if cfg.collector.host.is_empty() {
        bail!("collector.host must not be empty");
    }
    if cfg.collector.port == 0 {
        bail!("collector.port must be > 0");
    }
    match cfg.export.format.as_str() {
        "netflow9" | "ipfix" => {}
        other => bail!("unsupported export.format: {other} (use netflow9 or ipfix)"),
    }
    Ok(())
}
