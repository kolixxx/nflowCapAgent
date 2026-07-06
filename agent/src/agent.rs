use crate::capture::{open_capture, parse_ethernet_ipv4};
use crate::config::Config;
use crate::export::{create_exporter, export_flows};
use crate::flow::{describe as describe_flows, FlowTable};
use anyhow::Result;
use pcap::Error as PcapError;
use std::time::Instant;
use tracing::{error, info, warn};

const EXPIRE_SCAN_INTERVAL_MS: u128 = 1000;

pub fn run(cfg: &Config, shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>) -> Result<()> {
    describe_flows(cfg);

    let mut cap = open_capture(cfg)?;
    let mut table = FlowTable::new(cfg.flow.active_timeout_secs, cfg.flow.inactive_timeout_secs);
    let mut exporter = create_exporter(cfg)?;

    info!(
        collector = %format!("{}:{}", cfg.collector.host, cfg.collector.port),
        "netflowAgent running — Ctrl+C to stop"
    );

    let mut last_expire = Instant::now();

    loop {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            info!("shutdown requested, stopping");
            return Ok(());
        }

        match cap.next_packet() {
            Ok(packet) => {
                let now = Instant::now();
                if let Some((key, bytes)) = parse_ethernet_ipv4(packet.data) {
                    table.observe(key, bytes, now);
                }
            }
            Err(PcapError::TimeoutExpired) => {}
            Err(e) => {
                warn!(error = %e, "capture read error");
            }
        }

        let now = Instant::now();
        if now.duration_since(last_expire).as_millis() >= EXPIRE_SCAN_INTERVAL_MS {
            let expired = table.expire(now);
            if !expired.is_empty() {
                info!(
                    flows = expired.len(),
                    active = table.len(),
                    "exporting expired flows"
                );
                if let Err(e) = export_flows(&mut exporter, &expired) {
                    error!(error = %e, "export failed");
                }
            }
            last_expire = now;
        }
    }
}
