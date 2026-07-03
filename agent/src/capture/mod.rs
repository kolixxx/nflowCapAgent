mod parse;

use crate::config::Config;
use anyhow::{bail, Context, Result};
use pcap::{Capture, Device};
use tracing::{info, warn};

pub fn open_capture(cfg: &Config) -> Result<Capture<pcap::Active>> {
    let device = resolve_device(&cfg.capture.interface)?;
    info!(
        device = %device.name,
        desc = device.desc.as_deref().unwrap_or(""),
        "opening capture device"
    );

    let mut cap = Capture::from_device(device)
        .context("pcap from_device")?
        .promisc(cfg.capture.promiscuous)
        .snaplen(65535)
        .timeout(1000)
        .open()
        .context("pcap open")?;

    cap.filter("ip", true).context("pcap bpf filter")?;
    Ok(cap)
}

fn resolve_device(request: &str) -> Result<Device> {
    let devices = Device::list().context("listing pcap devices")?;
    if devices.is_empty() {
        bail!("no capture devices found — install Npcap (Windows) or libpcap (Linux)");
    }

    if request != "auto" {
        if let Some(d) = devices.iter().find(|d| device_matches(d, request)) {
            return Ok(d.clone());
        }
        warn!(
            requested = request,
            "exact device not found, available: {}",
            list_devices(&devices)
        );
        bail!("network interface not found: {request}");
    }

    devices
        .into_iter()
        .find(|d| {
            let n = d.name.to_lowercase();
            !(n.contains("loopback") || n.contains("npcap loopback"))
        })
        .context("no non-loopback capture device found")
}

fn device_matches(device: &Device, request: &str) -> bool {
    let req = request.to_lowercase();
    if device.name.eq_ignore_ascii_case(request) {
        return true;
    }
    if device.name.to_lowercase().contains(&req) {
        return true;
    }
    if let Some(desc) = &device.desc {
        if desc.to_lowercase().contains(&req) {
            return true;
        }
    }
    false
}

fn list_devices(devices: &[Device]) -> String {
    devices
        .iter()
        .map(|d| format!("{} ({})", d.name, d.desc.as_deref().unwrap_or("-")))
        .collect::<Vec<_>>()
        .join(", ")
}

pub use parse::parse_ethernet_ipv4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_matches_ethernet0_by_name() {
        let d = Device::from("Ethernet0");
        assert!(device_matches(&d, "Ethernet0"));
    }
}
