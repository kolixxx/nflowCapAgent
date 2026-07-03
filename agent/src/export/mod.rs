mod netflow_v9;

use crate::config::Config;
use crate::flow::FlowEntry;
use anyhow::{bail, Result};
use netflow_v9::NetflowV9Exporter;

pub fn create_exporter(cfg: &Config) -> Result<NetflowV9Exporter> {
    match cfg.export.format.as_str() {
        "netflow9" => NetflowV9Exporter::new(
            &cfg.collector.host,
            cfg.collector.port,
            cfg.export.clone(),
        ),
        "ipfix" => bail!("IPFIX export is planned for milestone 3"),
        _ => unreachable!("validated in config"),
    }
}

pub fn export_flows(exporter: &mut NetflowV9Exporter, flows: &[FlowEntry]) -> Result<()> {
    exporter.export_flows(flows)
}
