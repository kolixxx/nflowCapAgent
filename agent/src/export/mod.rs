mod ipfix;
mod netflow_v9;

use crate::config::Config;
use crate::flow::FlowEntry;
use anyhow::Result;
use ipfix::IpfixExporter;
use netflow_v9::NetflowV9Exporter;

pub enum FlowExporter {
    NetflowV9(NetflowV9Exporter),
    Ipfix(IpfixExporter),
}

pub fn create_exporter(cfg: &Config) -> Result<FlowExporter> {
    match cfg.export.format.as_str() {
        "netflow9" => Ok(FlowExporter::NetflowV9(NetflowV9Exporter::new(
            &cfg.collector.host,
            cfg.collector.port,
            cfg.export.clone(),
        )?)),
        "ipfix" => Ok(FlowExporter::Ipfix(IpfixExporter::new(
            &cfg.collector.host,
            cfg.collector.port,
            cfg.export.clone(),
        )?)),
        _ => unreachable!("validated in config"),
    }
}

pub fn export_flows(exporter: &mut FlowExporter, flows: &[FlowEntry]) -> Result<()> {
    match exporter {
        FlowExporter::NetflowV9(e) => e.export_flows(flows),
        FlowExporter::Ipfix(e) => e.export_flows(flows),
    }
}
