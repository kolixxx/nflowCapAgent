use crate::config::ExportConfig;
use crate::flow::FlowEntry;
use anyhow::{Context, Result};
use byteorder::{BigEndian, WriteBytesExt};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

const EXPORT_SOURCE_PORT: u16 = 2056;
const TEMPLATE_SET_ID: u16 = 2;
const TEMPLATE_ID: u16 = 258;

/// IANA IPFIX information elements (type, length).
const TEMPLATE_FIELDS: &[(u16, u16)] = &[
    (1, 4),   // octetDeltaCount
    (2, 4),   // packetDeltaCount
    (4, 1),   // protocolIdentifier
    (6, 1),   // tcpControlBits
    (7, 2),   // sourceTransportPort
    (8, 2),   // destinationTransportPort
    (12, 4),  // sourceIPv4Address
    (13, 4),  // destinationIPv4Address
    (10, 4),  // ingressInterface
    (11, 4),  // egressInterface
    (22, 4),  // flowStartSysUpTime
    (21, 4),  // flowEndSysUpTime
];

const RECORD_LEN: u16 = 38;
const INPUT_SNMP_INDEX: u32 = 1;
const OUTPUT_SNMP_INDEX: u32 = 0;

pub struct IpfixExporter {
    socket: UdpSocket,
    dest: SocketAddr,
    export_cfg: ExportConfig,
    sequence: u32,
    boot_instant: Instant,
    last_template: Option<Instant>,
}

impl IpfixExporter {
    pub fn new(collector_host: &str, collector_port: u16, export_cfg: ExportConfig) -> Result<Self> {
        let dest: SocketAddr = format!("{collector_host}:{collector_port}")
            .parse()
            .context("invalid collector address")?;

        let bind_addr = format!("0.0.0.0:{EXPORT_SOURCE_PORT}");
        let socket = UdpSocket::bind(&bind_addr)
            .with_context(|| format!("binding UDP export socket on {bind_addr}"))?;

        info!(%dest, source_port = EXPORT_SOURCE_PORT, "IPFIX exporter ready");

        Ok(Self {
            socket,
            dest,
            export_cfg,
            sequence: 0,
            boot_instant: Instant::now(),
            last_template: None,
        })
    }

    pub fn export_flows(&mut self, flows: &[FlowEntry]) -> Result<()> {
        if flows.is_empty() {
            return Ok(());
        }

        let send_template = match self.last_template {
            None => true,
            Some(t) => t.elapsed() >= std::time::Duration::from_secs(60),
        };

        let mut sets: Vec<Vec<u8>> = Vec::new();
        if send_template {
            sets.push(build_template_set(TEMPLATE_ID));
            self.last_template = Some(Instant::now());
        }
        sets.push(build_data_set(TEMPLATE_ID, flows, self.boot_instant)?);

        let domain_id = if self.export_cfg.observation_domain_id != 0 {
            self.export_cfg.observation_domain_id
        } else {
            self.export_cfg.source_id
        };

        let packet = build_ipfix_message(&sets, self.sequence, domain_id)?;
        self.sequence = self.sequence.wrapping_add(1);

        self.socket
            .send_to(&packet, self.dest)
            .with_context(|| format!("sending IPFIX to {}", self.dest))?;

        debug!(
            flows = flows.len(),
            bytes = packet.len(),
            sequence = self.sequence.saturating_sub(1),
            "exported IPFIX datagram"
        );

        Ok(())
    }
}

fn uptime_ms(boot: Instant, event: Instant) -> u32 {
    event.duration_since(boot).as_millis().min(u32::MAX as u128) as u32
}

fn unix_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

fn to_u32_counter(value: u64) -> u32 {
    value.min(u32::MAX as u64) as u32
}

fn build_template_set(template_id: u16) -> Vec<u8> {
    let field_count = TEMPLATE_FIELDS.len() as u16;
    let body_len = 4 + (field_count as usize * 4);
    let set_len = 4 + body_len;

    let mut buf = Vec::with_capacity(set_len);
    buf.write_u16::<BigEndian>(TEMPLATE_SET_ID).unwrap();
    buf.write_u16::<BigEndian>(set_len as u16).unwrap();
    buf.write_u16::<BigEndian>(template_id).unwrap();
    buf.write_u16::<BigEndian>(field_count).unwrap();
    for (typ, len) in TEMPLATE_FIELDS {
        buf.write_u16::<BigEndian>(*typ).unwrap();
        buf.write_u16::<BigEndian>(*len).unwrap();
    }
    buf
}

fn build_data_set(template_id: u16, flows: &[FlowEntry], boot: Instant) -> Result<Vec<u8>> {
    let records_len = flows.len() * RECORD_LEN as usize;
    let set_len = 4 + records_len;
    let mut buf = Vec::with_capacity(set_len);
    buf.write_u16::<BigEndian>(template_id).unwrap();
    buf.write_u16::<BigEndian>(set_len as u16).unwrap();

    for flow in flows {
        buf.write_u32::<BigEndian>(to_u32_counter(flow.bytes)).unwrap();
        buf.write_u32::<BigEndian>(to_u32_counter(flow.packets)).unwrap();
        buf.write_u8(flow.key.protocol).unwrap();
        buf.write_u8(flow.tcp_flags).unwrap();
        buf.write_u16::<BigEndian>(flow.key.src_port).unwrap();
        buf.write_u16::<BigEndian>(flow.key.dst_port).unwrap();
        write_ipv4(&mut buf, flow.key.src_ip);
        write_ipv4(&mut buf, flow.key.dst_ip);
        buf.write_u32::<BigEndian>(INPUT_SNMP_INDEX).unwrap();
        buf.write_u32::<BigEndian>(OUTPUT_SNMP_INDEX).unwrap();
        buf.write_u32::<BigEndian>(uptime_ms(boot, flow.first_seen))
            .unwrap();
        buf.write_u32::<BigEndian>(uptime_ms(boot, flow.last_seen))
            .unwrap();
    }

    Ok(buf)
}

fn write_ipv4(buf: &mut Vec<u8>, ip: std::net::Ipv4Addr) {
    for octet in ip.octets() {
        buf.push(octet);
    }
}

fn build_ipfix_message(sets: &[Vec<u8>], sequence: u32, observation_domain_id: u32) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    for set in sets {
        body.extend_from_slice(set);
    }

    let total_len = 16 + body.len();
    let mut packet = Vec::with_capacity(total_len);
    packet.write_u16::<BigEndian>(10).unwrap();
    packet.write_u16::<BigEndian>(total_len as u16).unwrap();
    packet.write_u32::<BigEndian>(unix_secs()).unwrap();
    packet.write_u32::<BigEndian>(sequence).unwrap();
    packet.write_u32::<BigEndian>(observation_domain_id).unwrap();
    packet.extend_from_slice(&body);
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{FlowEntry, FlowKey};
    use std::net::Ipv4Addr;
    use std::time::Instant;

    #[test]
    fn ipfix_message_starts_with_version_10() {
        let now = Instant::now();
        let key = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            src_port: 443,
            dst_port: 80,
            protocol: 6,
        };
        let flow = FlowEntry {
            key,
            packets: 1,
            bytes: 100,
            tcp_flags: 0x10,
            first_seen: now,
            last_seen: now,
        };
        let template = build_template_set(TEMPLATE_ID);
        let data = build_data_set(TEMPLATE_ID, &[flow], now).unwrap();
        let msg = build_ipfix_message(&[template, data], 1, 1).unwrap();
        assert_eq!(msg[0], 0);
        assert_eq!(msg[1], 10);
        assert_eq!(RECORD_LEN, 38);
    }
}
