use crate::config::ExportConfig;
use crate::flow::FlowEntry;
use anyhow::{Context, Result};
use byteorder::{BigEndian, WriteBytesExt};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

/// RFC 3954 recommends a stable exporter source port; many collectors expect it.
const EXPORT_SOURCE_PORT: u16 = 2056;
const TEMPLATE_ID: u16 = 256;

/// Standard field types used in our template (PEN 0).
const TEMPLATE_FIELDS: &[(u16, u16)] = &[
    (1, 8),   // IN_BYTES
    (2, 8),   // IN_PKTS
    (4, 1),   // PROTOCOL
    (7, 2),   // L4_SRC_PORT
    (11, 2),  // L4_DST_PORT
    (8, 4),   // IPV4_SRC_ADDR
    (12, 4),  // IPV4_DST_ADDR
    (22, 4),  // FIRST_SWITCHED
    (21, 4),  // LAST_SWITCHED
];

const RECORD_LEN: u16 = 37; // sum of TEMPLATE_FIELDS lengths

pub struct NetflowV9Exporter {
    socket: UdpSocket,
    dest: SocketAddr,
    export_cfg: ExportConfig,
    sequence: u32,
    boot_instant: Instant,
    last_template: Option<Instant>,
}

impl NetflowV9Exporter {
    pub fn new(collector_host: &str, collector_port: u16, export_cfg: ExportConfig) -> Result<Self> {
        let dest: SocketAddr = format!("{collector_host}:{collector_port}")
            .parse()
            .context("invalid collector address")?;

        let bind_addr = format!("0.0.0.0:{EXPORT_SOURCE_PORT}");
        let socket = UdpSocket::bind(&bind_addr)
            .with_context(|| format!("binding UDP export socket on {bind_addr}"))?;

        info!(%dest, source_port = EXPORT_SOURCE_PORT, "NetFlow v9 exporter ready");

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

        let mut flowsets: Vec<Vec<u8>> = Vec::new();
        if send_template {
            flowsets.push(build_template_flowset(TEMPLATE_ID));
            self.last_template = Some(Instant::now());
        }
        flowsets.push(build_data_flowset(
            TEMPLATE_ID,
            flows,
            self.boot_instant,
        )?);

        let packet = build_v9_packet(
            &flowsets,
            self.sequence,
            self.export_cfg.source_id,
            self.boot_instant,
        )?;
        self.sequence = self.sequence.wrapping_add(1);

        self.socket
            .send_to(&packet, self.dest)
            .with_context(|| format!("sending NetFlow v9 to {}", self.dest))?;

        debug!(
            flows = flows.len(),
            bytes = packet.len(),
            sequence = self.sequence.saturating_sub(1),
            "exported NetFlow v9 datagram"
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

fn build_template_flowset(template_id: u16) -> Vec<u8> {
    let field_count = TEMPLATE_FIELDS.len() as u16;
    let body_len = 4 + (field_count as usize * 4);
    let total_len = 4 + body_len;

    let mut buf = Vec::with_capacity(total_len);
    buf.write_u16::<BigEndian>(0).unwrap(); // FlowSet ID 0 = template
    buf.write_u16::<BigEndian>(total_len as u16).unwrap();
    buf.write_u16::<BigEndian>(template_id).unwrap();
    buf.write_u16::<BigEndian>(field_count).unwrap();
    for (typ, len) in TEMPLATE_FIELDS {
        buf.write_u16::<BigEndian>(*typ).unwrap();
        buf.write_u16::<BigEndian>(*len).unwrap();
    }
    buf
}

fn build_data_flowset(
    template_id: u16,
    flows: &[FlowEntry],
    boot: Instant,
) -> Result<Vec<u8>> {
    let records_len = flows.len() * RECORD_LEN as usize;
    let total_len = 4 + records_len;
    let mut buf = Vec::with_capacity(total_len);
    buf.write_u16::<BigEndian>(template_id).unwrap();
    buf.write_u16::<BigEndian>(total_len as u16).unwrap();

    for flow in flows {
        buf.write_u64::<BigEndian>(flow.bytes).unwrap();
        buf.write_u64::<BigEndian>(flow.packets).unwrap();
        buf.write_u8(flow.key.protocol).unwrap();
        buf.write_u16::<BigEndian>(flow.key.src_port).unwrap();
        buf.write_u16::<BigEndian>(flow.key.dst_port).unwrap();
        write_ipv4(&mut buf, flow.key.src_ip);
        write_ipv4(&mut buf, flow.key.dst_ip);
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

fn build_v9_packet(
    flowsets: &[Vec<u8>],
    sequence: u32,
    source_id: u32,
    boot: Instant,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    for fs in flowsets {
        body.extend_from_slice(fs);
    }

    let mut packet = Vec::with_capacity(20 + body.len());
    packet.write_u16::<BigEndian>(9).unwrap(); // version
    packet.write_u16::<BigEndian>(flowsets.len() as u16).unwrap(); // count = flow sets
    packet
        .write_u32::<BigEndian>(uptime_ms(boot, Instant::now()))
        .unwrap();
    packet.write_u32::<BigEndian>(unix_secs()).unwrap();
    packet.write_u32::<BigEndian>(sequence).unwrap();
    packet.write_u32::<BigEndian>(source_id).unwrap();
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
    fn template_flowset_has_expected_length() {
        let fs = build_template_flowset(TEMPLATE_ID);
        assert_eq!(fs.len(), 4 + 4 + TEMPLATE_FIELDS.len() * 4);
        assert_eq!(RECORD_LEN, 37);
    }

    #[test]
    fn builds_data_flowset_for_one_flow() {
        let now = Instant::now();
        let key = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
        };
        let flow = FlowEntry {
            key,
            packets: 10,
            bytes: 9000,
            first_seen: now,
            last_seen: now,
        };
        let fs = build_data_flowset(TEMPLATE_ID, &[flow], now).unwrap();
        assert_eq!(fs.len(), 4 + 37);
    }
}
