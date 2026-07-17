use crate::config::ExportConfig;
use crate::flow::FlowEntry;
use anyhow::{bail, Context, Result};
use byteorder::{BigEndian, WriteBytesExt};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

const EXPORT_SOURCE_PORT: u16 = 2056;
const TEMPLATE_SET_ID: u16 = 2;
/// Bumped from 258 because v0.3.0 advertised an invalid IPFIX field layout.
const TEMPLATE_ID: u16 = 259;
const IPFIX_HEADER_LEN: usize = 16;
/// Keep UDP payloads below a typical Ethernet MTU to avoid IP fragmentation.
const MAX_DATAGRAM_LEN: usize = 1400;

/// IANA IPFIX information elements (type, length).
const TEMPLATE_FIELDS: &[(u16, u16)] = &[
    (1, 4),   // octetDeltaCount
    (2, 4),   // packetDeltaCount
    (4, 1),   // protocolIdentifier
    (6, 2),   // tcpControlBits (IANA unsigned16)
    (7, 2),   // sourceTransportPort
    (11, 2),  // destinationTransportPort
    (8, 4),   // sourceIPv4Address
    (12, 4),  // destinationIPv4Address
    (10, 4),  // ingressInterface
    (14, 4),  // egressInterface
    (152, 8), // flowStartMilliseconds
    (153, 8), // flowEndMilliseconds
];

const RECORD_LEN: usize = 47;
const INPUT_SNMP_INDEX: u32 = 1;
const OUTPUT_SNMP_INDEX: u32 = 0;

#[derive(Clone, Copy)]
struct ExportClock {
    anchor_instant: Instant,
    anchor_unix_ms: u64,
}

impl ExportClock {
    fn now() -> Self {
        let anchor_instant = Instant::now();
        let anchor_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        Self {
            anchor_instant,
            anchor_unix_ms,
        }
    }

    fn unix_millis(self, event: Instant) -> u64 {
        if let Some(delta) = event.checked_duration_since(self.anchor_instant) {
            self.anchor_unix_ms
                .saturating_add(delta.as_millis().min(u64::MAX as u128) as u64)
        } else {
            let delta = self.anchor_instant.duration_since(event);
            self.anchor_unix_ms
                .saturating_sub(delta.as_millis().min(u64::MAX as u128) as u64)
        }
    }
}

pub struct IpfixExporter {
    socket: UdpSocket,
    dest: SocketAddr,
    export_cfg: ExportConfig,
    sequence: u32,
    last_template: Option<Instant>,
}

impl IpfixExporter {
    pub fn new(
        collector_host: &str,
        collector_port: u16,
        export_cfg: ExportConfig,
    ) -> Result<Self> {
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
            last_template: None,
        })
    }

    pub fn export_flows(&mut self, flows: &[FlowEntry]) -> Result<()> {
        if flows.is_empty() {
            return Ok(());
        }

        let mut send_template = match self.last_template {
            None => true,
            Some(t) => t.elapsed() >= Duration::from_secs(60),
        };

        let domain_id = if self.export_cfg.observation_domain_id != 0 {
            self.export_cfg.observation_domain_id
        } else {
            self.export_cfg.source_id
        };
        // Anchor wall time per batch so OS/NTP clock corrections are reflected.
        let clock = ExportClock::now();

        let mut offset = 0;
        while offset < flows.len() {
            let chunk_len = max_records_per_datagram(send_template).min(flows.len() - offset);
            if chunk_len == 0 {
                bail!("IPFIX record does not fit in the configured datagram size");
            }
            let chunk = &flows[offset..offset + chunk_len];
            let mut sets = Vec::with_capacity(if send_template { 2 } else { 1 });
            if send_template {
                sets.push(build_template_set(TEMPLATE_ID));
            }
            sets.push(build_data_set(TEMPLATE_ID, chunk, clock)?);

            let sequence = self.sequence;
            let packet = build_ipfix_message(&sets, sequence, domain_id)?;
            if packet.len() > MAX_DATAGRAM_LEN {
                bail!(
                    "IPFIX datagram is {} bytes, limit is {}",
                    packet.len(),
                    MAX_DATAGRAM_LEN
                );
            }
            self.socket
                .send_to(&packet, self.dest)
                .with_context(|| format!("sending IPFIX to {}", self.dest))?;

            self.sequence = advance_sequence(self.sequence, chunk.len());
            if send_template {
                self.last_template = Some(Instant::now());
                send_template = false;
            }
            offset += chunk.len();

            debug!(
                flows = chunk.len(),
                bytes = packet.len(),
                sequence,
                "exported IPFIX datagram"
            );
        }

        Ok(())
    }
}

fn unix_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

fn advance_sequence(sequence: u32, record_count: usize) -> u32 {
    sequence.wrapping_add(record_count as u32)
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

fn padded_len(len: usize) -> usize {
    len + ((4 - (len % 4)) % 4)
}

fn data_set_len(record_count: usize) -> Result<usize> {
    let records_len = record_count
        .checked_mul(RECORD_LEN)
        .context("IPFIX data record length overflow")?;
    let raw_len = 4usize
        .checked_add(records_len)
        .context("IPFIX data set length overflow")?;
    let set_len = padded_len(raw_len);
    if set_len > u16::MAX as usize {
        bail!("IPFIX data set exceeds 65535 bytes");
    }
    Ok(set_len)
}

fn max_records_per_datagram(include_template: bool) -> usize {
    let template_len = if include_template {
        build_template_set(TEMPLATE_ID).len()
    } else {
        0
    };
    let available = MAX_DATAGRAM_LEN
        .saturating_sub(IPFIX_HEADER_LEN)
        .saturating_sub(template_len)
        .saturating_sub(4);
    available / RECORD_LEN
}

fn build_data_set(template_id: u16, flows: &[FlowEntry], clock: ExportClock) -> Result<Vec<u8>> {
    let set_len = data_set_len(flows.len())?;
    let mut buf = Vec::with_capacity(set_len);
    buf.write_u16::<BigEndian>(template_id).unwrap();
    buf.write_u16::<BigEndian>(set_len as u16).unwrap();

    for flow in flows {
        buf.write_u32::<BigEndian>(to_u32_counter(flow.bytes))
            .unwrap();
        buf.write_u32::<BigEndian>(to_u32_counter(flow.packets))
            .unwrap();
        buf.write_u8(flow.key.protocol).unwrap();
        buf.write_u16::<BigEndian>(u16::from(flow.tcp_flags))
            .unwrap();
        buf.write_u16::<BigEndian>(flow.key.src_port).unwrap();
        buf.write_u16::<BigEndian>(flow.key.dst_port).unwrap();
        write_ipv4(&mut buf, flow.key.src_ip);
        write_ipv4(&mut buf, flow.key.dst_ip);
        buf.write_u32::<BigEndian>(INPUT_SNMP_INDEX).unwrap();
        buf.write_u32::<BigEndian>(OUTPUT_SNMP_INDEX).unwrap();
        buf.write_u64::<BigEndian>(clock.unix_millis(flow.first_seen))
            .unwrap();
        buf.write_u64::<BigEndian>(clock.unix_millis(flow.last_seen))
            .unwrap();
    }
    buf.resize(set_len, 0);

    Ok(buf)
}

fn write_ipv4(buf: &mut Vec<u8>, ip: std::net::Ipv4Addr) {
    for octet in ip.octets() {
        buf.push(octet);
    }
}

fn build_ipfix_message(
    sets: &[Vec<u8>],
    sequence: u32,
    observation_domain_id: u32,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    for set in sets {
        body.extend_from_slice(set);
    }

    let total_len = IPFIX_HEADER_LEN
        .checked_add(body.len())
        .context("IPFIX message length overflow")?;
    if total_len > u16::MAX as usize {
        bail!("IPFIX message exceeds 65535 bytes");
    }
    let mut packet = Vec::with_capacity(total_len);
    packet.write_u16::<BigEndian>(10).unwrap();
    packet.write_u16::<BigEndian>(total_len as u16).unwrap();
    packet.write_u32::<BigEndian>(unix_secs()).unwrap();
    packet.write_u32::<BigEndian>(sequence).unwrap();
    packet
        .write_u32::<BigEndian>(observation_domain_id)
        .unwrap();
    packet.extend_from_slice(&body);
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{FlowEntry, FlowKey};
    use byteorder::{BigEndian, ByteOrder};
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    fn test_flow(now: Instant) -> FlowEntry {
        FlowEntry {
            key: FlowKey {
                src_ip: Ipv4Addr::new(10, 0, 0, 1),
                dst_ip: Ipv4Addr::new(8, 8, 8, 8),
                src_port: 50_000,
                dst_port: 443,
                protocol: 6,
            },
            packets: 3,
            bytes: 1_500,
            tcp_flags: 0x1b,
            first_seen: now,
            last_seen: now + Duration::from_millis(250),
        }
    }

    fn test_clock(now: Instant) -> ExportClock {
        ExportClock {
            anchor_instant: now,
            anchor_unix_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn template_fields_match_iana_registry() {
        assert_eq!(
            TEMPLATE_FIELDS,
            &[
                (1, 4),
                (2, 4),
                (4, 1),
                (6, 2),
                (7, 2),
                (11, 2),
                (8, 4),
                (12, 4),
                (10, 4),
                (14, 4),
                (152, 8),
                (153, 8),
            ]
        );
        assert_eq!(
            TEMPLATE_FIELDS
                .iter()
                .map(|(_, len)| usize::from(*len))
                .sum::<usize>(),
            RECORD_LEN
        );
    }

    #[test]
    fn template_set_has_expected_layout() {
        let template = build_template_set(TEMPLATE_ID);
        assert_eq!(template.len(), 56);
        assert_eq!(BigEndian::read_u16(&template[0..2]), TEMPLATE_SET_ID);
        assert_eq!(BigEndian::read_u16(&template[2..4]), 56);
        assert_eq!(BigEndian::read_u16(&template[4..6]), TEMPLATE_ID);
        assert_eq!(BigEndian::read_u16(&template[6..8]), 12);
    }

    #[test]
    fn data_record_offsets_and_timestamps_match_template() {
        let now = Instant::now();
        let data = build_data_set(TEMPLATE_ID, &[test_flow(now)], test_clock(now)).unwrap();
        let record = &data[4..4 + RECORD_LEN];

        assert_eq!(BigEndian::read_u32(&record[0..4]), 1_500);
        assert_eq!(BigEndian::read_u32(&record[4..8]), 3);
        assert_eq!(record[8], 6);
        assert_eq!(BigEndian::read_u16(&record[9..11]), 0x1b);
        assert_eq!(BigEndian::read_u16(&record[11..13]), 50_000);
        assert_eq!(BigEndian::read_u16(&record[13..15]), 443);
        assert_eq!(&record[15..19], &[10, 0, 0, 1]);
        assert_eq!(&record[19..23], &[8, 8, 8, 8]);
        assert_eq!(BigEndian::read_u32(&record[23..27]), 1);
        assert_eq!(BigEndian::read_u32(&record[27..31]), 0);
        assert_eq!(BigEndian::read_u64(&record[31..39]), 1_700_000_000_000);
        assert_eq!(BigEndian::read_u64(&record[39..47]), 1_700_000_000_250);
    }

    #[test]
    fn data_sets_are_padded_to_four_octets() {
        let now = Instant::now();
        let flow = test_flow(now);
        let one =
            build_data_set(TEMPLATE_ID, std::slice::from_ref(&flow), test_clock(now)).unwrap();
        let two = build_data_set(TEMPLATE_ID, &[flow.clone(), flow], test_clock(now)).unwrap();

        assert_eq!(one.len(), 52);
        assert_eq!(one.len() % 4, 0);
        assert_eq!(one[51], 0);
        assert_eq!(BigEndian::read_u16(&one[2..4]) as usize, one.len());
        assert_eq!(two.len(), 100);
        assert_eq!(two.len() % 4, 0);
        assert_eq!(&two[98..100], &[0, 0]);
    }

    #[test]
    fn message_header_and_lengths_are_valid() {
        let now = Instant::now();
        let flow = test_flow(now);
        let template = build_template_set(TEMPLATE_ID);
        let data = build_data_set(TEMPLATE_ID, &[flow], test_clock(now)).unwrap();
        let msg = build_ipfix_message(&[template, data], 1, 1).unwrap();

        assert_eq!(BigEndian::read_u16(&msg[0..2]), 10);
        assert_eq!(BigEndian::read_u16(&msg[2..4]) as usize, msg.len());
        assert_eq!(msg.len(), 124);
        assert_eq!(BigEndian::read_u32(&msg[8..12]), 1);
        assert_eq!(BigEndian::read_u32(&msg[12..16]), 1);
    }

    #[test]
    fn datagram_capacity_stays_below_limit() {
        for include_template in [false, true] {
            let count = max_records_per_datagram(include_template);
            let template_len = if include_template { 56 } else { 0 };
            let message_len = IPFIX_HEADER_LEN + template_len + data_set_len(count).unwrap();
            assert!(count > 0);
            assert!(message_len <= MAX_DATAGRAM_LEN);
            assert!(
                IPFIX_HEADER_LEN + template_len + data_set_len(count + 1).unwrap()
                    > MAX_DATAGRAM_LEN
            );
        }
    }

    #[test]
    fn sequence_advances_by_data_record_count() {
        let sequence = u32::MAX - 1;
        assert_eq!(advance_sequence(sequence, 3), 1);
    }
}
