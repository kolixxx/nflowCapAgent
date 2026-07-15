use crate::flow::FlowKey;
use std::net::Ipv4Addr;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_VLAN: u16 = 0x8100;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// One parsed IPv4 frame suitable for flow aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedPacket {
    pub key: FlowKey,
    pub frame_bytes: u32,
    /// TCP flags byte (offset 13); cumulative OR across the flow at export.
    /// Zero for non-TCP.
    pub tcp_flags: u8,
}

/// Parse IPv4 TCP/UDP flows from a link-layer frame (Ethernet).
pub fn parse_ethernet_ipv4(data: &[u8]) -> Option<ParsedPacket> {
    if data.len() < 14 {
        return None;
    }

    let mut offset = 12;
    let mut ethertype = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    // 802.1Q VLAN
    if ethertype == ETHERTYPE_VLAN {
        if data.len() < offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        offset += 4;
    }

    if ethertype != ETHERTYPE_IPV4 {
        return None;
    }

    parse_ipv4_l4(&data[offset..])
}

fn parse_ipv4_l4(data: &[u8]) -> Option<ParsedPacket> {
    if data.len() < 20 {
        return None;
    }

    let version_ihl = data[0];
    if version_ihl >> 4 != 4 {
        return None;
    }

    let ihl = (version_ihl & 0x0f) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }

    let total_length = u16::from_be_bytes([data[2], data[3]]) as usize;
    if total_length < ihl || data.len() < total_length {
        return None;
    }

    let protocol = data[9];
    if protocol != IPPROTO_TCP && protocol != IPPROTO_UDP {
        return None;
    }

    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let l4 = &data[ihl..total_length];
    if l4.len() < 4 {
        return None;
    }

    let src_port = u16::from_be_bytes([l4[0], l4[1]]);
    let dst_port = u16::from_be_bytes([l4[2], l4[3]]);

    let tcp_flags = if protocol == IPPROTO_TCP {
        parse_tcp_flags(l4)
    } else {
        0
    };

    let key = FlowKey {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
    };

    Some(ParsedPacket {
        key,
        frame_bytes: total_length as u32,
        tcp_flags,
    })
}

/// TCP flags byte (FIN/SYN/RST/PSH/ACK/URG/…) at offset 13 of the TCP header.
fn parse_tcp_flags(tcp: &[u8]) -> u8 {
    if tcp.len() >= 14 {
        tcp[13]
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_udp_ipv4_over_ethernet() {
        let mut frame = vec![0u8; 14 + 28];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x45;
        frame[16] = 0x00;
        frame[17] = 0x1c;
        frame[23] = 17;
        frame[26] = 192;
        frame[27] = 168;
        frame[28] = 1;
        frame[29] = 10;
        frame[30] = 8;
        frame[31] = 8;
        frame[32] = 8;
        frame[33] = 8;
        frame[34] = 0x04;
        frame[35] = 0xd2;
        frame[36] = 0x00;
        frame[37] = 0x35;

        let pkt = parse_ethernet_ipv4(&frame).expect("parse");
        assert_eq!(pkt.key.src_port, 1234);
        assert_eq!(pkt.key.dst_port, 53);
        assert_eq!(pkt.key.protocol, 17);
        assert_eq!(pkt.frame_bytes, 28);
        assert_eq!(pkt.tcp_flags, 0);
    }

    #[test]
    fn parses_tcp_syn_flags() {
        let ip_off = 14usize;
        let mut frame = vec![0u8; ip_off + 40];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[ip_off] = 0x45;
        frame[ip_off + 2] = 0x00;
        frame[ip_off + 3] = 0x28;
        frame[ip_off + 9] = 6;
        frame[ip_off + 12] = 10;
        frame[ip_off + 13] = 0;
        frame[ip_off + 14] = 0;
        frame[ip_off + 15] = 1;
        frame[ip_off + 16] = 1;
        frame[ip_off + 17] = 1;
        frame[ip_off + 18] = 1;
        let tcp_off = ip_off + 20;
        frame[tcp_off] = 0x30;
        frame[tcp_off + 1] = 0x39;
        frame[tcp_off + 2] = 0x01;
        frame[tcp_off + 3] = 0xbb;
        frame[tcp_off + 12] = 0x50;
        frame[tcp_off + 13] = 0x02; // SYN

        let pkt = parse_ethernet_ipv4(&frame).expect("parse");
        assert_eq!(pkt.key.protocol, 6);
        assert_eq!(pkt.tcp_flags, 0x02);
    }
}
