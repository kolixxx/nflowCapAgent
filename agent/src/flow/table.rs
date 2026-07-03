use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

#[derive(Debug, Clone)]
pub struct FlowEntry {
    pub key: FlowKey,
    pub packets: u64,
    pub bytes: u64,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

pub struct FlowTable {
    flows: HashMap<FlowKey, FlowEntry>,
    active_timeout: std::time::Duration,
    inactive_timeout: std::time::Duration,
}

impl FlowTable {
    pub fn new(active_timeout_secs: u32, inactive_timeout_secs: u32) -> Self {
        Self {
            flows: HashMap::new(),
            active_timeout: std::time::Duration::from_secs(active_timeout_secs.into()),
            inactive_timeout: std::time::Duration::from_secs(inactive_timeout_secs.into()),
        }
    }

    pub fn observe(&mut self, key: FlowKey, packet_bytes: u32, now: Instant) {
        let entry = self.flows.entry(key).or_insert_with(|| FlowEntry {
            key,
            packets: 0,
            bytes: 0,
            first_seen: now,
            last_seen: now,
        });
        entry.packets += 1;
        entry.bytes += u64::from(packet_bytes);
        entry.last_seen = now;
    }

    /// Returns flows that expired and removes them from the table.
    pub fn expire(&mut self, now: Instant) -> Vec<FlowEntry> {
        let mut expired = Vec::new();
        self.flows.retain(|_, flow| {
            let inactive = now.duration_since(flow.last_seen) >= self.inactive_timeout;
            let active = now.duration_since(flow.first_seen) >= self.active_timeout;
            if inactive || active {
                expired.push(flow.clone());
                false
            } else {
                true
            }
        });
        expired
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }
}
