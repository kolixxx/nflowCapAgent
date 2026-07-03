mod table;

pub use table::{FlowEntry, FlowKey, FlowTable};

use crate::config::Config;
use tracing::info;

/// Flow aggregation is driven from `agent`; this module only provides the table type.
pub fn describe(cfg: &Config) {
    info!(
        active_timeout_secs = cfg.flow.active_timeout_secs,
        inactive_timeout_secs = cfg.flow.inactive_timeout_secs,
        "flow table ready"
    );
}
