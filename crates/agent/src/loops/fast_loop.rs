use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::{config, dashboard::AdvisoryEntry, process, reader, AgentState};

pub(crate) async fn run_incident_tick(
    data_dir: &Path,
    cursor: &mut reader::AgentCursor,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
    advisory_cache: &Arc<RwLock<VecDeque<AdvisoryEntry>>>,
) {
    process::incidents::process_incidents(data_dir, cursor, cfg, state, advisory_cache).await;
}
