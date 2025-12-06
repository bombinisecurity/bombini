//! Process cache holds Process information used by transmuters

use std::{collections::HashMap, sync::Arc};

use crate::transmuter::process::Process;
use bombini_common::event::process::ProcessKey;

pub struct CachedProcess {
    pub process: Arc<Process>,
    pub exited: bool,
}

pub type ProcessCache = HashMap<ProcessKey, CachedProcess>;
