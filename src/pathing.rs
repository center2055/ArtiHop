use anyhow::{Result, bail};

use crate::config::Mode;

pub fn ensure_supported(mode: Mode) -> Result<()> {
    if !mode.is_experimental() {
        return Ok(());
    }

    bail!(
        "{mode} is intentionally not implemented in the compileable MVP. \
         Arti's stable TorClient API does not expose a supported hook for forcing \
         one-hop or two-hop exit circuits."
    )
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExperimentalPathGoal {
    GuardExit,
    SingleRelay,
}

#[allow(dead_code)]
pub fn describe_experimental_goal(mode: Mode) -> Option<ExperimentalPathGoal> {
    match mode {
        Mode::Normal => None,
        Mode::Short2 => Some(ExperimentalPathGoal::GuardExit),
        Mode::Short1 => Some(ExperimentalPathGoal::SingleRelay),
    }
}
