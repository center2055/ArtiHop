use crate::config::Mode;
use tor_circmgr::experimental_path::{ExperimentalPathMode, set_experimental_path_mode};
use tracing::warn;

pub fn configure(mode: Mode) {
    let arti_mode = match mode {
        Mode::Normal => ExperimentalPathMode::Standard,
        Mode::Short2 => ExperimentalPathMode::Short2,
        Mode::Short1 => ExperimentalPathMode::Short1,
    };

    set_experimental_path_mode(arti_mode);

    if mode.is_experimental() {
        warn!(
            %mode,
            "experimental shortened Tor circuit mode enabled; anonymity is reduced"
        );
    }
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
