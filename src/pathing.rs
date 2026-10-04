use crate::config::Mode;
use tor_circmgr::experimental_path::{ExperimentalPathMode, set_experimental_path_mode};
use tracing::warn;

/// The mode that can actually work. Through a bridge, a shortened circuit is Bridge -> Exit, and Tor
/// exits refuse streams on circuits like that (TORPROTOCOL), so every connection would fail. Bridges
/// therefore get the standard 3-hop path.
pub fn effective_mode(requested: Mode, using_bridges: bool) -> Mode {
    if using_bridges && requested.is_experimental() {
        warn!(
            %requested,
            "shortened circuits do not work through bridges (exits refuse them); using normal 3-hop circuits"
        );
        return Mode::Normal;
    }

    requested
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridges_force_three_hop_circuits() {
        assert_eq!(effective_mode(Mode::Short2, true), Mode::Normal);
        assert_eq!(effective_mode(Mode::Short1, true), Mode::Normal);
        assert_eq!(effective_mode(Mode::Normal, true), Mode::Normal);
    }

    #[test]
    fn without_bridges_the_requested_mode_stands() {
        assert_eq!(effective_mode(Mode::Short2, false), Mode::Short2);
        assert_eq!(effective_mode(Mode::Normal, false), Mode::Normal);
    }
}
