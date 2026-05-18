//! ArtiHop-only circuit length controls.
//!
//! This module is intentionally outside Arti's stable public API. It exists so
//! ArtiHop can run a local fork experiment without pretending that upstream
//! `arti-client` exposes path-length injection.

use std::sync::atomic::{AtomicU8, Ordering};

/// Exit-circuit path length selected by the embedding process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExperimentalPathMode {
    /// Upstream Arti behavior.
    Standard,
    /// Experimental guard-to-exit path, omitting the middle relay.
    Short2,
    /// Experimental single relay path, using the selected exit as the only hop.
    Short1,
}

/// Atomic storage for the process-wide path mode.
static MODE: AtomicU8 = AtomicU8::new(0);

impl ExperimentalPathMode {
    /// Convert this mode into its atomic storage representation.
    fn as_storage_value(self) -> u8 {
        match self {
            ExperimentalPathMode::Standard => 0,
            ExperimentalPathMode::Short2 => 1,
            ExperimentalPathMode::Short1 => 2,
        }
    }
}

/// Set the process-wide experimental path mode.
///
/// Circuit managers cache open circuits. Call this once during process startup,
/// before launching or reusing client circuits.
pub fn set_experimental_path_mode(mode: ExperimentalPathMode) {
    MODE.store(mode.as_storage_value(), Ordering::SeqCst);
}

/// Return the process-wide experimental path mode.
pub fn experimental_path_mode() -> ExperimentalPathMode {
    match MODE.load(Ordering::SeqCst) {
        1 => ExperimentalPathMode::Short2,
        2 => ExperimentalPathMode::Short1,
        _ => ExperimentalPathMode::Standard,
    }
}
