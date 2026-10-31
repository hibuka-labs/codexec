//! Worker lifecycle (codexec-design §7).
//!
//! ```text
//! NotStarted → Alive → (crash/timeout) → ResetPending → Restarted
//!                  ↘ Exited (idle exit)
//! ```
//!
//! Hard rule: after a reset the engine **never replays UI actions** from the
//! lost turn. The model must re-observe and rebuild references first — the
//! reset path returns `session_reset` instead.

use crate::observation::ExecError;

/// Where the worker session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// No worker yet.
    NotStarted,
    /// Running and usable.
    Alive,
    /// Crashed / timed out; the next cell triggers a restart and reports
    /// `session_reset` (that cell does not run).
    ResetPending,
    /// Fresh worker after a reset; previous references are void.
    Restarted,
    /// Idle exit; a new session is needed.
    Exited,
}

/// Session state machine plus the no-replay invariant.
#[derive(Debug)]
pub struct Lifecycle {
    state: SessionState,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl Lifecycle {
    /// Fresh lifecycle (state `NotStarted`).
    pub fn new() -> Self {
        Self {
            state: SessionState::NotStarted,
        }
    }

    /// Current state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// A worker came up.
    pub fn on_worker_up(&mut self) {
        self.state = match self.state {
            SessionState::NotStarted => SessionState::Alive,
            SessionState::ResetPending => SessionState::Restarted,
            other => other,
        };
    }

    /// The worker died or timed out.
    pub fn on_worker_lost(&mut self) {
        self.state = SessionState::ResetPending;
    }

    /// Idle exit.
    pub fn on_idle_exit(&mut self) {
        self.state = SessionState::Exited;
    }

    /// True while a worker is usable (freshly restarted counts).
    pub fn is_alive(&self) -> bool {
        matches!(self.state, SessionState::Alive | SessionState::Restarted)
    }

    /// True when the next cell must report `session_reset` instead of running
    /// (codexec-design §7: "本 cell 不执行").
    pub fn needs_reset_report(&self) -> bool {
        self.state == SessionState::ResetPending
    }

    /// The invariant, stated where a future implementer will trip over it:
    /// **a reset never replays the previous turn's UI actions.**
    pub const fn may_replay_ui_after_reset() -> bool {
        false
    }

    /// Map a lost worker onto the model-visible error.
    pub fn session_reset_error() -> ExecError {
        ExecError::SessionReset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_reports_reset_before_running_again() {
        let mut lc = Lifecycle::new();
        lc.on_worker_up();
        assert!(lc.is_alive());
        lc.on_worker_lost();
        assert!(lc.needs_reset_report());
        // The reset report is one-shot: after the engine reports + restarts,
        // the state moves to Restarted and the next cell may run.
        lc.on_worker_up();
        assert_eq!(lc.state(), SessionState::Restarted);
        assert!(lc.is_alive());
    }

    #[test]
    fn never_replays_ui_after_reset() {
        assert!(!Lifecycle::may_replay_ui_after_reset());
    }
}
