//! Observations (codexec-design §4.3): what the model gets back after a step.
//!
//! `stdout` carries the text observation stream, **including one
//! `namespace: …` snapshot line per cell** (sdk-assembly §8.2) — the model
//! should never have to guess what is still alive.

use crate::policy::PolicyDecision;
use phi_cap::Capability;
use phi_ns::ImageRef;
use thiserror::Error;

/// Side-channel events raised while a cell ran (codexec-design §4.3,
/// sdk-assembly §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellEvent {
    /// A todo changed state.
    TodoChanged {
        /// Todo id.
        id: String,
        /// New status.
        status: String,
    },
    /// A picture for the model — never smuggled through `stdout`.
    Image(ImageRef),
    /// A short notice line.
    Notice {
        /// What the model should know.
        text: String,
    },
    /// A spilled observation body's standing reference (M3c,
    /// action-executor-design §6): the body is in the artifact store, the
    /// adapters render [`crate::artifacts::artifact_line`] from this into
    /// the observation text — summary + one fetch instruction.
    Artifact {
        /// Stable store id (`art_<seq>`).
        capture_id: String,
        /// What the body is (`"stdout"` / `"stderr"` / `"observation"` / the
        /// emitter's own label).
        kind: String,
        /// Body size in bytes (line metadata).
        bytes: usize,
        /// The truncation-heuristic glimpse of the body.
        summary: String,
    },
}

/// One cell's mediated-effect tally for the round: what the world actually
/// did while the cell ran, counted at the same chokepoint the journal rows
/// land on (host calls and PEP 578 audit events alike). The ledger has always
/// recorded these — the tally brings them back to the model, which otherwise
/// only sees what the code chose to print.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CellEffects {
    /// 0-based cell the effects are attributed to.
    pub cell_index: usize,
    /// Allowed effects per capability class, in O7 order (Pure first).
    pub counts: Vec<(Capability, usize)>,
    /// Effects policy refused (deny / hold) — the step may have halted on one.
    pub denied: usize,
}

/// What one step produced (codexec-design §4.3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observation {
    /// Text output, limits-respecting, with per-cell snapshot lines folded in.
    pub stdout: String,
    /// Diagnostic output.
    pub stderr: String,
    /// First failure of the step, if any.
    pub error: Option<ExecError>,
    /// Side-channel events.
    pub events: Vec<CellEvent>,
    /// The round's progress trail, already stamped (`"[12.3s] downloaded 40%"`)
    /// — what the run looked like while it ran (knife③).
    pub progress: Vec<String>,
    /// Per-cell effect tally (knife①): what the world did, not only what the
    /// code printed. One entry per cell that produced at least one row.
    pub effects: Vec<CellEffects>,
}

impl Observation {
    /// A step that produced nothing.
    pub fn empty() -> Self {
        Self::default()
    }

    /// True when the step halted on a policy hold (deny/ask).
    pub fn is_policy_hold(&self) -> bool {
        matches!(self.error, Some(ExecError::PolicyHold { .. }))
    }

    /// True when the session had to be reset; the cell did not run
    /// (codexec-design §7).
    pub fn is_session_reset(&self) -> bool {
        matches!(self.error, Some(ExecError::SessionReset))
    }
}

/// Failure of a step, in a form the next model turn can act on.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExecError {
    /// Worker was dead/resetting — **this cell did not run**. The model must
    /// re-observe and rebuild references (codexec-design §7).
    #[error("session_reset: worker was lost; re-observe and rebuild references before continuing")]
    SessionReset,

    /// The round hit its hard timeout; the worker is recycled.
    /// `where_it_stuck` carries the worker's own stack dump when it managed to
    /// emit one before the kill (knife②) — a hang now says where it hung.
    #[error("timeout: round exceeded {timeout_ms}ms; worker recycled{}", .where_it_stuck.as_deref().map(|s| format!("\n{s}")).unwrap_or_default())]
    Timeout {
        /// The configured round timeout.
        timeout_ms: u64,
        /// Where the round hung, when known.
        where_it_stuck: Option<String>,
    },

    /// A block failed to compile — **no block ran** (D2).
    #[error("compile_error in block #{index}: {message}")]
    CompileError {
        /// 0-based block index.
        index: usize,
        /// Compiler/parser message.
        message: String,
    },

    /// A block raised an uncaught exception; later blocks did not run (D4).
    #[error("error in block #{index} ({kind}): {message}")]
    CellError {
        /// 0-based block index.
        index: usize,
        /// Exception class name.
        kind: String,
        /// Message / traceback tail for the model.
        message: String,
    },

    /// Policy held a side-effecting call; the step halted (D4).
    #[error(
        "policy held {method} ({cap}) as {decision}{}; step halted",
        .reason.as_deref().map(|r| format!(": {r}")).unwrap_or_default()
    )]
    PolicyHold {
        /// The held method.
        method: String,
        /// Coarse capability class.
        cap: String,
        /// What policy answered (`deny` / `ask`).
        decision: PolicyDecision,
        /// Where in the step it happened.
        cell_index: usize,
        /// Why the hold came out this way when there is more to say than the
        /// decision itself ("consent refused", an interaction that could not
        /// be answered) — the model-visible message carries it.
        reason: Option<String>,
    },

    /// Journal write failed — the action is aborted (fail-closed).
    #[error("journal failed: {0}")]
    Journal(String),

    /// Worker channel/protocol failure.
    #[error("worker error: {0}")]
    Worker(String),
}
