//! codexec — the CodeAct execution layer: one resident interpreter, capability
//! packs as namespaces, policy + journal at the single host-call seam.
//!
//! Engine only. Domain rules (what is allowed, what a command means) live in
//! the application that composes a [`policy::Policy`] and a [`journal::Journal`]
//! with these parts.

pub mod action;
pub mod artifacts;
pub mod audit;
pub mod escape;
pub mod executor;
pub mod interact;
pub mod journal;
pub mod lifecycle;
pub mod limits;
pub mod observation;
pub mod policy;
pub mod protocol;
pub mod registry;
pub mod worker;
pub mod workers;

pub use action::{Action, ParseError, parse_actions};
pub use artifacts::{
    ArtifactHub, ArtifactRef, ArtifactStore, SUMMARY_MAX, artifact_line, summary_of,
};
pub use escape::{CommandOutput, EXECUTE_COMMAND, EscapeHatch, escape_hatches, execute_command};
pub use executor::{CodeCellExecutor, ExecutorBuilder};
pub use interact::{ConsentRequest, InteractionBridge, SuspensionClock, SuspensionGuard};
pub use journal::{
    ActionEntry, ActionOutcome, Audited, FileJournal, Journal, JournalError, JournalHandle,
    MemJournal, cell_entry_for, entry_for,
};
pub use lifecycle::{Lifecycle, SessionState};
pub use limits::{Limits, RoundBudget};
pub use observation::{CellEvent, ExecError, Observation};
pub use policy::{AllowAll, CallCtx, ClassPolicy, DenyAll, MethodPolicy, Policy, PolicyDecision};
pub use protocol::BlockSpec;
pub use registry::{NamespaceRegistry, RegisteredFn, ScopedImage};
pub use worker::{BlockError, BlockOutcome, RoundResult, Worker};
pub use workers::PythonWorker;
