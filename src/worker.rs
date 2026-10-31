//! [`Worker`] — the cross-cell execution environment (codexec-design §4–§6).
//!
//! One worker = one resident interpreter: globals, imports, object identity,
//! and cwd survive across cells (D1). That persistence is exactly what makes
//! this an engine rather than a script runner — and what makes a crash costly
//! (references die with the process; see `lifecycle`).
//!
//! The worker also implements [`phi_ns::WorkerSink`] — capability packs
//! install through it, so `phi-ns` never depends on this crate.

use crate::observation::ExecError;
use crate::protocol::BlockSpec;
use async_trait::async_trait;
use phi_ns::{NsObject, WorkerSink};

/// One finished block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockOutcome {
    /// 0-based block index.
    pub index: usize,
    /// Captured stdout (before engine-level quota accounting).
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
    /// Uncaught exception, if any.
    pub error: Option<BlockError>,
    /// `_NS` entries right after this block (snapshot input).
    pub ns: Vec<NsObject>,
}

/// A block failure, already flattened for the observation stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockError {
    /// Exception class name.
    pub kind: String,
    /// Message.
    pub message: String,
    /// Traceback tail, if any.
    pub traceback: Option<String>,
}

/// What one round produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundResult {
    /// Per-block outcomes, in order.
    pub blocks: Vec<BlockOutcome>,
    /// Wall time of the round.
    pub elapsed_ms: u64,
    /// Top-level failure: compile errors stop the whole round before any
    /// block runs (D2).
    pub compile_error: Option<BlockError>,
    /// Block index of a compile failure.
    pub compile_error_index: Option<usize>,
    /// Block index where execution stopped early (uncaught exception / hold).
    pub stopped_at: Option<usize>,
}

/// The resident execution environment.
#[async_trait]
pub trait Worker: WorkerSink {
    /// Run one round: validate **all** blocks first, then execute in order
    /// (D2). Shared variables across blocks (D4).
    async fn exec(&mut self, blocks: Vec<BlockSpec>) -> Result<RoundResult, ExecError>;

    /// True while the interpreter process is usable.
    fn is_alive(&self) -> bool;

    /// Kill the worker (timeout / crash containment).
    fn kill(&mut self);

    /// Graceful shutdown.
    async fn shutdown(&mut self) -> Result<(), ExecError>;
}
