//! Worker subprocess protocol — correlated JSON lines (codexec-design §9).
//!
//! One line per frame on stdin/stdout; every request carries a `request_id`
//! and late/foreign frames are dropped. The worker's real `print()` output is
//! captured per block — process stdout carries protocol frames only.
//!
//! `host_call` / `host_result` is the single hook point: a capability shim
//! calls `_phi_call(name, args)`, the host answers with policy + journal
//! already applied.

use serde::{Deserialize, Serialize};

/// One code block on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockSpec {
    /// The model's intent note.
    pub intent: String,
    /// Source in the worker's language.
    pub code: String,
}

/// Round configuration (limits are advisory to the worker's capture layer;
/// the engine's per-round budget is authoritative).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundConfig {
    /// Output ceilings, bytes.
    pub limits: WireLimits,
    /// Hard round timeout, milliseconds.
    pub timeout_ms: u64,
}

/// The limit numbers on the wire (codexec-design §9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireLimits {
    /// stdout ceiling.
    pub stdout: usize,
    /// stderr ceiling.
    pub stderr: usize,
    /// Single frame ceiling.
    pub rpc: usize,
}

/// host → worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostFrame {
    /// Run one round of blocks: validate all, then execute in order (D2).
    Exec {
        /// Correlation id.
        request_id: String,
        /// Blocks of this step, in order.
        blocks: Vec<BlockSpec>,
        /// Round config.
        config: RoundConfig,
    },
    /// Evaluate source in the worker namespace (pack install).
    Eval {
        /// Correlation id.
        request_id: String,
        /// Source to run.
        code: String,
    },
    /// Materialize callable proxies for registered host functions.
    Define {
        /// Correlation id.
        request_id: String,
        /// Dotted function names (`"b.click"`).
        names: Vec<String>,
    },
    /// Read the worker's `_NS` back.
    Ns {
        /// Correlation id.
        request_id: String,
    },
    /// Stop the worker.
    Shutdown {
        /// Correlation id.
        request_id: String,
    },
    /// Answer to a [`WorkerFrame::HostCall`].
    HostResult {
        /// Correlates to the call.
        call_id: String,
        /// Whether the call succeeded.
        ok: bool,
        /// Return value (JSON) when `ok`.
        value: serde_json::Value,
        /// Error text when not `ok` — raised into the cell.
        error: Option<String>,
    },
}

/// A cell failure on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireError {
    /// Exception class name (`"SyntaxError"`, `"RuntimeError"`, …).
    pub kind: String,
    /// Message.
    pub message: String,
    /// Traceback tail, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traceback: Option<String>,
}

/// One `_NS` entry on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireNsEntry {
    /// Binding name.
    pub name: String,
    /// Type name.
    pub kind: String,
    /// Truncated repr.
    pub repr: String,
    /// `_phi_summary_()` hint, if the object provides one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// worker → host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkerFrame {
    /// One finished block: its captured streams, failure (if any), and the
    /// `_NS` snapshot input right after it ran (sdk-assembly §8).
    BlockResult {
        /// Correlation id.
        request_id: String,
        /// 0-based block index.
        index: usize,
        /// Captured stdout.
        stdout: String,
        /// Captured stderr.
        stderr: String,
        /// Uncaught exception, if any — later blocks do not run (D4).
        error: Option<WireError>,
        /// Namespace entries after this block.
        ns: Vec<WireNsEntry>,
    },
    /// Result of [`HostFrame::Eval`].
    Value {
        /// Correlation id.
        request_id: String,
        /// Whether eval succeeded.
        ok: bool,
        /// Repr of the last expression, if any.
        repr: Option<String>,
        /// Error text when not `ok`.
        error: Option<String>,
    },
    /// Result of [`HostFrame::Ns`].
    NsEntries {
        /// Correlation id.
        request_id: String,
        /// Current namespace entries.
        entries: Vec<WireNsEntry>,
    },
    /// A capability shim is calling back into the host — the single audit
    /// hook point.
    HostCall {
        /// Correlates to the [`HostFrame::HostResult`].
        call_id: String,
        /// Declared function name (`"sh.run"`).
        #[serde(rename = "fn")]
        fn_name: String,
        /// Positional arguments.
        args: Vec<serde_json::Value>,
        /// Which block was running.
        cell_index: usize,
    },
    /// A progress tick while a round runs: what a block printed (throttled)
    /// and how long it has been going. The observation itself is atomic to
    /// the model — the trail makes the run legible after it ends.
    Progress {
        /// Correlation id.
        request_id: String,
        /// 0-based block index in flight.
        index: usize,
        /// Milliseconds since round start.
        at_ms: u64,
        /// The tick text (worker-side truncated).
        text: String,
    },
    /// End of one request.
    Done {
        /// Correlation id.
        request_id: String,
        /// 0 on success.
        exit: i32,
        /// Wall time of the request.
        elapsed_ms: u64,
        /// `"exec"` / `"eval"` / `"define"` / `"ns"` / `"shutdown"`.
        phase: String,
        /// Top-level failure (`compile_error` stops everything, D2).
        error: Option<WireError>,
        /// Block index where execution stopped, if it stopped early.
        stopped_at: Option<usize>,
    },
}

/// Encode one frame as a JSON line (no trailing newline).
pub fn encode_line(frame: &impl Serialize) -> Result<String, serde_json::Error> {
    serde_json::to_string(frame)
}

/// Decode one JSON line into a host frame.
pub fn decode_host_line(line: &str) -> Result<HostFrame, serde_json::Error> {
    serde_json::from_str(line)
}

/// Decode one JSON line into a worker frame.
pub fn decode_worker_line(line: &str) -> Result<WorkerFrame, serde_json::Error> {
    serde_json::from_str(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_as_json_lines() {
        let f = HostFrame::HostResult {
            call_id: "c1".into(),
            ok: true,
            value: serde_json::json!({"stdout": "hi", "stderr": "", "code": 0}),
            error: None,
        };
        let line = encode_line(&f).unwrap();
        assert_eq!(decode_host_line(&line).unwrap(), f);

        let w = WorkerFrame::HostCall {
            call_id: "c1".into(),
            fn_name: "sh.run".into(),
            args: vec![serde_json::json!("ls")],
            cell_index: 2,
        };
        let line = encode_line(&w).unwrap();
        assert!(line.contains("\"fn\":\"sh.run\""));
        assert_eq!(decode_worker_line(&line).unwrap(), w);
    }
}
