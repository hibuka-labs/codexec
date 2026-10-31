//! [`PythonWorker`] — the host half of the resident Python interpreter.
//!
//! One child process per worker; stdin/stdout carry the correlated
//! JSON-lines protocol and nothing else (model `print()` is captured inside
//! the child and returned in `block_result` frames). Capability packs install
//! through [`WorkerSink`]: their host functions land in the registry, their
//! shims land in the child via `eval`, and every shim call comes back through
//! `host_call` — the one point policy + journal run.

use crate::limits::Limits;
use crate::observation::ExecError;
use crate::protocol::{
    BlockSpec, HostFrame, RoundConfig, WireLimits, WorkerFrame, decode_worker_line, encode_line,
};
use crate::registry::NamespaceRegistry;
use crate::worker::{BlockError, BlockOutcome, RoundResult, Worker};
use async_trait::async_trait;
use phi_ns::{HostCall, NsError, NsObject, WorkerSink};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

/// The worker runtime itself (a Python source file, shipped inside the binary).
const STUB: &str = include_str!("stub/worker.py");

/// Host side of one resident Python interpreter.
pub struct PythonWorker {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<Lines<BufReader<ChildStdout>>>,
    registry: Arc<NamespaceRegistry>,
    pending_defines: Vec<String>,
    req_seq: u64,
    alive: bool,
    limits: Limits,
}

impl PythonWorker {
    /// Boot a worker and register nothing yet (see
    /// [`NamespaceRegistry::register_ns`] for the assembly step).
    pub fn spawn(registry: Arc<NamespaceRegistry>, limits: Limits) -> Result<Self, ExecError> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let stub_path =
            std::env::temp_dir().join(format!("codexec-worker-{}-{stamp}.py", std::process::id()));
        std::fs::write(&stub_path, STUB)
            .map_err(|e| ExecError::Worker(format!("could not write worker stub: {e}")))?;

        // Override for exotic installs; `python3` is the platform default.
        let python = std::env::var("CODEXEC_PYTHON").unwrap_or_else(|_| "python3".to_string());
        let (child, stdin, stdout, stderr) = spawn_process(&python, &stub_path)
            .map_err(|e| ExecError::Worker(format!("could not spawn python worker: {e}")))?;
        // Diagnostics stay visible (session log) without the screen damage —
        // the original intent of a shared terminal, none of the painting.
        tokio::spawn(drain_worker_stderr(stderr));

        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout: Some(BufReader::new(stdout).lines()),
            registry,
            pending_defines: Vec::new(),
            req_seq: 0,
            alive: true,
            limits,
        })
    }

    fn next_id(&mut self, phase: &str) -> String {
        self.req_seq += 1;
        format!("{phase}-{}", self.req_seq)
    }

    async fn send(&mut self, frame: &HostFrame) -> Result<(), ExecError> {
        let line = encode_line(frame).map_err(|e| ExecError::Worker(format!("encode: {e}")))?;
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| ExecError::Worker("worker stdin gone".into()))?;
        stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|e| ExecError::Worker(format!("write: {e}")))?;
        stdin
            .write_all(b"\n")
            .await
            .map_err(|e| ExecError::Worker(format!("write: {e}")))?;
        stdin
            .flush()
            .await
            .map_err(|e| ExecError::Worker(format!("flush: {e}")))
    }

    async fn recv(&mut self) -> Result<Option<WorkerFrame>, ExecError> {
        let stdout = self
            .stdout
            .as_mut()
            .ok_or_else(|| ExecError::Worker("worker stdout gone".into()))?;
        loop {
            match stdout.next_line().await {
                Ok(None) => {
                    self.alive = false;
                    return Ok(None);
                }
                Ok(Some(line)) => {
                    if line.trim().is_empty() {
                        continue;
                    }
                    return decode_worker_line(&line).map(Some).map_err(|e| {
                        ExecError::Worker(format!("bad worker frame: {e} (line: {line})"))
                    });
                }
                Err(e) => {
                    self.alive = false;
                    return Err(ExecError::Worker(format!("worker stdout: {e}")));
                }
            }
        }
    }

    /// The single audit seam: answer a shim's call with policy + journal
    /// already applied by the registry. The reserved [`crate::audit::AUDIT_CALL`]
    /// name carries mediated worker effects (layer 2) — decide + journal
    /// here, the effect runs in the worker afterwards.
    async fn answer_host_call(
        &mut self,
        call_id: String,
        fn_name: String,
        args: Vec<serde_json::Value>,
        cell_index: usize,
    ) -> Result<(), ExecError> {
        let result = if fn_name == crate::audit::AUDIT_CALL {
            let outcome = match args.as_slice() {
                [event, payload, rw] => {
                    self.registry
                        .audit(
                            event.as_str().unwrap_or_default(),
                            payload.clone(),
                            rw.as_str().unwrap_or_default(),
                            cell_index,
                        )
                        .await
                }
                _ => Err(NsError::Denied {
                    method: fn_name.clone(),
                    cap: String::new(),
                    reason: "malformed audit call (want event, args, rw)".into(),
                }),
            };
            outcome.map(|()| serde_json::Value::Null)
        } else {
            self.registry.dispatch(&fn_name, args, cell_index).await
        };
        let frame = match result {
            Ok(value) => HostFrame::HostResult {
                call_id,
                ok: true,
                value,
                error: None,
            },
            Err(e) => HostFrame::HostResult {
                call_id,
                ok: false,
                value: serde_json::Value::Null,
                error: Some(e.to_string()),
            },
        };
        self.send(&frame).await
    }

    /// Push queued `register_fn` names into the worker as callable proxies.
    async fn flush_defines(&mut self) -> Result<(), ExecError> {
        if self.pending_defines.is_empty() {
            return Ok(());
        }
        let mut names: Vec<String> = Vec::new();
        for n in std::mem::take(&mut self.pending_defines) {
            if !names.contains(&n) {
                names.push(n);
            }
        }
        let rid = self.next_id("define");
        self.send(&HostFrame::Define {
            request_id: rid.clone(),
            names,
        })
        .await?;
        self.wait_done(&rid, "define", &mut None).await
    }

    /// Wait for one request's `done`, answering any host calls on the way.
    async fn wait_done(
        &mut self,
        rid: &str,
        phase: &str,
        value_slot: &mut Option<Result<String, String>>,
    ) -> Result<(), ExecError> {
        loop {
            match self.recv().await? {
                None => {
                    return Err(ExecError::Worker(format!("worker exited during {phase}")));
                }
                Some(WorkerFrame::HostCall {
                    call_id,
                    fn_name,
                    args,
                    cell_index,
                }) => {
                    self.answer_host_call(call_id, fn_name, args, cell_index)
                        .await?;
                }
                Some(WorkerFrame::Value {
                    request_id,
                    ok,
                    error,
                    repr,
                    ..
                }) if request_id == rid => {
                    *value_slot = Some(if ok {
                        Ok(repr.unwrap_or_default())
                    } else {
                        Err(error.unwrap_or_else(|| "eval failed".into()))
                    });
                }
                Some(WorkerFrame::Done {
                    request_id, error, ..
                }) if request_id == rid => {
                    if let Some(err) = error {
                        return Err(ExecError::Worker(format!(
                            "{phase} failed: {}: {}",
                            err.kind, err.message
                        )));
                    }
                    return Ok(());
                }
                Some(_) => continue,
            }
        }
    }
}

#[async_trait]
impl WorkerSink for PythonWorker {
    fn register_fn(&mut self, name: &str, call: Box<dyn HostCall>) -> Result<(), NsError> {
        self.registry.insert_declared(name, call)?;
        if !self.pending_defines.iter().any(|n| n == name) {
            self.pending_defines.push(name.to_string());
        }
        Ok(())
    }

    async fn eval(&mut self, code: &str) -> Result<(), NsError> {
        self.flush_defines().await.map_err(map_ns)?;
        let rid = self.next_id("eval");
        self.send(&HostFrame::Eval {
            request_id: rid.clone(),
            code: code.to_string(),
        })
        .await
        .map_err(map_ns)?;
        let mut slot: Option<Result<String, String>> = None;
        self.wait_done(&rid, "eval", &mut slot)
            .await
            .map_err(map_ns)?;
        match slot {
            Some(Err(e)) => Err(NsError::Sink(e)),
            _ => Ok(()),
        }
    }

    async fn namespace_entries(&mut self) -> Result<Vec<NsObject>, NsError> {
        self.flush_defines().await.map_err(map_ns)?;
        let rid = self.next_id("ns");
        self.send(&HostFrame::Ns {
            request_id: rid.clone(),
        })
        .await
        .map_err(map_ns)?;
        let mut found: Option<Vec<NsObject>> = None;
        loop {
            match self.recv().await.map_err(map_ns)? {
                None => return Err(NsError::Sink("worker exited during ns".into())),
                Some(WorkerFrame::NsEntries {
                    request_id,
                    entries,
                }) if request_id == rid => {
                    found = Some(
                        entries
                            .into_iter()
                            .map(|e| NsObject {
                                name: e.name,
                                kind: e.kind,
                                repr: e.repr,
                                detail: e.detail,
                            })
                            .collect(),
                    );
                }
                Some(WorkerFrame::HostCall {
                    call_id,
                    fn_name,
                    args,
                    cell_index,
                }) => {
                    self.answer_host_call(call_id, fn_name, args, cell_index)
                        .await
                        .map_err(map_ns)?;
                }
                Some(WorkerFrame::Done { request_id, .. }) if request_id == rid => {
                    return found.ok_or_else(|| NsError::Sink("ns returned no entries".into()));
                }
                Some(_) => continue,
            }
        }
    }
}

/// Spawn the interpreter under the one contract that keeps it off the
/// user's terminal (same as agent-works' MCP client): stdin/stdout carry the
/// protocol and nothing else, stderr is **piped** — never `inherit()`. An
/// inherited stderr paints straight onto the TUI's alternate screen (a cell's
/// parse-time `SyntaxWarning` was observed landing in the composer) and the
/// renderer's diffing never repaints those cells. Returns the stderr handle
/// so the caller can drain it into the log.
fn spawn_process(
    python: &str,
    script: &std::path::Path,
) -> std::io::Result<(Child, ChildStdin, ChildStdout, ChildStderr)> {
    let mut child = Command::new(python)
        .arg("-u")
        .arg(script)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("worker stdin missing"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("worker stdout missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("worker stderr missing"))?;
    Ok((child, stdin, stdout, stderr))
}

/// Drain a worker's stderr into the log, one line per diagnostic.
async fn drain_worker_stderr(stderr: ChildStderr) {
    let mut lines = BufReader::new(stderr).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        tracing::warn!(%line, "codexec python worker stderr");
    }
}

fn map_ns(e: ExecError) -> NsError {
    NsError::Sink(e.to_string())
}

#[async_trait]
impl Worker for PythonWorker {
    async fn exec(&mut self, blocks: Vec<BlockSpec>) -> Result<RoundResult, ExecError> {
        self.flush_defines().await?;
        let rid = self.next_id("exec");
        let config = RoundConfig {
            limits: WireLimits {
                stdout: self.limits.stdout_max,
                stderr: self.limits.stderr_max,
                rpc: self.limits.rpc_max,
            },
            timeout_ms: self.limits.timeout_ms,
        };
        self.send(&HostFrame::Exec {
            request_id: rid.clone(),
            blocks,
            config,
        })
        .await?;

        let mut outcomes: Vec<BlockOutcome> = Vec::new();
        let mut compile_error: Option<BlockError> = None;
        let mut compile_error_index: Option<usize> = None;

        loop {
            match self.recv().await? {
                None => return Err(ExecError::Worker("worker exited mid-round".into())),
                Some(WorkerFrame::BlockResult {
                    request_id,
                    index,
                    stdout,
                    stderr,
                    error,
                    ns,
                }) => {
                    if request_id != rid {
                        continue;
                    }
                    outcomes.push(BlockOutcome {
                        index,
                        stdout,
                        stderr,
                        error: error.map(|e| BlockError {
                            kind: e.kind,
                            message: e.message,
                            traceback: e.traceback,
                        }),
                        ns: ns
                            .into_iter()
                            .map(|e| NsObject {
                                name: e.name,
                                kind: e.kind,
                                repr: e.repr,
                                detail: e.detail,
                            })
                            .collect(),
                    });
                }
                Some(WorkerFrame::HostCall {
                    call_id,
                    fn_name,
                    args,
                    cell_index,
                }) => {
                    self.answer_host_call(call_id, fn_name, args, cell_index)
                        .await?;
                }
                Some(WorkerFrame::Done {
                    request_id,
                    elapsed_ms,
                    error,
                    stopped_at,
                    ..
                }) => {
                    if request_id != rid {
                        continue;
                    }
                    if let Some(err) = error {
                        // A done-level error is the D2 compile failure: nothing
                        // ran, `stopped_at` names the offending block.
                        compile_error_index = stopped_at.or(Some(0));
                        compile_error = Some(BlockError {
                            kind: err.kind,
                            message: err.message,
                            traceback: err.traceback,
                        });
                    }
                    return Ok(RoundResult {
                        blocks: outcomes,
                        elapsed_ms,
                        compile_error,
                        compile_error_index,
                        stopped_at,
                    });
                }
                Some(_) => continue,
            }
        }
    }

    fn is_alive(&self) -> bool {
        self.alive
    }

    fn kill(&mut self) {
        self.alive = false;
        let _ = self.child.start_kill();
        self.stdin = None;
        self.stdout = None;
    }

    async fn shutdown(&mut self) -> Result<(), ExecError> {
        if self.alive {
            let rid = self.next_id("shutdown");
            // Best effort: the child may already be gone.
            let _ = self
                .send(&HostFrame::Shutdown {
                    request_id: rid.clone(),
                })
                .await;
            let mut slot: Option<Result<String, String>> = None;
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                self.wait_done(&rid, "shutdown", &mut slot),
            )
            .await;
            let _ = tokio::time::timeout(Duration::from_secs(2), self.child.wait()).await;
        }
        self.kill();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// Regression (screen corruption): the worker's stderr must come back to
    /// us through a pipe. An inherited stderr hands back no handle at all and
    /// paints its diagnostics onto the TUI's terminal (a cell's parse-time
    /// `SyntaxWarning` was observed landing in the composer).
    #[tokio::test]
    async fn spawn_stderr_is_piped_not_inherited() {
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("probe.py");
        std::fs::write(&script, "import os\nos.write(2, b'FD2LEAK\\n')\n").expect("write probe");
        let (mut child, _stdin, _stdout, stderr) =
            spawn_process("python3", &script).expect("probe spawns");
        let mut seen = Vec::new();
        let mut stderr = stderr;
        stderr.read_to_end(&mut seen).await.expect("drain");
        assert_eq!(seen, b"FD2LEAK\n");
        let _ = child.wait().await;
    }
}
