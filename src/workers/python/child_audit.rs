//! The child-process audit channel (codexec-design §8.4): a Python child the
//! worker spawns auto-installs the same PEP 578 mediation
//! (`stub/sitecustomize.py`, loaded via `PYTHONPATH`) and streams its events
//! here — one Unix-socket connection per child, one inline verdict per event.
//!
//! The seam is the registry's [`NamespaceRegistry::audit`]: same classify →
//! decide → journal write-ahead as every host call, so a child effect lands as
//! a `call` row like any other — and a denial raises **inside the child**,
//! before the effect runs (fail-closed), exactly as in the resident worker.
//!
//! Unix only: the transport is a Unix domain socket. On other platforms the
//! channel is not installed and a child's effects keep the old blind spot
//! (only its parent's `subprocess.Popen` row) — documented, never silent.
//!
//! Residual holes (beyond §8.4): non-Python children (a shell, a binary);
//! children started with `-S` / `-E` / `-I` (no `site`, no `PYTHONPATH`).

use crate::registry::NamespaceRegistry;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

/// One child event on the wire (JSON line, `stub/sitecustomize.py`'s `emit`).
#[derive(serde::Deserialize)]
struct ChildEvent {
    /// Correlates to the verdict.
    id: u64,
    /// The mediated event name (`"open"`).
    event: String,
    /// Event arguments, already JSON-ified by the child hook.
    args: serde_json::Value,
    /// The hook's `open` read/write decode (`""` for non-`open` events).
    #[serde(default)]
    rw: String,
    /// Block the child was spawned under (`PHI_CELL` attribution).
    #[serde(default)]
    cell: usize,
}

/// The listening socket plus its accept task. Dropping stops the channel and
/// removes the socket file.
pub(crate) struct ChildAudit {
    sock_path: PathBuf,
    accept: tokio::task::JoinHandle<()>,
}

impl ChildAudit {
    /// Bind the audit socket inside `dir` and start answering child events.
    ///
    /// Fixed short name: a Unix socket path must fit `sun_path` (~104 bytes on
    /// macOS), and the private directory already carries the unique stamp. A
    /// stale file at the path (directory reuse) is cleared before binding —
    /// `bind` itself refuses an occupied name.
    pub(crate) fn start(registry: Arc<NamespaceRegistry>, dir: &Path) -> std::io::Result<Self> {
        let sock_path = dir.join("audit.sock");
        let _ = std::fs::remove_file(&sock_path);
        let listener = UnixListener::bind(&sock_path)?;
        let accept = tokio::spawn(accept_loop(listener, registry));
        Ok(Self { sock_path, accept })
    }

    /// Where children connect (`PHI_AUDIT_SOCK`).
    pub(crate) fn sock_path(&self) -> &Path {
        &self.sock_path
    }
}

impl Drop for ChildAudit {
    fn drop(&mut self) {
        self.accept.abort();
        let _ = std::fs::remove_file(&self.sock_path);
    }
}

async fn accept_loop(listener: UnixListener, registry: Arc<NamespaceRegistry>) {
    while let Ok((stream, _)) = listener.accept().await {
        let registry = Arc::clone(&registry);
        tokio::spawn(handle(stream, registry));
    }
}

/// One child connection: JSON-lines requests, one inline verdict each. A
/// malformed line closes the connection (that child's next mediated event
/// then fails to reach its verdict and raises there — fail-closed).
async fn handle(stream: UnixStream, registry: Arc<NamespaceRegistry>) {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let Ok(req) = serde_json::from_str::<ChildEvent>(&line) else {
            break;
        };
        let outcome = registry
            .audit(&req.event, req.args, &req.rw, req.cell)
            .await;
        let verdict = match outcome {
            Ok(()) => serde_json::json!({"id": req.id, "ok": true}),
            Err(e) => serde_json::json!({"id": req.id, "ok": false, "error": e.to_string()}),
        };
        let mut out = serde_json::to_string(&verdict).unwrap_or_else(|_| "{\"ok\":false}".into());
        out.push('\n');
        if write.write_all(out.as_bytes()).await.is_err() {
            break;
        }
    }
}
