//! Stdio contract of the resident Python worker. Regression: worker stderr
//! used to be inherited onto the terminal, so a cell's parse-time
//! `SyntaxWarning` painted over the TUI composer instead of reaching the
//! block's stderr.

use codexec::{
    AllowAll, BlockSpec, JournalHandle, Limits, MemJournal, NamespaceRegistry, PythonWorker, Worker,
};
use std::sync::Arc;

fn spawn() -> PythonWorker {
    let registry = Arc::new(NamespaceRegistry::new(
        Arc::new(AllowAll),
        JournalHandle::new(Box::new(MemJournal::default())),
    ));
    PythonWorker::spawn(registry, Limits::default()).expect("worker spawns")
}

/// Parse-time warnings (invalid escapes et al.) belong to the block that
/// produced them: the D2 validation pass runs outside the per-block capture,
/// so they must be folded into that block's stderr rather than leaked.
#[tokio::test]
async fn parse_warnings_land_in_block_stderr() {
    let mut worker = spawn();
    let round = worker
        .exec(vec![BlockSpec {
            intent: "escape probe".into(),
            code: "x = \"\\(\"".into(),
        }])
        .await
        .expect("round runs");
    assert!(round.compile_error.is_none(), "a warning is not an error");
    assert_eq!(round.blocks.len(), 1);
    let stderr = &round.blocks[0].stderr;
    assert!(
        stderr.contains("<cell 0>:") && stderr.contains("SyntaxWarning"),
        "block stderr should carry the parse warning, got: {stderr:?}"
    );
    worker.shutdown().await.expect("shutdown");
}

/// fd-2 writes from inside a cell (grandchild processes, interpreter
/// diagnostics) must not disturb the protocol round — the host drains them
/// to the log instead of letting them reach the terminal.
#[tokio::test]
async fn fd2_writes_do_not_disturb_the_round() {
    let mut worker = spawn();
    let round = worker
        .exec(vec![BlockSpec {
            intent: "fd2 probe".into(),
            code: "import os\nos.write(2, b'FD2LEAK')\nprint('ok')".into(),
        }])
        .await
        .expect("round runs");
    assert!(round.compile_error.is_none());
    assert_eq!(round.blocks.len(), 1);
    assert!(
        round.blocks[0].stdout.contains("ok"),
        "stdout: {:?}",
        round.blocks[0].stdout
    );
    assert!(round.blocks[0].error.is_none());
    worker.shutdown().await.expect("shutdown");
}
