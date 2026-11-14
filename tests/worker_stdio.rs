//! Stdio contract of the resident Python worker. Regression: worker stderr
//! used to be inherited onto the terminal, so a cell's parse-time
//! `SyntaxWarning` painted over the TUI composer instead of reaching the
//! block's stderr.

use codexec::protocol::{
    HostFrame, RoundConfig, WireLimits, WorkerFrame, decode_worker_line, encode_line,
};
use codexec::{
    AllowAll, BlockSpec, JournalHandle, Limits, MemJournal, NamespaceRegistry, PythonWorker, Worker,
};
use std::io::{BufRead, BufReader, Write};
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

/// The wire's codec is the contract's, not the machine's. Regression
/// (2026-11-14 Windows report): on Windows the text layer of `sys.stdin`
/// decodes the host's UTF-8 frames with the ANSI code page plus
/// `surrogateescape` (CPython initconfig.c: "On Windows, always use
/// surrogateescape by default"), so the em dash every discovery-docs install
/// carries (phi-ns `api_line`: "name — doc") collapsed to a lone surrogate
/// and `compile()` refused it — phimint died at startup with "code-exec
/// engine must assemble". `PYTHONIOENCODING=cp936:surrogateescape` pins that
/// Windows default on any platform; the frames must arrive intact anyway.
#[test]
fn frames_survive_the_windows_stdio_locale() {
    let stub =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/workers/python/stub/worker.py");
    let mut child = std::process::Command::new("python3")
        .arg("-u")
        .arg(&stub)
        .env("PYTHONIOENCODING", "cp936:surrogateescape")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("worker spawns");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let mut send = |frame: &HostFrame| {
        stdin
            .write_all(encode_line(frame).expect("encode").as_bytes())
            .expect("write frame");
        stdin.write_all(b"\n").expect("write newline");
        stdin.flush().expect("flush");
    };

    // The exact shape `install_discovery_docs` evals at every pack install:
    // a doc map whose help text carries the em dash at the position the
    // Windows report failed on.
    let install = "_phi_define_docs({\"sh.run\":\"sh.run — run a shell command; returns Output(stdout, stderr, code)\\ncapability: process:spawn{}\"})";
    send(&HostFrame::Eval {
        request_id: "eval-1".into(),
        code: install.into(),
    });
    send(&HostFrame::Exec {
        request_id: "exec-1".into(),
        blocks: vec![BlockSpec {
            intent: "cjk probe".into(),
            code: "print(\"中文测试 — ok\")".into(),
        }],
        config: RoundConfig {
            limits: WireLimits {
                stdout: 262144,
                stderr: 65536,
                rpc: 65536,
            },
            timeout_ms: 30_000,
        },
    });
    send(&HostFrame::Shutdown {
        request_id: "shutdown".into(),
    });

    let (mut eval_checked, mut exec_checked) = (false, false);
    for line in stdout.lines() {
        let line = line.expect("read frame line");
        match decode_worker_line(&line).expect("valid worker frame") {
            WorkerFrame::Value {
                request_id,
                ok,
                error,
                ..
            } if request_id == "eval-1" => {
                assert!(
                    ok,
                    "install eval must survive a Windows-locale stdin, got: {error:?}"
                );
                eval_checked = true;
            }
            WorkerFrame::BlockResult {
                request_id,
                stdout,
                error,
                ..
            } if request_id == "exec-1" => {
                assert!(error.is_none(), "cjk cell must run clean: {error:?}");
                assert_eq!(
                    stdout, "中文测试 — ok\n",
                    "CJK must round-trip byte-identical (mojibake guard)"
                );
                exec_checked = true;
            }
            WorkerFrame::Done { request_id, .. } if request_id == "shutdown" => break,
            _ => {}
        }
    }
    assert!(eval_checked, "the install eval must answer");
    assert!(exec_checked, "the cjk round must answer");
    let _ = child.wait();
}
