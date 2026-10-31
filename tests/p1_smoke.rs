//! Day-1 acceptance (codexec-design §10): **能跑 · 能拦 · 能记**.
//!
//! These run the real `codexec` binary — the same surface a user drives.

use std::path::PathBuf;
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_codexec")
}

fn run(
    cells: &[&str],
    policy: Option<&str>,
    journal: &std::path::Path,
    cwd: &std::path::Path,
) -> Output {
    let mut cmd = Command::new(bin());
    cmd.current_dir(cwd).arg("run");
    for c in cells {
        cmd.arg("--cell").arg(c);
    }
    if let Some(p) = policy {
        cmd.arg("--policy").arg(p);
    }
    cmd.arg("--journal").arg(journal);
    cmd.output().expect("codexec should run")
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn journal_rows(path: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect()
}

fn temp_dir(tag: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let journal = dir.path().join(format!("{tag}.jsonl"));
    (dir, journal)
}

#[test]
fn smoke_cells_run_print_and_snapshot() {
    // codexec run --cell 'x = 41' --cell 'print(x + 1)' --cell 'sh.run("ls")'
    let (dir, journal) = temp_dir("smoke");
    std::fs::write(dir.path().join("marker.txt"), b"here").unwrap();

    let out = run(
        &["x = 41", "print(x + 1)", "sh.run(\"ls\")"],
        None,
        &journal,
        dir.path(),
    );
    let stdout = stdout_of(&out);
    assert!(
        out.status.success(),
        "run should succeed: {stdout}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 能跑: cell 2 prints 42, cell 3 echoes the shell output.
    assert!(stdout.contains("42"), "cell 2 should print 42:\n{stdout}");
    assert!(
        stdout.contains("marker.txt"),
        "cell 3 should print ls output:\n{stdout}"
    );

    // 观察流末尾有 namespace 快照行.
    let lines: Vec<&str> = stdout.lines().collect();
    let last = lines
        .iter()
        .rev()
        .find(|l| !l.trim().is_empty() && !l.starts_with("journal:"))
        .expect("stream should end with a namespace line");
    assert!(
        last.starts_with("namespace: "),
        "stream should end with a namespace snapshot:\n{stdout}"
    );

    // D1/D3: state survives cells and is summarized honestly.
    assert!(stdout.contains("x(int, 41)"), "x survives cells:\n{stdout}");
    assert!(
        stdout.contains("sh(ShellSdk)"),
        "pack root is visible:\n{stdout}"
    );
    assert!(
        stdout.contains("out(Output, "),
        "last expression is bound to out:\n{stdout}"
    );

    // 能记: one side effect, one call row — and one cell row per submitted
    // cell (write-ahead), so the ledger covers pure-Python cells too.
    let rows = journal_rows(&journal);
    let calls: Vec<&String> = rows
        .iter()
        .filter(|r| r.contains("\"kind\":\"call\""))
        .collect();
    assert_eq!(calls.len(), 1, "sh.run is the only side effect: {rows:?}");
    assert!(calls[0].contains("\"fn_name\":\"sh.run\""), "{}", calls[0]);
    assert!(calls[0].contains("\"decision\":\"allow\""), "{}", calls[0]);
    assert!(
        calls[0].contains("\"result\":\"dispatched\""),
        "{}",
        calls[0]
    );
    let cells: Vec<&String> = rows
        .iter()
        .filter(|r| r.contains("\"kind\":\"cell\""))
        .collect();
    assert_eq!(cells.len(), 3, "one row per cell: {rows:?}");
}

#[test]
fn deny_process_holds_journals_and_halts_the_step() {
    // codexec run --cell 'sh.run("rm -rf …")' --policy deny-process
    let (dir, journal) = temp_dir("deny");
    let target = dir.path().join("should-not-exist");

    let out = run(
        &[
            &format!("sh.run(\"touch {}\")", target.display()),
            "print(\"after\")",
        ],
        Some("deny-process"),
        &journal,
        dir.path(),
    );
    let stdout = stdout_of(&out);

    // 能拦: the effect never ran, the step halted, later cells never ran.
    assert!(
        !out.status.success(),
        "a hold is a non-zero exit:\n{stdout}"
    );
    assert!(
        stdout.contains("policy held"),
        "the hold is visible:\n{stdout}"
    );
    assert!(!target.exists(), "the denied effect must not run");
    assert!(
        !stdout.contains("after"),
        "cells after the hold must not run:\n{stdout}"
    );

    // 能记: exactly one call row, blocked — plus one cell row per submitted
    // cell (the ledger records attempts; the hold is the call row's job).
    let rows = journal_rows(&journal);
    let calls: Vec<&String> = rows
        .iter()
        .filter(|r| r.contains("\"kind\":\"call\""))
        .collect();
    assert_eq!(calls.len(), 1, "one held call, one call row: {rows:?}");
    assert!(calls[0].contains("\"decision\":\"deny\""), "{}", calls[0]);
    assert!(calls[0].contains("\"result\":\"blocked\""), "{}", calls[0]);
    assert!(
        calls[0].contains("\"capability\":\"process\""),
        "{}",
        calls[0]
    );
    let cells: Vec<&String> = rows
        .iter()
        .filter(|r| r.contains("\"kind\":\"cell\""))
        .collect();
    assert_eq!(cells.len(), 2, "one row per submitted cell: {rows:?}");
}

#[test]
fn ask_process_also_suspends() {
    let (dir, journal) = temp_dir("ask");
    let out = run(
        &["sh.run(\"echo hi\")"],
        Some("ask-process"),
        &journal,
        dir.path(),
    );
    let stdout = stdout_of(&out);
    assert!(!out.status.success(), "ask suspends:\n{stdout}");
    assert!(stdout.contains("policy held"), "{stdout}");
    let rows = journal_rows(&journal);
    let calls: Vec<&String> = rows
        .iter()
        .filter(|r| r.contains("\"kind\":\"call\""))
        .collect();
    assert_eq!(calls.len(), 1, "{rows:?}");
    assert!(calls[0].contains("\"decision\":\"ask\""), "{}", calls[0]);
}

#[test]
fn compile_error_runs_no_cell() {
    // D2: validate everything first — one bad block and nothing runs.
    let (dir, journal) = temp_dir("d2");
    let out = run(
        &["print(\"alpha\")", "def broken(:", "print(\"bravo\")"],
        None,
        &journal,
        dir.path(),
    );
    let stdout = stdout_of(&out);
    assert!(
        !out.status.success(),
        "compile error fails the step:\n{stdout}"
    );
    assert!(!stdout.contains("alpha"), "nothing runs on D2:\n{stdout}");
    assert!(!stdout.contains("bravo"), "nothing runs on D2:\n{stdout}");
    assert!(
        stdout.contains("compile_error"),
        "the failure is named:\n{stdout}"
    );
}

#[tokio::test]
async fn escape_hatch_only_when_the_session_is_dead() {
    use codexec::{
        AllowAll, CodeCellExecutor, JournalHandle, Limits, MemJournal, NamespaceRegistry,
        PythonWorker, Worker, escape_hatches,
    };
    use std::sync::Arc;

    let mk = || {
        let registry = Arc::new(NamespaceRegistry::new(
            Arc::new(AllowAll),
            JournalHandle::new(Box::new(MemJournal::default())),
        ));
        (registry.clone(), registry)
    };

    // Live session: the model writes code, no raw-command hatch.
    let (registry, reg_for_spawn) = mk();
    let worker =
        PythonWorker::spawn(Arc::clone(&registry), Limits::default()).expect("worker spawns");
    let executor = CodeCellExecutor::new(
        worker,
        move || PythonWorker::spawn(Arc::clone(&reg_for_spawn), Limits::default()),
        registry,
        Limits::default(),
    );
    assert!(executor.is_session_alive());
    assert!(
        escape_hatches(executor.is_session_alive()).is_empty(),
        "no escape hatch while code can run"
    );

    // Dead session: the hatch appears, and only then.
    let (registry, reg_for_spawn) = mk();
    let mut worker = PythonWorker::spawn(Arc::clone(&registry), Limits::default()).unwrap();
    worker.kill();
    let executor = CodeCellExecutor::new(
        worker,
        move || PythonWorker::spawn(Arc::clone(&reg_for_spawn), Limits::default()),
        registry,
        Limits::default(),
    );
    assert!(!executor.is_session_alive());
    let hatches = escape_hatches(executor.is_session_alive());
    assert_eq!(hatches.len(), 1);
    assert_eq!(hatches[0].name, "execute_command");
}
