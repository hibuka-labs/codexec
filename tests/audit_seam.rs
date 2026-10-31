//! The worker-effect audit seam (layer 2): pure-Python effects used to leave
//! the journal blind (the dogfood gap). The PEP 578 hook in the worker turns
//! every mediated stdlib event into one call row at the same chokepoint pack
//! calls use — and a denied event blocks the effect itself (fail-closed).
//! Residual holes (ctypes calls past the bind point, `os.stat`-level reads)
//! are documented in codexec-design §8.4.

use codexec::{
    Action, ActionEntry, AllowAll, Audited, ClassPolicy, CodeCellExecutor, ExecError,
    ExecutorBuilder, FileJournal, Journal, JournalError, JournalHandle, Limits, Policy,
    PolicyDecision, PythonWorker,
};
use phi_cap::Capability;
use phi_ns::builtin::PhiNsShell;

/// Fails every `record` after `fail_at` rows have landed — a disk that gives
/// out mid-sequence.
struct FailAfterJournal {
    file: FileJournal,
    written: usize,
    fail_at: usize,
}

impl Journal for FailAfterJournal {
    fn record(&mut self, entry: ActionEntry) -> Result<(), JournalError> {
        if self.written >= self.fail_at {
            return Err(JournalError::Encode("journal disk full (test)".into()));
        }
        self.file.record(entry)?;
        self.written += 1;
        Ok(())
    }
}

async fn executor_with(
    journal: Box<dyn Journal + Send>,
    policy: impl Policy + 'static,
) -> CodeCellExecutor<PythonWorker> {
    ExecutorBuilder::new(JournalHandle::new(journal))
        .with_policy(policy)
        .with_ns(PhiNsShell::builtin())
        .build(|registry| PythonWorker::spawn(registry, Limits::default()))
        .await
        .expect("engine assembles")
}

fn rows(path: &std::path::Path) -> Vec<ActionEntry> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("journal row parses"))
        .collect()
}

fn calls(rows: &[ActionEntry]) -> Vec<&ActionEntry> {
    rows.iter()
        .filter(|r| matches!(r.audited, Audited::Call { .. }))
        .collect()
}

fn call_fns(rows: &[ActionEntry]) -> Vec<&str> {
    let mut names: Vec<&str> = calls(rows)
        .iter()
        .map(|c| match &c.audited {
            Audited::Call { fn_name, .. } => fn_name.as_str(),
            other => panic!("expected a call row, got {other:?}"),
        })
        .collect();
    names.sort_unstable();
    names
}

fn cell(intent: &str, code: String) -> Action {
    Action::CodeCell {
        intent: intent.into(),
        code,
    }
}

fn write_cell(path: &std::path::Path, payload: &str) -> Action {
    cell(
        "write a file",
        format!(
            "from pathlib import Path; Path({:?}).write_text({:?})",
            path.display().to_string(),
            payload
        ),
    )
}

fn assert_facts(row: &ActionEntry, want_fn: &str, want_cap: Capability) {
    match &row.audited {
        Audited::Call {
            capability,
            fn_name,
            decision,
            result,
            capture_id,
            ..
        } => {
            assert_eq!(fn_name, want_fn, "{row:?}");
            assert_eq!(*capability, want_cap, "{row:?}");
            assert_eq!(*decision, PolicyDecision::Allow, "{row:?}");
            assert_eq!(*result, codexec::ActionOutcome::Dispatched, "{row:?}");
            assert_eq!(*capture_id, None, "audit rows never mint captures");
        }
        other => panic!("expected a call row, got {other:?}"),
    }
}

/// The dogfood shape (pure Python write + rename) now leaves effect rows —
/// one per mediated stdlib event, classified under the one vocabulary.
#[tokio::test]
async fn a_pathlib_write_and_rename_leave_their_mediated_rows() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let mut executor = executor_with(
        Box::new(FileJournal::open(&journal_path).unwrap()),
        AllowAll,
    )
    .await;

    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    let obs = executor
        .execute(vec![
            write_cell(&a, "one"),
            cell(
                "rename",
                format!(
                    "import os; os.rename({:?}, {:?})",
                    a.display().to_string(),
                    b.display().to_string()
                ),
            ),
        ])
        .await;
    assert!(obs.error.is_none(), "{obs:?}");

    let rows = rows(&journal_path);
    assert_eq!(
        rows.iter()
            .filter(|r| matches!(r.audited, Audited::Cell { .. }))
            .count(),
        2,
        "{rows:?}"
    );
    // The pathlib import in the first cell leaves nothing; the effects do.
    assert_eq!(call_fns(&rows), ["open", "os.rename"], "{rows:?}");
    assert_facts(calls(&rows)[0], "open", Capability::WriteFs);
    assert_facts(calls(&rows)[1], "os.rename", Capability::WriteFs);
    assert_eq!(std::fs::read_to_string(&b).unwrap(), "one", "artifact");
    assert!(!a.exists(), "rename moved it");
}

/// Reads are mediated too, and classified `ReadFs` — the `open` row's class
/// splits on the hook's read/write decode.
#[tokio::test]
async fn a_read_open_is_classified_readfs() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let mut executor = executor_with(
        Box::new(FileJournal::open(&journal_path).unwrap()),
        AllowAll,
    )
    .await;

    let p = dir.path().join("in.txt");
    std::fs::write(&p, "payload").unwrap();
    let obs = executor
        .execute(vec![cell(
            "read",
            format!("print(open({:?}).read())", p.display().to_string()),
        )])
        .await;
    assert!(obs.error.is_none(), "{obs:?}");
    assert!(obs.stdout.contains("payload"), "{obs:?}");

    let rows = rows(&journal_path);
    assert_eq!(call_fns(&rows), ["open"], "{rows:?}");
    assert_facts(calls(&rows)[0], "open", Capability::ReadFs);
}

/// Effect-level 能拦: a denied write is blocked at the call site — the file
/// never appears — and the step halts on the policy hold, not on the raise.
#[tokio::test]
async fn a_denied_write_blocks_the_effect_and_holds_the_step() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let policy =
        ClassPolicy::new(PolicyDecision::Allow).with(Capability::WriteFs, PolicyDecision::Deny);
    let mut executor =
        executor_with(Box::new(FileJournal::open(&journal_path).unwrap()), policy).await;

    let a = dir.path().join("a.txt");
    let obs = executor.execute(vec![write_cell(&a, "one")]).await;
    match &obs.error {
        Some(ExecError::PolicyHold {
            method,
            cap,
            decision,
            cell_index,
            reason: _,
        }) => {
            assert_eq!(method, "open", "{obs:?}");
            assert_eq!(cap, "write_fs", "{obs:?}");
            assert_eq!(*decision, PolicyDecision::Deny, "{obs:?}");
            assert_eq!(*cell_index, 0, "{obs:?}");
        }
        other => panic!("expected a policy hold, got {other:?}"),
    }
    assert!(!a.exists(), "the effect never ran");

    let rows = rows(&journal_path);
    assert_eq!(call_fns(&rows), ["open"], "{rows:?}");
    match &calls(&rows)[0].audited {
        Audited::Call {
            capability,
            decision,
            result,
            ..
        } => {
            assert_eq!(*capability, Capability::WriteFs, "{rows:?}");
            assert_eq!(*decision, PolicyDecision::Deny, "{rows:?}");
            assert_eq!(*result, codexec::ActionOutcome::Blocked, "{rows:?}");
        }
        other => panic!("expected a call row, got {other:?}"),
    }
}

/// Import machinery is plumbing: loading modules opens plenty of files and
/// must not flood the ledger (nor break under its own mediation).
#[tokio::test]
async fn import_machinery_noise_leaves_no_rows() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let mut executor = executor_with(
        Box::new(FileJournal::open(&journal_path).unwrap()),
        AllowAll,
    )
    .await;

    let obs = executor
        .execute(vec![cell(
            "import libraries",
            "import csv, email, json, xml.etree.ElementTree".into(),
        )])
        .await;
    assert!(obs.error.is_none(), "{obs:?}");

    let rows = rows(&journal_path);
    assert_eq!(
        rows.iter()
            .filter(|r| matches!(r.audited, Audited::Cell { .. }))
            .count(),
        1,
        "{rows:?}"
    );
    assert!(calls(&rows).is_empty(), "{rows:?}");
}

/// ctypes binds are mediated and sit under `Process`: past the bind point a
/// ctypes call is arbitrary native code (the documented residual hole).
#[tokio::test]
async fn loading_a_library_through_ctypes_is_a_process_row() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let mut executor = executor_with(
        Box::new(FileJournal::open(&journal_path).unwrap()),
        AllowAll,
    )
    .await;

    let obs = executor
        .execute(vec![cell(
            "load native code",
            "import ctypes; ctypes.CDLL(None)".into(),
        )])
        .await;
    assert!(obs.error.is_none(), "{obs:?}");

    // Two real loads: `import ctypes` itself binds the process image
    // (`pythonapi = PyDLL(None)` in its module body), then CDLL(None).
    // No `ctypes.dlsym` rows — the namespace snapshot must not poke
    // `__getattr__` (ctypes resolves any attribute as a symbol lookup).
    let rows = rows(&journal_path);
    assert_eq!(
        call_fns(&rows),
        ["ctypes.dlopen", "ctypes.dlopen"],
        "{rows:?}"
    );
    for call in calls(&rows) {
        assert_facts(call, "ctypes.dlopen", Capability::Process);
    }
}

/// CPython's error rendering fetches source for compile pseudo-filenames
/// (a failed cell's traceback caret parse opens `<unknown>`) — that is
/// plumbing, not an effect, and must leave no rows.
#[tokio::test]
async fn an_erroring_cells_traceback_leaves_no_noise_rows() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let mut executor = executor_with(
        Box::new(FileJournal::open(&journal_path).unwrap()),
        AllowAll,
    )
    .await;

    let obs = executor
        .execute(vec![cell("explode", "raise RuntimeError(\"boom\")".into())])
        .await;
    assert!(
        matches!(obs.error, Some(ExecError::CellError { .. })),
        "{obs:?}"
    );

    let rows = rows(&journal_path);
    assert_eq!(
        rows.iter()
            .filter(|r| matches!(r.audited, Audited::Cell { .. }))
            .count(),
        1,
        "{rows:?}"
    );
    assert!(calls(&rows).is_empty(), "{rows:?}");
}

/// Same for the D2 compile-failure path: the SyntaxError fetch on `<cell N>`
/// is an artifact, and the written prefix is pure attempt accounting.
#[tokio::test]
async fn a_compile_error_leaves_only_cell_rows() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let mut executor = executor_with(
        Box::new(FileJournal::open(&journal_path).unwrap()),
        AllowAll,
    )
    .await;

    let obs = executor
        .execute(vec![
            write_cell(&dir.path().join("a.txt"), "one"),
            cell("bad syntax", "def (".into()),
        ])
        .await;
    assert!(
        matches!(obs.error, Some(ExecError::CompileError { index: 1, .. })),
        "{obs:?}"
    );

    let rows = rows(&journal_path);
    assert_eq!(
        rows.iter()
            .filter(|r| matches!(r.audited, Audited::Cell { .. }))
            .count(),
        2,
        "{rows:?}"
    );
    assert!(calls(&rows).is_empty(), "{rows:?}");
    assert!(!dir.path().join("a.txt").exists(), "D2: no block ran");
}

/// Fail-closed at the effect, not just at the cell: when the journal cannot
/// take the mediated row, the effect refuses to run.
#[tokio::test]
async fn a_broken_journal_refuses_mediated_effects_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let journal = FailAfterJournal {
        file: FileJournal::open(&journal_path).unwrap(),
        written: 0,
        fail_at: 1, // the cell row lands; the `open` row does not
    };
    let mut executor = executor_with(Box::new(journal), AllowAll).await;

    let a = dir.path().join("a.txt");
    let obs = executor.execute(vec![write_cell(&a, "one")]).await;
    match &obs.error {
        Some(ExecError::CellError { kind, message, .. }) => {
            assert_eq!(kind, "RuntimeError", "{obs:?}");
            assert!(message.contains("journal"), "{obs:?}");
        }
        other => panic!("expected the effect to refuse, got {other:?}"),
    }
    assert!(!a.exists(), "no row, no effect — fail-closed");
    assert_eq!(rows(&journal_path).len(), 1, "only the cell row landed");
}
