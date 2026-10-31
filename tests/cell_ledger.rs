//! The cell ledger (audit seam layer 1): every submitted cell lands in the
//! journal write-ahead — the dogfood gap was pure Python effects leaving
//! zero rows (phimint `notes/code-cell-dogfood.md`). The invariant under
//! test: **every cell leaves a row whatever it does**, call rows stay the
//! effect-level seam, and a broken journal aborts the step (fail-closed).

use codexec::{
    Action, ActionEntry, AllowAll, Audited, CodeCellExecutor, ExecError, ExecutorBuilder,
    FileJournal, Journal, JournalError, JournalHandle, Limits, PythonWorker,
};
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

async fn executor_with(journal: Box<dyn Journal + Send>) -> CodeCellExecutor<PythonWorker> {
    ExecutorBuilder::new(JournalHandle::new(journal))
        .with_policy(AllowAll)
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

fn cells(rows: &[ActionEntry]) -> Vec<&ActionEntry> {
    rows.iter()
        .filter(|r| matches!(r.audited, Audited::Cell { .. }))
        .collect()
}

fn calls(rows: &[ActionEntry]) -> Vec<&ActionEntry> {
    rows.iter()
        .filter(|r| matches!(r.audited, Audited::Call { .. }))
        .collect()
}

fn write_cell(path: &std::path::Path, payload: &str) -> Action {
    // Pure Python FS work — the dogfood bypass shape (open/pathlib, no
    // host_call). Whatever it does, the cell must still leave a row.
    Action::CodeCell {
        intent: "write a file".into(),
        code: format!(
            "from pathlib import Path; Path({:?}).write_text({:?})",
            path.display().to_string(),
            payload
        ),
    }
}

#[tokio::test]
async fn pure_python_cells_leave_cell_rows_and_mediated_call_rows() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let mut executor = executor_with(Box::new(FileJournal::open(&journal_path).unwrap())).await;

    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    let obs = executor
        .execute(vec![write_cell(&a, "one"), write_cell(&b, "two")])
        .await;
    assert!(obs.error.is_none(), "{obs:?}");

    // Account-vs-artifact: two effects, two cell rows — and since the worker
    // audit hook (layer 2), one mediated `open` row each. The import in the
    // cell leaves nothing: import machinery is plumbing, not an effect.
    let rows = rows(&journal_path);
    assert_eq!(cells(&rows).len(), 2, "{rows:?}");
    let calls = calls(&rows);
    assert_eq!(calls.len(), 2, "{rows:?}");
    for call in &calls {
        match &call.audited {
            Audited::Call {
                fn_name,
                capability,
                decision,
                result,
                ..
            } => {
                assert_eq!(fn_name, "open", "{rows:?}");
                assert_eq!(*capability, phi_cap::Capability::WriteFs, "{rows:?}");
                assert_eq!(*decision, codexec::PolicyDecision::Allow, "{rows:?}");
                assert_eq!(*result, codexec::ActionOutcome::Dispatched, "{rows:?}");
            }
            other => panic!("expected a call row, got {other:?}"),
        }
    }
    assert_eq!(
        std::fs::read_to_string(&a).unwrap(),
        "one",
        "artifact one exists"
    );
    assert_eq!(
        std::fs::read_to_string(&b).unwrap(),
        "two",
        "artifact two exists"
    );
}

#[tokio::test]
async fn mixed_step_reconciles_cells_plus_calls() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let mut executor = executor_with(Box::new(FileJournal::open(&journal_path).unwrap())).await;

    let a = dir.path().join("a.txt");
    let obs = executor
        .execute(vec![
            write_cell(&a, "one"),
            Action::CodeCell {
                intent: "shout".into(),
                code: "sh.run(\"echo hello\")".into(),
            },
        ])
        .await;
    assert!(obs.error.is_none(), "{obs:?}");
    assert!(obs.stdout.contains("hello"), "{obs:?}");

    let rows = rows(&journal_path);
    assert_eq!(cells(&rows).len(), 2, "{rows:?}");
    let calls = calls(&rows);
    // One mediated `open` (the pathlib write) + one host call (`sh.run`).
    assert_eq!(calls.len(), 2, "{rows:?}");
    let mut names: Vec<&str> = calls
        .iter()
        .map(|c| match &c.audited {
            Audited::Call { fn_name, .. } => fn_name.as_str(),
            other => panic!("expected a call row, got {other:?}"),
        })
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["open", "sh.run"], "{rows:?}");
    assert!(std::fs::read_to_string(&a).unwrap() == "one", "artifact");
}

#[tokio::test]
async fn journal_failure_aborts_the_step_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let journal = FailAfterJournal {
        file: FileJournal::open(&journal_path).unwrap(),
        written: 0,
        fail_at: 0,
    };
    let mut executor = executor_with(Box::new(journal)).await;

    let a = dir.path().join("a.txt");
    let obs = executor.execute(vec![write_cell(&a, "one")]).await;
    assert!(
        matches!(obs.error, Some(ExecError::Journal(_))),
        "the step dies on the journal: {obs:?}"
    );
    assert!(!a.exists(), "no row, no run — fail-closed");
    assert_eq!(rows(&journal_path).len(), 0, "{:?}", rows(&journal_path));
}

#[tokio::test]
async fn a_mid_sequence_journal_failure_leaves_only_attempt_rows() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let journal = FailAfterJournal {
        file: FileJournal::open(&journal_path).unwrap(),
        written: 0,
        fail_at: 1,
    };
    let mut executor = executor_with(Box::new(journal)).await;

    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    let obs = executor
        .execute(vec![write_cell(&a, "one"), write_cell(&b, "two")])
        .await;
    assert!(
        matches!(obs.error, Some(ExecError::Journal(_))),
        "the step dies on the journal: {obs:?}"
    );
    // The written prefix stands as submitted attempts; the step error is the
    // cancellation record. Nothing ran — neither artifact exists.
    let rows = rows(&journal_path);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(matches!(rows[0].audited, Audited::Cell { .. }), "{rows:?}");
    assert!(!a.exists() && !b.exists(), "the round never dispatched");
}
