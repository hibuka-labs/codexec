//! Policy + journal seam (codexec-design §8.1): the hook is one place, the
//! audit row is written write-ahead, and a hold halts the step.

use codexec::{
    Action, ActionEntry, Audited, ClassPolicy, CodeCellExecutor, ExecError, ExecutorBuilder,
    FileJournal, JournalHandle, Limits, Observation, Policy, PolicyDecision, PythonWorker,
};
use phi_cap::Capability;
use phi_ns::builtin::PhiNsShell;
use std::sync::Arc;

async fn executor_with(
    policy: Arc<dyn Policy>,
    journal_path: &std::path::Path,
) -> CodeCellExecutor<PythonWorker> {
    let journal = FileJournal::open(journal_path).expect("journal opens");
    ExecutorBuilder::new(JournalHandle::new(Box::new(journal)))
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

fn call_rows(rows: &[ActionEntry]) -> Vec<&ActionEntry> {
    rows.iter()
        .filter(|r| matches!(r.audited, Audited::Call { .. }))
        .collect()
}

fn cell_rows(rows: &[ActionEntry]) -> Vec<&ActionEntry> {
    rows.iter()
        .filter(|r| matches!(r.audited, Audited::Cell { .. }))
        .collect()
}

fn assert_call(
    row: &ActionEntry,
    want_name: &str,
    want_cap: Capability,
    want_decision: PolicyDecision,
    want_result: codexec::ActionOutcome,
) {
    let Audited::Call {
        capability,
        fn_name,
        decision,
        result,
        ..
    } = &row.audited
    else {
        panic!("expected a call row, got {row:?}");
    };
    assert_eq!(fn_name, want_name, "{row:?}");
    assert_eq!(*capability, want_cap, "{row:?}");
    assert_eq!(*decision, want_decision, "{row:?}");
    assert_eq!(*result, want_result, "{row:?}");
}

async fn run_one(executor: &mut CodeCellExecutor<PythonWorker>, code: &str) -> Observation {
    executor
        .execute(vec![Action::CodeCell {
            intent: String::new(),
            code: code.to_string(),
        }])
        .await
}

#[tokio::test]
async fn deny_process_halts_and_leaves_exactly_one_blocked_row() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let policy =
        ClassPolicy::new(PolicyDecision::Allow).with(Capability::Process, PolicyDecision::Deny);
    let mut executor = executor_with(Arc::new(policy), &journal_path).await;

    let obs = run_one(&mut executor, "sh.run(\"echo hi\")").await;
    assert!(obs.is_policy_hold(), "{obs:?}");
    match &obs.error {
        Some(ExecError::PolicyHold {
            method,
            cap,
            decision,
            ..
        }) => {
            assert_eq!(method, "sh.run");
            assert_eq!(cap, "process");
            assert_eq!(*decision, PolicyDecision::Deny);
        }
        other => panic!("expected a policy hold, got {other:?}"),
    }
    assert!(!obs.stdout.contains("hi"), "the effect never ran");

    let rows = rows(&journal_path);
    let calls = call_rows(&rows);
    assert_eq!(calls.len(), 1, "one held call, one call row: {rows:?}");
    assert_call(
        calls[0],
        "sh.run",
        Capability::Process,
        PolicyDecision::Deny,
        codexec::ActionOutcome::Blocked,
    );
    assert_eq!(
        cell_rows(&rows).len(),
        1,
        "one row per submitted cell: {rows:?}"
    );
}

#[tokio::test]
async fn ask_suspends_with_an_ask_row() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let policy =
        ClassPolicy::new(PolicyDecision::Allow).with(Capability::Process, PolicyDecision::Ask);
    let mut executor = executor_with(Arc::new(policy), &journal_path).await;

    let obs = run_one(&mut executor, "sh.run(\"echo hi\")").await;
    assert!(obs.is_policy_hold(), "{obs:?}");
    let rows = rows(&journal_path);
    let calls = call_rows(&rows);
    assert_eq!(calls.len(), 1, "{rows:?}");
    assert_call(
        calls[0],
        "sh.run",
        Capability::Process,
        PolicyDecision::Ask,
        codexec::ActionOutcome::Blocked,
    );
}

#[tokio::test]
async fn allow_dispatches_and_journals_the_side_effect() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let mut executor = executor_with(Arc::new(codexec::AllowAll), &journal_path).await;

    let obs = run_one(&mut executor, "sh.run(\"echo hi\")").await;
    assert!(obs.error.is_none(), "{obs:?}");
    assert!(obs.stdout.contains("hi"), "{obs:?}");

    let rows = rows(&journal_path);
    let calls = call_rows(&rows);
    assert_eq!(calls.len(), 1, "{rows:?}");
    assert_call(
        calls[0],
        "sh.run",
        Capability::Process,
        PolicyDecision::Allow,
        codexec::ActionOutcome::Dispatched,
    );
}

#[tokio::test]
async fn a_hold_in_the_middle_of_a_step_stops_the_later_cells() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let policy =
        ClassPolicy::new(PolicyDecision::Allow).with(Capability::Process, PolicyDecision::Deny);
    let mut executor = executor_with(Arc::new(policy), &journal_path).await;

    let obs = executor
        .execute(vec![
            Action::CodeCell {
                intent: String::new(),
                code: "sh.run(\"echo one\")".into(),
            },
            Action::CodeCell {
                intent: String::new(),
                code: "print(\"two\")".into(),
            },
        ])
        .await;
    assert!(obs.is_policy_hold(), "{obs:?}");
    assert!(
        !obs.stdout.contains("two"),
        "later cells do not run: {obs:?}"
    );

    // Both cells were submitted write-ahead (attempt rows); only the first
    // executed — "did it run" lives in the observation, not the row. The one
    // held call journals its own blocked row.
    let rows = rows(&journal_path);
    let calls = call_rows(&rows);
    assert_eq!(calls.len(), 1, "the held call journaled: {rows:?}");
    assert_call(
        calls[0],
        "sh.run",
        Capability::Process,
        PolicyDecision::Deny,
        codexec::ActionOutcome::Blocked,
    );
    assert_eq!(cell_rows(&rows).len(), 2, "one row per submitted cell");
}
