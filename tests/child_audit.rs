//! The child-process audit channel: a Python child a cell spawns used to
//! leave the ledger blind (only its parent's `subprocess.Popen` row). With
//! `sitecustomize.py` + `PHI_AUDIT_SOCK` the child mediates its own effects at
//! the same chokepoint — a child write is a `call` row, and a denial raises
//! inside the child before the effect runs (fail-closed).
//!
//! Also here: the round's progress trail (what a run looked like while it
//! ran) and the timeout stack dump (where a hung round was).

use codexec::{
    Action, AllowAll, Audited, ClassPolicy, CodeCellExecutor, ExecError, ExecutorBuilder,
    FileJournal, JournalHandle, Limits, PolicyDecision, PythonWorker,
};
use phi_cap::Capability;

async fn executor_with(
    policy: impl codexec::Policy + 'static,
    limits: Limits,
) -> (tempfile::TempDir, CodeCellExecutor<PythonWorker>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let journal = FileJournal::open(dir.path().join("journal.jsonl")).expect("journal opens");
    let executor = ExecutorBuilder::new(JournalHandle::new(Box::new(journal)))
        .with_policy(policy)
        .with_limits(limits)
        .build(move |registry| PythonWorker::spawn(registry, limits))
        .await
        .expect("engine assembles");
    (dir, executor)
}

fn cell(code: String) -> Action {
    Action::CodeCell {
        intent: "test".into(),
        code,
    }
}

fn rows(dir: &tempfile::TempDir) -> Vec<codexec::ActionEntry> {
    std::fs::read_to_string(dir.path().join("journal.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("journal row parses"))
        .collect()
}

/// Call rows matching (fn_name, capability) with their decisions.
fn decisions_on(
    rows: &[codexec::ActionEntry],
    fn_name: &str,
    cap: Capability,
) -> Vec<PolicyDecision> {
    rows.iter()
        .filter_map(|r| match &r.audited {
            Audited::Call {
                fn_name: f,
                capability,
                decision,
                ..
            } if f == fn_name && *capability == cap => Some(*decision),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn child_python_write_lands_in_the_journal() {
    let limits = Limits::default();
    let (dir, mut executor) = executor_with(AllowAll, limits).await;
    let marker = dir.path().join("child_wrote.txt");
    let code = format!(
        "import subprocess, sys\n\
         subprocess.run([sys.executable, '-c', \"open('{marker}', 'w').write('x')\"], check=True)\n",
        marker = marker.display()
    );
    let obs = executor.execute(vec![cell(code)]).await;
    assert!(obs.error.is_none(), "cell ran clean: {:?}", obs.error);

    // The world agrees with the ledger: the file exists...
    assert_eq!(
        std::fs::read_to_string(&marker).expect("marker readable"),
        "x",
        "the child's write happened"
    );
    // ...and the child's `open` is a row — decided, not smuggled.
    let rows = rows(&dir);
    let writes = decisions_on(&rows, "open", Capability::WriteFs);
    assert_eq!(
        writes,
        vec![PolicyDecision::Allow],
        "exactly one write row — the child's, decided at the chokepoint"
    );
}

#[tokio::test]
async fn child_python_write_is_refused_under_read_only_policy() {
    // The sub-agent posture: reads pass, writes refuse — now for children too.
    let policy = ClassPolicy::new(PolicyDecision::Deny)
        .with(Capability::ReadFs, PolicyDecision::Allow)
        .with(Capability::Pure, PolicyDecision::Allow)
        .with(Capability::Process, PolicyDecision::Allow);
    let limits = Limits::default();
    let (dir, mut executor) = executor_with(policy, limits).await;
    let marker = dir.path().join("child_wrote.txt");
    let code = format!(
        "import subprocess, sys\n\
         r = subprocess.run([sys.executable, '-c', \"open('{marker}', 'w').write('x')\"],\n\
         \x20                  capture_output=True, text=True)\n\
         assert r.returncode != 0, 'the child write must be refused'\n",
        marker = marker.display()
    );
    let obs = executor.execute(vec![cell(code)]).await;

    // Fail-closed: no file, and the refusal is in the ledger.
    assert!(
        std::fs::read_to_string(&marker).is_err(),
        "the refused write left nothing behind"
    );
    let rows = rows(&dir);
    let writes = decisions_on(&rows, "open", Capability::WriteFs);
    assert_eq!(
        writes,
        vec![PolicyDecision::Deny],
        "the child's write journals its refusal"
    );
    // The hold outranks the (handled) child failure — same as any refusal.
    assert!(
        obs.is_policy_hold(),
        "the refusal surfaces as the step error"
    );
}

#[tokio::test]
async fn the_worker_mediates_exactly_once() {
    // The resident worker loads `sitecustomize` too (PYTHONPATH is inherited
    // by its children — there is no "children only" env). Its own hook and the
    // child hook must not both mediate the same effect: exactly one row.
    let limits = Limits::default();
    let (dir, mut executor) = executor_with(AllowAll, limits).await;
    let marker = dir.path().join("worker_wrote.txt");
    let code = format!(
        "open({marker:?}, 'w').write('x')\n",
        marker = marker.display().to_string()
    );
    let obs = executor.execute(vec![cell(code)]).await;
    assert!(obs.error.is_none(), "cell ran clean: {:?}", obs.error);
    let rows = rows(&dir);
    let writes = decisions_on(&rows, "open", Capability::WriteFs);
    assert_eq!(
        writes,
        vec![PolicyDecision::Allow],
        "one effect, one row — no double mediation"
    );
}

#[tokio::test]
async fn round_carries_a_progress_trail() {
    let limits = Limits {
        timeout_ms: 3_000,
        ..Limits::default()
    };
    let (_dir, mut executor) = executor_with(AllowAll, limits).await;
    let code = "import time\nprint('hello')\ntime.sleep(1.2)\n".to_string();
    let obs = executor.execute(vec![cell(code)]).await;
    assert!(obs.error.is_none(), "cell ran clean: {:?}", obs.error);
    // The print tick (tee) and the heartbeat tick while it slept.
    assert!(
        obs.progress.iter().any(|l| l.contains("hello")),
        "prints tick the trail: {:?}",
        obs.progress
    );
    assert!(
        obs.progress.iter().any(|l| l.contains("still running")),
        "a silent stretch still ticks: {:?}",
        obs.progress
    );
}

#[tokio::test]
async fn timeout_error_says_where_it_stuck() {
    let limits = Limits {
        timeout_ms: 2_000,
        ..Limits::default()
    };
    let (_dir, mut executor) = executor_with(AllowAll, limits).await;
    let obs = executor
        .execute(vec![cell("while True: pass\n".to_string())])
        .await;
    match obs.error {
        Some(ExecError::Timeout {
            where_it_stuck: Some(where_it_stuck),
            ..
        }) => {
            assert!(
                where_it_stuck.contains("<cell>"),
                "the dump names the cell: {where_it_stuck}"
            );
        }
        other => panic!("want a timeout with a stack dump, got {other:?}"),
    }
}
