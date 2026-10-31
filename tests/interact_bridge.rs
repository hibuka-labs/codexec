//! The cell-interaction seam (action-executor-design OV-6 / T8): consent
//! suspends at the host-call chokepoint, `ask.user` suspends in its host call,
//! and an unanswered interaction fails closed — three scenarios against real
//! cells, under the same one-row journal contract as the rest of the throat.

use codexec::{
    Action, ActionEntry, Audited, ClassPolicy, CodeCellExecutor, ConsentRequest, ExecError,
    ExecutorBuilder, FileJournal, InteractionBridge, JournalHandle, Limits, PolicyDecision,
    PythonWorker,
};
use phi_cap::Capability;
use phi_ns::builtin::PhiNsShell;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// What the scripted human does when asked to consent.
#[derive(Debug, Clone)]
enum ConsentScript {
    Allow,
    Deny,
    Fail(String),
}

/// A human who answers by script: records what it was shown so tests can
/// assert the payload actually reaches the decision.
struct Scripted {
    consent: ConsentScript,
    ask: Result<Value, String>,
    /// `(fn_name, args wire)` as the consent path saw it.
    seen: Mutex<Vec<(String, Option<String>)>>,
    /// How long the human takes to answer (round-budget freeze coverage).
    reading_time: Duration,
}

impl Scripted {
    fn new(consent: ConsentScript) -> Self {
        Self {
            consent,
            ask: Ok(Value::Null),
            seen: Mutex::new(Vec::new()),
            reading_time: Duration::ZERO,
        }
    }
}

#[async_trait::async_trait]
impl InteractionBridge for Scripted {
    async fn consent(&self, req: &ConsentRequest<'_>) -> Result<PolicyDecision, String> {
        self.seen
            .lock()
            .unwrap()
            .push((req.fn_name.to_string(), req.args.map(|a| a.to_string())));
        tokio::time::sleep(self.reading_time).await;
        match &self.consent {
            ConsentScript::Allow => Ok(PolicyDecision::Allow),
            ConsentScript::Deny => Ok(PolicyDecision::Deny),
            ConsentScript::Fail(reason) => Err(reason.clone()),
        }
    }

    async fn ask(&self, _question: &str, _options: &[Value]) -> Result<Value, String> {
        self.ask.clone()
    }
}

async fn executor_with(
    policy: Arc<dyn codexec::Policy>,
    bridge: Option<Arc<Scripted>>,
    limits: Limits,
    journal_path: &std::path::Path,
) -> CodeCellExecutor<PythonWorker> {
    let journal = FileJournal::open(journal_path).expect("journal opens");
    let mut builder = ExecutorBuilder::new(JournalHandle::new(Box::new(journal)))
        .with_policy(policy)
        .with_limits(limits)
        .with_ns(PhiNsShell::builtin());
    if let Some(bridge) = bridge {
        builder = builder.with_interaction(bridge);
    }
    builder
        .build(move |registry| PythonWorker::spawn(registry, limits))
        .await
        .expect("engine assembles")
}

fn cell(code: &str) -> Action {
    Action::CodeCell {
        intent: String::new(),
        code: code.to_string(),
    }
}

fn call_rows(path: &std::path::Path) -> Vec<ActionEntry> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("journal row parses"))
        .collect::<Vec<ActionEntry>>()
        .into_iter()
        .filter(|r| matches!(r.audited, Audited::Call { .. }))
        .collect()
}

fn one_call(
    path: &std::path::Path,
) -> (String, Capability, PolicyDecision, codexec::ActionOutcome) {
    let rows = call_rows(path);
    assert_eq!(rows.len(), 1, "the call journals exactly one row: {rows:?}");
    let Audited::Call {
        fn_name,
        capability,
        decision,
        result,
        ..
    } = &rows[0].audited
    else {
        panic!("expected a call row, got {:?}", rows[0]);
    };
    (fn_name.clone(), *capability, *decision, *result)
}

fn ask_policy() -> Arc<dyn codexec::Policy> {
    Arc::new(ClassPolicy::new(PolicyDecision::Allow).with(Capability::Process, PolicyDecision::Ask))
}

#[tokio::test]
async fn consent_answered_allow_lets_the_call_run_with_one_final_row() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let human = Arc::new(Scripted::new(ConsentScript::Allow));
    let mut executor = executor_with(
        ask_policy(),
        Some(Arc::clone(&human)),
        Limits::default(),
        &journal_path,
    )
    .await;

    let obs = executor.execute(vec![cell("sh.run(\"echo hi\")")]).await;
    assert!(obs.error.is_none(), "{obs:?}");
    assert!(obs.stdout.contains("hi"), "the effect ran: {obs:?}");

    // ONE row, and it carries the FINAL decision — never an intermediate
    // `ask` hold (inventory §3.4: decide → journal → effect).
    let (fn_name, cap, decision, result) = one_call(&journal_path);
    assert_eq!(fn_name, "sh.run");
    assert_eq!(cap, Capability::Process);
    assert_eq!(decision, PolicyDecision::Allow);
    assert_eq!(result, codexec::ActionOutcome::Dispatched);

    // The human saw the call's payload, not just its digest.
    let seen = human.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].0, "sh.run");
    assert!(
        seen[0].1.as_deref().unwrap_or_default().contains("echo hi"),
        "{seen:?}"
    );
}

#[tokio::test]
async fn consent_answered_deny_halts_the_step_and_leaves_one_blocked_row() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let human = Arc::new(Scripted::new(ConsentScript::Deny));
    let mut executor = executor_with(
        ask_policy(),
        Some(Arc::clone(&human)),
        Limits::default(),
        &journal_path,
    )
    .await;

    let obs = executor
        .execute(vec![cell("sh.run(\"echo hi\")"), cell("print(\"late\")")])
        .await;
    assert!(obs.is_policy_hold(), "{obs:?}");
    assert!(!obs.stdout.contains("hi"), "the effect never ran: {obs:?}");
    assert!(
        !obs.stdout.contains("late"),
        "later cells do not run: {obs:?}"
    );
    match &obs.error {
        Some(ExecError::PolicyHold {
            decision,
            reason,
            cell_index,
            ..
        }) => {
            assert_eq!(*decision, PolicyDecision::Deny, "{obs:?}");
            assert_eq!(reason.as_deref(), Some("consent refused"), "{obs:?}");
            assert_eq!(*cell_index, 0, "{obs:?}");
        }
        other => panic!("expected a policy hold, got {other:?}"),
    }

    // The refusal is a fate, not a silence: one blocked row, final decision.
    let (fn_name, cap, decision, result) = one_call(&journal_path);
    assert_eq!(fn_name, "sh.run");
    assert_eq!(cap, Capability::Process);
    assert_eq!(decision, PolicyDecision::Deny);
    assert_eq!(result, codexec::ActionOutcome::Blocked);
}

#[tokio::test]
async fn ask_user_suspends_in_its_host_call_and_returns_the_pick() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let human = Arc::new(Scripted {
        consent: ConsentScript::Allow,
        ask: Ok(serde_json::json!({"picked": {"id": "a", "label": "Alpha"}})),
        seen: Mutex::new(Vec::new()),
        reading_time: Duration::ZERO,
    });
    let mut executor = executor_with(
        Arc::new(ClassPolicy::new(PolicyDecision::Allow)),
        Some(Arc::clone(&human)),
        Limits::default(),
        &journal_path,
    )
    .await;

    let obs = executor
        .execute(vec![cell(
            "print(ask.user(\"which one?\", [{\"id\": \"a\", \"label\": \"Alpha\"}]))",
        )])
        .await;
    assert!(obs.error.is_none(), "{obs:?}");
    assert!(
        obs.stdout.contains("Alpha"),
        "the answer came back: {obs:?}"
    );

    // Asking a human is a journaled call like any other (throat: no
    // exceptions) — decision key `Pure`, and it ran.
    let (fn_name, cap, decision, result) = one_call(&journal_path);
    assert_eq!(fn_name, "ask.user");
    assert_eq!(cap, Capability::Pure);
    assert_eq!(decision, PolicyDecision::Allow);
    assert_eq!(result, codexec::ActionOutcome::Dispatched);
}

#[tokio::test]
async fn an_unanswered_interaction_fails_closed_with_the_reason() {
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let human = Arc::new(Scripted::new(ConsentScript::Fail(
        "interaction cancelled".into(),
    )));
    let mut executor = executor_with(
        ask_policy(),
        Some(Arc::clone(&human)),
        Limits::default(),
        &journal_path,
    )
    .await;

    let obs = executor.execute(vec![cell("sh.run(\"echo hi\")")]).await;
    assert!(obs.is_policy_hold(), "{obs:?}");
    match &obs.error {
        Some(ExecError::PolicyHold {
            decision, reason, ..
        }) => {
            assert_eq!(*decision, PolicyDecision::Deny, "{obs:?}");
            assert!(
                reason
                    .as_deref()
                    .unwrap_or_default()
                    .contains("interaction cancelled"),
                "{obs:?}"
            );
        }
        other => panic!("expected a policy hold, got {other:?}"),
    }
    assert!(!obs.stdout.contains("hi"), "the effect never ran: {obs:?}");

    let (fn_name, cap, decision, result) = one_call(&journal_path);
    assert_eq!(fn_name, "sh.run");
    assert_eq!(cap, Capability::Process);
    assert_eq!(decision, PolicyDecision::Deny);
    assert_eq!(result, codexec::ActionOutcome::Blocked);
}

#[tokio::test]
async fn human_reading_time_does_not_consume_the_round_budget() {
    // A tiny hard timeout and a slow consent: the budget freezes while the
    // human reads, so the cell still runs instead of the round dying mid-dialog.
    let dir = tempfile::tempdir().unwrap();
    let journal_path = dir.path().join("j.jsonl");
    let mut human = Scripted::new(ConsentScript::Allow);
    human.reading_time = Duration::from_millis(1_200);
    let human = Arc::new(human);
    let limits = Limits {
        timeout_ms: 250,
        ..Limits::default()
    };
    let mut executor = executor_with(ask_policy(), Some(human), limits, &journal_path).await;

    let obs = executor.execute(vec![cell("sh.run(\"echo hi\")")]).await;
    assert!(
        obs.error.is_none(),
        "the round must survive the dialog: {obs:?}"
    );
    assert!(obs.stdout.contains("hi"), "{obs:?}");
}
