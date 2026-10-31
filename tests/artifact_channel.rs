//! The artifact channel (M3c, action-executor-design §6): a body cut by the
//! round quota is not dead content — it spills whole to the store beside the
//! journal and the round keeps a summary+reference event. The `obs.*` face
//! records a value on purpose (`obs.emit`) and pulls a body back
//! (`obs.fetch`) across the same `_phi_call` seam as every host call.
//!
//! 账-物对账 is the point of these tests: every `art_*` id in an event must
//! fetch back the exact bytes that were cut.

use codexec::{
    Action, CellEvent, CodeCellExecutor, ExecutorBuilder, FileJournal, JournalHandle, Limits,
    PythonWorker,
};

async fn executor_with(
    limits: Limits,
    artifacts: Option<&std::path::Path>,
    journal_path: &std::path::Path,
) -> CodeCellExecutor<PythonWorker> {
    let journal = FileJournal::open(journal_path).expect("journal opens");
    let mut builder = ExecutorBuilder::new(JournalHandle::new(Box::new(journal)))
        .with_policy(codexec::AllowAll)
        .with_limits(limits);
    if let Some(dir) = artifacts {
        builder = builder.with_artifacts(dir);
    }
    builder
        .build(move |registry| PythonWorker::spawn(registry, limits))
        .await
        .expect("engine assembles")
}

fn cells(codes: &[&str]) -> Vec<Action> {
    codes
        .iter()
        .map(|code| Action::CodeCell {
            intent: String::new(),
            code: (*code).to_string(),
        })
        .collect()
}

/// A round-quota cut spills the whole block body: the store holds the bytes
/// byte for byte and the round carries one summary+reference event. The print
/// fits the worker's per-block cap (which is the same `stdout_max`) and
/// overflows only the round budget — so what the fold spilled is the body in
/// full, nothing cut it upstream.
#[tokio::test]
async fn a_round_quota_cut_spills_the_block_body_and_keeps_a_reference() {
    let dir = tempfile::tempdir().unwrap();
    let limits = Limits {
        stdout_max: 1_024,
        ..Limits::default()
    };
    let mut executor = executor_with(
        limits,
        Some(&dir.path().join("captures")),
        &dir.path().join("j.jsonl"),
    )
    .await;

    let full = format!("{}\n", "B".repeat(700));
    let obs = executor
        .execute(cells(&["print('A' * 700)", "print('B' * 700)"]))
        .await;
    assert!(obs.error.is_none(), "{obs:?}");
    assert!(obs.stdout.contains("AAAA"), "{obs:?}");
    assert!(
        obs.stdout.contains("…[truncated]"),
        "the cut is marked: {obs:?}"
    );

    assert_eq!(obs.events.len(), 1, "{obs:?}");
    let CellEvent::Artifact {
        capture_id,
        kind,
        bytes,
        summary,
    } = &obs.events[0]
    else {
        panic!("expected an artifact event, got {:?}", obs.events[0]);
    };
    assert_eq!(capture_id, "art_0001");
    assert_eq!(kind, "stdout");
    // 账-物对账: the event's id fetches back exactly the bytes that were cut.
    let hub = executor.registry().artifacts().expect("hub mounted");
    assert_eq!(
        hub.store().fetch(capture_id).as_deref(),
        Some(full.as_str())
    );
    assert_eq!(*bytes, full.len());
    assert!(summary.contains("...[output truncated]"), "{summary}");
    assert!(summary.chars().count() <= codexec::SUMMARY_MAX, "{summary}");
}

/// `obs.emit` splits inline from stored, and `obs.fetch` brings the body back
/// through the worker — the same seam as every host call.
#[tokio::test]
async fn obs_emit_splits_inline_from_stored_and_fetch_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let limits = Limits::default();
    let mut executor = executor_with(
        limits,
        Some(&dir.path().join("captures")),
        &dir.path().join("j.jsonl"),
    )
    .await;

    let obs = executor
        .execute(cells(&[
            "print(obs.emit('small note'))",
            "r = obs.emit('y' * 5000, 'report')",
            "print(sorted(r.keys()))",
            "print(len(obs.fetch(r['capture_id'])))",
            "print(obs.fetch(r['capture_id'])[:4])",
            "print(obs.emit({'k': 'v'}))",
        ]))
        .await;
    assert!(obs.error.is_none(), "{obs:?}");
    assert!(obs.stdout.contains("inlined"), "{obs:?}");
    assert!(
        obs.stdout.contains("5000"),
        "fetch returned the whole body: {obs:?}"
    );
    assert!(obs.stdout.contains("yyyy"), "{obs:?}");

    // The inline value is a notice event; the big one is a reference.
    assert!(
        obs.events
            .iter()
            .any(|e| matches!(e, CellEvent::Notice { text } if text == "small note")),
        "{obs:?}"
    );
    let artifact = obs.events.iter().find_map(|e| match e {
        CellEvent::Artifact {
            capture_id,
            kind,
            bytes,
            summary,
        } if kind == "report" => Some((capture_id.clone(), *bytes, summary.clone())),
        _ => None,
    });
    let (capture_id, bytes, summary) = artifact.expect("a report artifact event");
    assert_eq!(capture_id, "art_0001");
    assert_eq!(bytes, 5_000);
    assert!(
        summary.contains("...[output truncated]")
            && summary.chars().count() <= codexec::SUMMARY_MAX,
        "the summary is a glimpse, not the body: {summary:.60}"
    );

    let hub = executor.registry().artifacts().expect("hub mounted");
    assert_eq!(
        hub.store().fetch(&capture_id).as_deref(),
        Some("y".repeat(5_000).as_str())
    );
}

/// An unknown id fails with the way back spelled out, not a silent `None`.
#[tokio::test]
async fn fetching_an_unknown_id_fails_with_the_way_back() {
    let dir = tempfile::tempdir().unwrap();
    let limits = Limits::default();
    let mut executor = executor_with(
        limits,
        Some(&dir.path().join("captures")),
        &dir.path().join("j.jsonl"),
    )
    .await;

    let obs = executor.execute(cells(&["obs.fetch('art_9999')"])).await;
    let Some(err) = &obs.error else {
        panic!("expected the bad fetch to surface, got {obs:?}");
    };
    assert!(err.to_string().contains("unknown artifact"), "{err}");
}

/// No store mounted: the cut truncates and marks exactly as before — the
/// behavior-preserve path (and `obs.*` simply does not exist).
#[tokio::test]
async fn without_a_store_the_cut_still_truncates_and_marks() {
    let dir = tempfile::tempdir().unwrap();
    let limits = Limits {
        stdout_max: 1_024,
        ..Limits::default()
    };
    let mut executor = executor_with(limits, None, &dir.path().join("j.jsonl")).await;

    let obs = executor
        .execute(cells(&["print('A' * 700)", "print('B' * 700)"]))
        .await;
    assert!(obs.error.is_none(), "{obs:?}");
    assert!(obs.stdout.contains("…[truncated]"), "{obs:?}");
    assert!(obs.events.is_empty(), "no hub, no artifact events: {obs:?}");
    assert!(executor.registry().artifacts().is_none());
}
