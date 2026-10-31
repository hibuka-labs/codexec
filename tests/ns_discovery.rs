//! The ns discovery protocol (T12, 独立验收项): `dir()` finds names,
//! `help(name)` answers from the **declaration** (`MethodSpec` via phi-ns
//! `help_doc`) — never from a shim docstring — and the prompt face of the
//! engine is exactly what it installs (提示面同源). 不达标不算完.

use codexec::{
    Action, CodeCellExecutor, ExecutorBuilder, FileJournal, JournalHandle, Limits, PythonWorker,
};
use phi_ns::builtin::PhiNsShell;
use std::process::{Command, Output};
use std::sync::Arc;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_codexec")
}

fn run(code: &str) -> Output {
    let dir = tempfile::tempdir().expect("tempdir");
    let journal = dir.path().join("j.jsonl");
    Command::new(bin())
        .arg("run")
        .arg("--cell")
        .arg(code)
        .arg("--journal")
        .arg(&journal)
        .output()
        .expect("codexec should run")
}

fn out_of(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The one declaration line the help face must serve — exact text, so a
/// shim-docstring answer (the drift case) cannot pass as the declaration.
const DECL_LINE: &str = "sh.run — run a shell command; returns Output(stdout, stderr, code)";

#[test]
fn help_by_name_answers_from_the_declaration() {
    let out = run(r#"help("sh.run")"#);
    let text = out_of(&out);
    assert!(out.status.success(), "{text}");
    assert!(text.contains(DECL_LINE), "declaration line: {text}");
    assert!(text.contains("capability: process"), "class line: {text}");
}

#[test]
fn help_by_root_serves_the_pack_view() {
    let out = run(r#"help("sh")"#);
    let text = out_of(&out);
    assert!(out.status.success(), "{text}");
    assert!(text.contains(DECL_LINE), "pack view: {text}");
}

#[test]
fn help_by_object_resolves_the_live_proxy() {
    let out = run("help(sh.run)");
    let text = out_of(&out);
    assert!(out.status.success(), "{text}");
    assert!(text.contains(DECL_LINE), "object form: {text}");
}

#[test]
fn help_for_an_unknown_name_under_a_declared_root_fails_loud() {
    let out = run(r#"help("sh.ryn")"#);
    let text = out_of(&out);
    assert!(!out.status.success(), "must fail: {text}");
    assert!(
        text.contains("no namespace declaration"),
        "loud failure: {text}"
    );
}

#[test]
fn help_without_arguments_lists_the_overview_not_pydocs_pager() {
    let out = run("help()");
    let text = out_of(&out);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("sh:"), "root line: {text}");
    assert!(text.contains(DECL_LINE), "overview rows: {text}");
}

#[test]
fn dir_discovers_the_roots_and_their_methods() {
    let out = run(r#"assert "sh" in dir(); assert "run" in dir(sh); print("dir-ok")"#);
    let text = out_of(&out);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("dir-ok"), "{text}");
}

#[test]
fn help_is_runtime_surface_not_namespace_state() {
    // The snapshot lists what is alive to use — `help` is how to discover,
    // so it must not show up as state beside `sh`, `x`, `out`.
    let out = run("x = 1");
    let text = out_of(&out);
    assert!(out.status.success(), "{text}");
    let snap = text
        .lines()
        .rev()
        .find(|l| l.starts_with("namespace: "))
        .expect("namespace snapshot");
    assert!(snap.contains("x(int, 1)"), "{snap}");
    assert!(!snap.contains("help("), "help leaks into state: {snap}");
}

// ---- the face the prompt serves is the face the engine installs ----------

struct NoHuman;

#[async_trait::async_trait]
impl codexec::InteractionBridge for NoHuman {
    async fn consent(
        &self,
        _req: &codexec::ConsentRequest<'_>,
    ) -> Result<codexec::PolicyDecision, String> {
        Ok(codexec::PolicyDecision::Allow)
    }

    async fn ask(
        &self,
        _question: &str,
        _options: &[serde_json::Value],
    ) -> Result<serde_json::Value, String> {
        Ok(serde_json::Value::Null)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prompt_face_is_exactly_what_the_engine_installs() {
    let dir = tempfile::tempdir().unwrap();
    let journal = FileJournal::open(dir.path().join("j.jsonl")).expect("journal opens");
    let limits = Limits::default();
    let builder = ExecutorBuilder::new(JournalHandle::new(Box::new(journal)))
        .with_policy(codexec::AllowAll)
        .with_limits(limits)
        .with_ns(PhiNsShell::builtin())
        .with_interaction(Arc::new(NoHuman));
    let face = builder.prompt_face();
    assert!(face.contains("sh.run — "), "shell rows: {face}");
    assert!(face.contains("ask.user — "), "interaction rows: {face}");

    let executor = builder
        .build(move |registry| PythonWorker::spawn(registry, limits))
        .await
        .expect("engine assembles");
    let declared = executor.registry().declared_names();
    for name in ["sh.run", "ask.user"] {
        assert!(
            declared.iter().any(|d| d == name),
            "{name} installed: {declared:?}"
        );
    }
    // Every face line names a declared method — the prompt can never
    // advertise a name the worker doesn't have.
    for line in face.lines() {
        let name = line.split(" — ").next().expect("api line");
        assert!(
            declared.iter().any(|d| d == name),
            "face line {name:?} must be installed: {declared:?}"
        );
    }
}

// ---- capability names survive a worker loss ------------------------------

fn cell(code: &str) -> Action {
    Action::CodeCell {
        intent: String::new(),
        code: code.to_string(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reinstall_rebuilds_the_worker_face_including_help() {
    let dir = tempfile::tempdir().unwrap();
    let journal = FileJournal::open(dir.path().join("j.jsonl")).expect("journal opens");
    let limits = Limits::default();
    let mut executor: CodeCellExecutor<PythonWorker> =
        ExecutorBuilder::new(JournalHandle::new(Box::new(journal)))
            .with_policy(codexec::AllowAll)
            .with_limits(limits)
            .with_ns(PhiNsShell::builtin())
            .build(move |registry| PythonWorker::spawn(registry, limits))
            .await
            .expect("engine assembles");

    // Kill the interpreter from inside — the strongest worker-loss shape.
    let obs = executor
        .execute(vec![cell("import os\nos.kill(os.getpid(), 9)")])
        .await;
    assert!(obs.error.is_some(), "the worker died mid-round: {obs:?}");

    // The reset report cell does not run; the one after it does — on a
    // fresh worker whose packs must be back (shims, proxies, help docs).
    let reset = executor.execute(vec![cell("print(42)")]).await;
    assert!(reset.is_session_reset(), "{reset:?}");

    let obs = executor
        .execute(vec![cell(
            "print(sh.run(\"echo alive\").stdout.strip())\nhelp(\"sh.run\")",
        )])
        .await;
    assert!(obs.error.is_none(), "{obs:?}");
    assert!(obs.stdout.contains("alive"), "shim is back: {obs:?}");
    assert!(
        obs.stdout.contains(DECL_LINE),
        "help answers from the declaration after respawn: {obs:?}"
    );
}
