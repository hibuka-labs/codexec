//! `codexec` CLI — the Day-1 acceptance surface over the engine.
//!
//! ```text
//! codexec run --cell 'x = 41' --cell 'print(x + 1)' [--policy P] [--journal PATH]
//! codexec replay PATH
//! ```
//!
//! Exit codes: 0 clean · 1 the step failed/held · 2 bad usage.

use codexec::{
    Action, ActionEntry, Audited, ClassPolicy, ExecError, FileJournal, JournalHandle, Limits,
    Observation, Policy, PolicyDecision, PythonWorker,
};
use phi_cap::Capability;
use phi_ns::builtin::PhiNsShell;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: cannot start runtime: {e}");
            return ExitCode::from(1);
        }
    };
    match args.first().map(String::as_str) {
        Some("run") => runtime.block_on(run_cmd(&args[1..])),
        Some("replay") => replay_cmd(&args[1..]),
        Some("--help") | Some("-h") | Some("help") => {
            usage();
            ExitCode::SUCCESS
        }
        _ => {
            usage();
            ExitCode::from(2)
        }
    }
}

fn usage() {
    eprintln!(
        "usage:
  codexec run --cell CODE [--cell CODE]... [--policy allow-all|deny-process|ask-process]
              [--journal PATH] [--timeout MS]
  codexec replay PATH"
    );
}

struct RunArgs {
    cells: Vec<String>,
    policy: String,
    journal: Option<PathBuf>,
    timeout_ms: Option<u64>,
}

fn parse_run_args(args: &[String]) -> Result<RunArgs, String> {
    let mut out = RunArgs {
        cells: Vec::new(),
        policy: "allow-all".to_string(),
        journal: None,
        timeout_ms: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cell" => {
                i += 1;
                let code = args
                    .get(i)
                    .ok_or_else(|| "--cell needs a code argument".to_string())?;
                out.cells.push(code.clone());
            }
            "--policy" => {
                i += 1;
                let name = args
                    .get(i)
                    .ok_or_else(|| "--policy needs a name".to_string())?;
                match name.as_str() {
                    "allow-all" | "deny-process" | "ask-process" => out.policy = name.clone(),
                    other => return Err(format!("unknown policy {other:?}")),
                }
            }
            "--journal" => {
                i += 1;
                let path = args
                    .get(i)
                    .ok_or_else(|| "--journal needs a path".to_string())?;
                out.journal = Some(PathBuf::from(path));
            }
            "--timeout" => {
                i += 1;
                let ms = args
                    .get(i)
                    .ok_or_else(|| "--timeout needs milliseconds".to_string())?;
                out.timeout_ms = Some(
                    ms.parse()
                        .map_err(|_| format!("--timeout expects an integer, got {ms:?}"))?,
                );
            }
            other => return Err(format!("unknown flag {other:?}")),
        }
        i += 1;
    }
    if out.cells.is_empty() {
        return Err("at least one --cell is required".into());
    }
    Ok(out)
}

/// CLI policy presets — the application layer's opinions, not the engine's.
fn build_policy(name: &str) -> Arc<dyn Policy> {
    match name {
        "deny-process" => Arc::new(
            ClassPolicy::new(PolicyDecision::Allow).with(Capability::Process, PolicyDecision::Deny),
        ),
        "ask-process" => Arc::new(
            ClassPolicy::new(PolicyDecision::Allow).with(Capability::Process, PolicyDecision::Ask),
        ),
        _ => Arc::new(codexec::AllowAll),
    }
}

async fn run_cmd(args: &[String]) -> ExitCode {
    let run = match parse_run_args(args) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            usage();
            return ExitCode::from(2);
        }
    };

    let mut limits = Limits::default();
    if let Some(ms) = run.timeout_ms {
        limits.timeout_ms = ms;
    }

    let journal_path = run.journal.clone().unwrap_or_else(|| {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "codexec-journal-{}-{stamp}.jsonl",
            std::process::id()
        ))
    });
    let journal = match FileJournal::open(&journal_path) {
        Ok(j) => JournalHandle::new(Box::new(j)),
        Err(e) => {
            eprintln!("error: cannot open journal {journal_path:?}: {e}");
            return ExitCode::from(1);
        }
    };

    // Assembly line (sdk-assembly §3.4): one `.with_ns(...)` per pack.
    let mut executor = match codexec::ExecutorBuilder::new(journal)
        .with_policy(build_policy(&run.policy))
        .with_limits(limits)
        .with_ns(PhiNsShell::builtin())
        .build(move |registry| PythonWorker::spawn(registry, limits))
        .await
    {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: engine assembly failed: {e}");
            return ExitCode::from(1);
        }
    };

    let actions: Vec<Action> = run
        .cells
        .iter()
        .map(|code| Action::CodeCell {
            intent: String::new(),
            code: code.clone(),
        })
        .collect();
    let obs = executor.execute(actions).await;
    print!("{stdout}", stdout = obs.stdout);
    if !obs.stderr.is_empty() {
        eprint!("{stderr}", stderr = obs.stderr);
    }
    if let Some(err) = &obs.error {
        println!("error: {err}");
    }
    println!(
        "journal: {path} ({n} entries)",
        path = journal_path.display(),
        n = count_entries(&journal_path)
    );

    match obs.error {
        None => ExitCode::SUCCESS,
        Some(_) => ExitCode::from(1),
    }
}

fn count_entries(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path)
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0)
}

fn replay_cmd(args: &[String]) -> ExitCode {
    let Some(path) = args.first() else {
        eprintln!("error: replay needs a journal path");
        usage();
        return ExitCode::from(2);
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let mut n = 0;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<ActionEntry>(line) {
            Ok(e) => {
                n += 1;
                match &e.audited {
                    Audited::Call {
                        capability,
                        fn_name,
                        args_digest,
                        decision,
                        result,
                        ..
                    } => println!(
                        "{time}  call  {cap}  {name}  {dec}  {result}  step={step} cell={cell}  {digest}",
                        time = e.time,
                        cap = capability,
                        name = fn_name,
                        dec = decision,
                        result = match result {
                            codexec::ActionOutcome::Dispatched => "dispatched",
                            codexec::ActionOutcome::Blocked => "blocked",
                        },
                        step = e.step_index,
                        cell = e.cell_index,
                        digest = args_digest,
                    ),
                    Audited::Cell {
                        intent,
                        code_digest,
                    } => println!(
                        "{time}  cell  {intent}  step={step} cell={cell}  {digest}",
                        time = e.time,
                        step = e.step_index,
                        cell = e.cell_index,
                        digest = code_digest,
                    ),
                }
            }
            Err(e) => {
                eprintln!("error: bad journal row: {e}");
                return ExitCode::from(1);
            }
        }
    }
    println!("{n} entries");
    ExitCode::SUCCESS
}

// Keep the observation helpers' names in scope for readers of this file.
#[allow(dead_code)]
fn _contract_types(obs: &Observation, e: &ExecError) -> bool {
    obs.is_policy_hold() || matches!(e, ExecError::SessionReset)
}
