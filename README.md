The CodeAct execution layer: one resident interpreter, capability packs as namespaces, policy + journal at the single host-call seam.

Engine only. Domain rules — what is allowed, what a command means — live in
the application that composes a `Policy` and a `Journal` with these parts.

```rust
use codexec::{CodeCellExecutor, ExecutorBuilder, PythonWorker, FileJournal};

let executor = ExecutorBuilder::new(PythonWorker::new())
    .journal(FileJournal::new("run.jsonl"))
    .build()
    .await?;
```

What it provides:

* **Action parsing** — the model's code blocks become `Action`s with an
  explicit escape hatch, not implicit string commands.
* **A resident interpreter** — one worker process holds the state across
  cells, so the model writes code against a live namespace instead of shelling
  out per step.
* **Policy + journal at the host-call seam** — every capability call passes
  one chokepoint, so audit cannot be bypassed from inside a worker.
* **Limits** — per-turn and per-session budgets, so a runaway cell is stopped
  rather than merely reported.

```toml
[dependencies]
codexec = "0.1.0"
```

## License

MIT.
