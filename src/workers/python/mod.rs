//! Python worker: a resident CPython child process speaking the JSON-lines
//! protocol (`stub/worker.py`).

#[cfg(unix)]
mod child_audit;
mod runtime;

pub use runtime::PythonWorker;
