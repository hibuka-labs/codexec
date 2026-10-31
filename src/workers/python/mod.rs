//! Python worker: a resident CPython child process speaking the JSON-lines
//! protocol (`stub/worker.py`).

mod runtime;

pub use runtime::PythonWorker;
