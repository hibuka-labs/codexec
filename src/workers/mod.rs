//! Worker implementations — one resident interpreter per language (D5).
//!
//! Only the runtime host lives here; the language itself is the pluggable
//! part (`workers/python` first).

pub mod python;

pub use python::PythonWorker;
