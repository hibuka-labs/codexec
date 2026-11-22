//! Helpers the integration tests share.
//!
//! The one that matters: a path written into Python *source text* is not
//! the same string as a path. A Windows path is `C:\Users\me\file.txt`, and
//! Python reads the `\U` as the start of a unicode escape — the cell dies
//! with "'unicodeescape' codec can't decode bytes in position 8-9" before
//! the code under test ever runs. Unix paths do not have this problem,
//! which is why the defect only shows up on the Windows runner.

// Each integration test binary compiles this module on its own, so a helper
// another binary uses is dead code here. The gate is shared, not per binary.
#![allow(dead_code)]

use std::path::Path;

/// A path as a Python string literal, backslash included.
///
/// The literal is what Python's own `repr` produces, so the value the cell
/// sees is the path and nothing else — no escapes the test author has to
/// think about, and no `\U` waiting to explode on Windows.
pub fn py_path(path: &Path) -> String {
    py_str(&path.to_string_lossy())
}

/// A Rust string as a Python string literal.
pub fn py_str(value: &str) -> String {
    // Python and Rust agree on these; the ones that differ are the ones
    // that matter here (`\u` and `\U` are the landmines on Windows).
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}
