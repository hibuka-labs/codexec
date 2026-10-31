//! The journal (codexec-design §8.1): **audit that cannot be switched off**.
//!
//! Every code cell and every side-effecting call leaves one [`ActionEntry`] —
//! write-ahead, so a failed journal aborts the step (fail-closed). Cell rows
//! are the ledger's honesty guarantee: pure Python effects never cross the
//! host-call seam, and without a row per cell the journal would lie by
//! omission (dogfood evidence in phimint's `notes/code-cell-dogfood.md`).
//! The engine ships [`FileJournal`]; applications may swap the
//! implementation, never disable it. `codexec replay <path>` reads these
//! rows back.

use crate::policy::PolicyDecision;
use phi_cap::Capability;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// What happened to the call once decided — the journal's result granularity
/// (the effect's own output lives in the observation stream).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionOutcome {
    /// Handed to the implementation.
    Dispatched,
    /// Held back; the effect never ran.
    Blocked,
}

/// One audit row: time, placement, and what was audited
/// (codexec-design §8.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionEntry {
    /// Wall-clock time, unix milliseconds.
    pub time_ms: u64,
    /// Time as UTC text (human review).
    pub time: String,
    /// 0-based cell index within the step.
    pub cell_index: usize,
    /// Step counter (one `execute()` = one step).
    pub step_index: usize,
    /// What ran, and under what terms. Flattened into the row so call rows
    /// keep their §8.1 facts (`fn_name` / `decision`) at top level.
    #[serde(flatten)]
    pub audited: Audited,
}

/// What a row audits — two row kinds, one vocabulary.
///
/// `call` is the §8.1 classic row (a host-mediated side effect). `cell` is
/// the CodeAct ledger row: one per code cell submitted to the worker,
/// whatever the cell goes on to do. A cell row deliberately carries **no
/// capability class, no policy answer, and no outcome** — the cell is
/// unclassified code, and stamping any of those on it would be exactly the
/// lie the ledger exists to prevent. A row's existence says the cell was
/// handed to the worker; whether it executed (a hold or compile error stops
/// the round early) and what it did live in the observation stream, and
/// effect-level facts surface as `call` rows — host calls, and mediated
/// stdlib effects through the worker audit hook (codexec-design §8.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Audited {
    /// A host-mediated side-effecting call.
    Call {
        /// Coarse capability class the call was decided under.
        capability: Capability,
        /// Function name as injected (`"sh.run"`).
        fn_name: String,
        /// Stable digest of the arguments — correlation, not payload.
        args_digest: String,
        /// What policy answered.
        decision: PolicyDecision,
        /// What happened next.
        result: ActionOutcome,
        /// The capture this call spent (dispatched) or sought (reuse refused) —
        /// inventory §3.4: consumption lands in the journal at the chokepoint.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capture_id: Option<String>,
    },
    /// One code cell handed to the worker (write-ahead of the round).
    Cell {
        /// The cell's declared intent (human review; short on purpose).
        intent: String,
        /// Stable digest of the cell source — correlation, not payload.
        code_digest: String,
    },
}

impl ActionEntry {
    /// Stamp a row with the current wall clock.
    pub fn now(cell_index: usize, step_index: usize, audited: Audited) -> Self {
        let time_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            time_ms,
            time: utc_text(time_ms),
            cell_index,
            step_index,
            audited,
        }
    }

    /// The capture gate settles the call outcome after the ledger answers: a
    /// spent capture lands here, and a refused reuse flips the call to
    /// blocked. No-op outside call rows (the gate only ever holds those).
    pub fn set_call_outcome(&mut self, result: ActionOutcome, capture_id: Option<String>) {
        if let Audited::Call {
            result: slot,
            capture_id: id,
            ..
        } = &mut self.audited
        {
            *slot = result;
            *id = capture_id;
        }
    }
}

/// Journal failures abort the action (fail-closed).
#[derive(Debug, Error)]
pub enum JournalError {
    /// Underlying I/O failed.
    #[error("journal io: {0}")]
    Io(#[from] std::io::Error),
    /// Serialization failed.
    #[error("journal encode: {0}")]
    Encode(String),
}

/// The audit sink. `record` failing must fail the action.
pub trait Journal: Send {
    /// Record one audit row (a cell or a call). Called exactly once per row,
    /// write-ahead of the thing it describes.
    fn record(&mut self, entry: ActionEntry) -> Result<(), JournalError>;
}

/// Shared handle to a journal (the gate and the registry both write).
#[derive(Clone)]
pub struct JournalHandle {
    inner: Arc<Mutex<Box<dyn Journal + Send>>>,
}

impl JournalHandle {
    /// Wrap any journal implementation.
    pub fn new(journal: Box<dyn Journal + Send>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(journal)),
        }
    }

    /// Record one entry (fail-closed on error).
    pub fn record(&self, entry: ActionEntry) -> Result<(), JournalError> {
        self.inner.lock().expect("journal poisoned").record(entry)
    }
}

/// Append-only JSONL journal — the default, always available.
pub struct FileJournal {
    path: PathBuf,
    file: std::fs::File,
}

impl FileJournal {
    /// Open (create/append) the journal at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self { path, file })
    }

    /// Where this journal writes.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// How many rows it holds (reads the file back — cheap enough for CLI).
    pub fn entry_count(&self) -> usize {
        std::fs::read_to_string(&self.path)
            .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
            .unwrap_or(0)
    }
}

impl Journal for FileJournal {
    fn record(&mut self, entry: ActionEntry) -> Result<(), JournalError> {
        let line =
            serde_json::to_string(&entry).map_err(|e| JournalError::Encode(e.to_string()))?;
        writeln!(self.file, "{line}")?;
        self.file.flush()?;
        Ok(())
    }
}

/// An in-memory journal for tests and replays of already-recorded steps.
#[derive(Default)]
pub struct MemJournal {
    /// Recorded rows.
    pub rows: Vec<ActionEntry>,
}

impl Journal for MemJournal {
    fn record(&mut self, entry: ActionEntry) -> Result<(), JournalError> {
        self.rows.push(entry);
        Ok(())
    }
}

/// Build the write-ahead row for one host-mediated call. The capture gate
/// fills `capture_id` when the call draws on one (see `decide_and_journal`).
#[allow(clippy::too_many_arguments)]
pub fn entry_for(
    capability: Capability,
    fn_name: &str,
    args_digest: String,
    decision: PolicyDecision,
    result: ActionOutcome,
    cell_index: usize,
    step_index: usize,
) -> ActionEntry {
    ActionEntry::now(
        cell_index,
        step_index,
        Audited::Call {
            capability,
            fn_name: fn_name.to_string(),
            args_digest,
            decision,
            result,
            capture_id: None,
        },
    )
}

/// Build the write-ahead row for one code cell — recorded before the round
/// runs, so the row means "handed to the worker", not "executed" (a hold or
/// compile error may stop the round early). The code itself is digested, not
/// stored (correlation, not payload), mirroring call rows.
pub fn cell_entry_for(
    intent: &str,
    code: &str,
    cell_index: usize,
    step_index: usize,
) -> ActionEntry {
    let code_digest = phi_ns::remote::args_digest(&serde_json::Value::String(code.to_string()));
    ActionEntry::now(
        cell_index,
        step_index,
        Audited::Cell {
            intent: intent.to_string(),
            code_digest,
        },
    )
}

/// Format unix milliseconds as `YYYY-MM-DDTHH:MM:SS.mmmZ` (civil-from-days,
/// no dependency).
pub fn utc_text(time_ms: u64) -> String {
    let secs = time_ms / 1000;
    let millis = time_ms % 1000;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

/// Howard Hinnant's civil_from_days.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_text_rounds_to_a_readable_stamp() {
        // 2026-10-25T00:00:00.000Z
        let ms = 1_792_886_400_000u64;
        assert_eq!(utc_text(ms), "2026-10-25T00:00:00.000Z");
    }

    #[test]
    fn rows_round_trip_both_kinds_with_flat_call_facts() {
        // Call rows keep their §8.1 facts at top level (greppable JSONL);
        // cell rows claim nothing but the submission itself.
        let call = entry_for(
            Capability::Process,
            "sh.run",
            "deadbeef".into(),
            PolicyDecision::Deny,
            ActionOutcome::Blocked,
            2,
            7,
        );
        let text = serde_json::to_string(&call).unwrap();
        assert!(text.contains("\"kind\":\"call\""), "{text}");
        assert!(text.contains("\"fn_name\":\"sh.run\""), "{text}");
        assert!(text.contains("\"decision\":\"deny\""), "{text}");
        assert_eq!(serde_json::from_str::<ActionEntry>(&text).unwrap(), call);

        let cell = cell_entry_for("sum the files", "print(1)", 0, 7);
        let text = serde_json::to_string(&cell).unwrap();
        assert!(text.contains("\"kind\":\"cell\""), "{text}");
        assert!(text.contains("\"intent\":\"sum the files\""), "{text}");
        assert!(!text.contains("decision"), "no policy answer: {text}");
        assert!(!text.contains("\"result\""), "no outcome claim: {text}");
        assert_eq!(serde_json::from_str::<ActionEntry>(&text).unwrap(), cell);
    }

    #[test]
    fn file_journal_appends_rows() {
        let dir = std::env::temp_dir().join(format!("codexec-jrnl-{}", std::process::id()));
        let path = dir.join("j.jsonl");
        let mut j = FileJournal::open(&path).unwrap();
        for _ in 0..3 {
            j.record(entry_for(
                Capability::Process,
                "sh.run",
                "deadbeef".into(),
                PolicyDecision::Deny,
                ActionOutcome::Blocked,
                0,
                1,
            ))
            .unwrap();
        }
        assert_eq!(j.entry_count(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
