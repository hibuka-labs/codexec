//! The artifact store (action-executor-design §6 / §6.1): when an
//! observation body is too big for the model's context, the body spills
//! here and the model keeps a summary plus a reference line. Bodies live
//! beside the journal (`captures/`) — one file per artifact, id `art_<seq>`
//! (账-物同账本: the store landing on disk IS the account).
//!
//! The id space is deliberately separate from the look→act capture ledger
//! (`capture_<face>_<seq>`, phi-ns `capture.rs`): a capture is a one-use act
//! authorization that can expire; an artifact reference is stable and
//! re-fetchable. Two semantics, two pools (§6.1).
//!
//! Model face — one line, built by [`artifact_line`] and carried by
//! [`CellEvent::Artifact`] (the adapters render it into the observation
//! text):
//!
//! ```text
//! artifact art_0001 (stdout, 240112 bytes): <summary> — obs.fetch('art_0001') for the full body
//! ```
//!
//! The line rides the **event** channel on purpose (T13 ruling): a stdout
//! floor line dies exactly when the round quota is exhausted — the moment it
//! is needed — so the event budget (its own quota) is the real floor. The
//! summary is a truncation heuristic (OV-14: no model call): head 1/3 +
//! marker + tail 2/3 of a bounded budget, the family `truncate_output` shape.
//!
//! The `obs.*` face ([`ObsPack`]) is how the model records a value on
//! purpose (`obs.emit`) and pulls a body back (`obs.fetch`). It rides the
//! same `_phi_call` throat as every host call — policy sees it, the journal
//! records it — and it is not a tool: no tool schema, no approval face.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use phi_ns::{HostCall, MethodSpec, NamespaceProvider, NsError, NsObject, WorkerSink, m};
use serde_json::{Value, json};

use crate::observation::CellEvent;

/// Elision marker inside a summary — same family convention as the kernel
/// tools' `truncate_output` (head kept, tail kept, middle marked).
const SUMMARY_MARKER: &str = "...[output truncated]";

/// A summary that floods defeats its purpose: the reference line must stay a
/// line. 512 chars is a glimpse, not a re-read.
pub const SUMMARY_MAX: usize = 512;

/// `obs.emit` values at or below this many chars ride the observation inline
/// (one `notice` line); larger values become artifacts. Under it, a fetch
/// round-trip would cost more than the value; over it, the value is exactly
/// what the emit economics exist for.
const EMIT_INLINE_MAX: usize = 4_096;

/// One spilled body's standing reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRef {
    /// Stable id, `art_<seq>`.
    pub capture_id: String,
    /// What the body is (`"stdout"` / `"stderr"` / `"observation"` / the
    /// emitter's own label).
    pub kind: String,
    /// Body size in bytes.
    pub bytes: usize,
    /// The truncation heuristic ([`summary_of`]).
    pub summary: String,
}

impl ArtifactRef {
    /// The model event for this reference (the adapters render
    /// [`artifact_line`] from it).
    pub fn event(&self) -> CellEvent {
        CellEvent::Artifact {
            capture_id: self.capture_id.clone(),
            kind: self.kind.clone(),
            bytes: self.bytes,
            summary: self.summary.clone(),
        }
    }
}

/// The model-facing line for one artifact: what it is, a glimpse of it, and
/// exactly how to get the body back.
pub fn artifact_line(capture_id: &str, kind: &str, bytes: usize, summary: &str) -> String {
    format!(
        "artifact {capture_id} ({kind}, {bytes} bytes): {summary} — obs.fetch('{capture_id}') for the full body"
    )
}

/// The summary heuristic (OV-14): head 1/3 + marker + tail 2/3 of a
/// [`SUMMARY_MAX`]-char budget. Compile/test errors cluster at the end and
/// listings make sense at the start, so both ends survive — the family
/// `truncate_output` shape, copied here because codexec stands below the
/// crates that own that copy (dependency direction is an iron rule).
///
/// Always ONE line, whitespace collapsed: the summary rides inside
/// [`artifact_line`], and that line is matched per physical line by the
/// rotation extractor (the pinned shape lives in both test suites — keep
/// them in step). A summary with a newline in it broke the line in two and
/// real artifacts silently dropped out of the rotation index (live
/// acceptance 20261029_a8015baa).
pub fn summary_of(body: &str) -> String {
    let flat = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    let total = body.chars().count();
    if total <= SUMMARY_MAX {
        return flat(body);
    }
    let available = SUMMARY_MAX.saturating_sub(SUMMARY_MARKER.chars().count() + 2);
    let head_chars = available / 3;
    let tail_chars = available - head_chars;
    let head: String = body.chars().take(head_chars).collect();
    let tail: String = body
        .chars()
        .rev()
        .take(tail_chars)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{} {SUMMARY_MARKER} {}", flat(&head), flat(&tail))
}

/// Strict id form: `art_` + digits and nothing else. An id is not a path and
/// must never become one — `fetch` joins it onto the store directory, so a
/// lax form is a traversal hole.
fn is_artifact_id(id: &str) -> bool {
    id.strip_prefix("art_")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

/// The store: one directory of full bodies, one id sequence.
pub struct ArtifactStore {
    dir: PathBuf,
    seq: AtomicUsize,
}

impl ArtifactStore {
    /// A store writing into `dir` (the journal's `captures/` sibling).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            seq: AtomicUsize::new(0),
        }
    }

    /// Spill one body: the full text lands in `captures/art_<seq>`, the
    /// summary is minted here. `Err` when the store cannot write — the
    /// caller keeps its truncation marker (never silent, still honest) and
    /// the body stays as lost as it was before M3c.
    pub fn spill(&self, kind: &str, body: &str) -> Result<ArtifactRef, String> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let capture_id = format!("art_{seq:04}");
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        std::fs::write(self.dir.join(&capture_id), body).map_err(|e| e.to_string())?;
        Ok(ArtifactRef {
            capture_id,
            kind: kind.to_string(),
            bytes: body.len(),
            summary: summary_of(body),
        })
    }

    /// Fetch a spilled body by id. `None` for an unknown id or one that is
    /// not a plain artifact id ([`is_artifact_id`]).
    pub fn fetch(&self, capture_id: &str) -> Option<String> {
        if !is_artifact_id(capture_id) {
            return None;
        }
        std::fs::read_to_string(self.dir.join(capture_id)).ok()
    }

    /// Where a given id's body lives (validated ids only).
    pub fn path_of(&self, capture_id: &str) -> PathBuf {
        self.dir.join(capture_id)
    }
}

/// The store plus this round's queued observation events — what the fold
/// drains ([`ArtifactHub::take_queued`]). One hub per engine: the store is
/// never duplicated (§6.1: 词汇一套).
pub struct ArtifactHub {
    store: ArtifactStore,
    queued: Mutex<Vec<CellEvent>>,
}

impl ArtifactHub {
    /// A hub over a store in `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            store: ArtifactStore::new(dir),
            queued: Mutex::new(Vec::new()),
        }
    }

    /// The store (fetch / inspection).
    pub fn store(&self) -> &ArtifactStore {
        &self.store
    }

    /// Spill a body and queue its model event for the round's fold — one
    /// call for every spill trigger (round-quota cut, adapter cut, emit) so
    /// the store and the event channel cannot drift apart.
    pub fn spill(&self, kind: &str, body: &str) -> Result<ArtifactRef, String> {
        let r = self.store.spill(kind, body)?;
        self.queued.lock().expect("queued poisoned").push(r.event());
        Ok(r)
    }

    /// Queue an inline observation (a small `obs.emit` value).
    pub fn notice(&self, text: String) {
        self.queued
            .lock()
            .expect("queued poisoned")
            .push(CellEvent::Notice { text });
    }

    /// Drain the round's queued events (fold time).
    pub fn take_queued(&self) -> Vec<CellEvent> {
        std::mem::take(&mut *self.queued.lock().expect("queued poisoned"))
    }
}

/// Worker-side shim installed by [`NamespaceProvider::install`]: `obs.emit`
/// and `obs.fetch` cross the host seam via `_phi_call` like every other
/// method. The emit guard keeps non-JSON values off the wire (the frame
/// serializer would raise mid-cell); JSON-native values pass untouched —
/// never re-encoded, the double-encoded shape is a known model fumble.
const PY_SHIM: &str = r#"
class ObsSdk:
    def emit(self, value, kind="text"):
        """Record one observation value: small values ride the observation
        inline, large ones are stored and referenced. Returns
        {"inlined": true} or {"capture_id": "art_0001", "bytes": …, "summary": …}."""
        if value is not None and not isinstance(value, (str, int, float, bool, list, dict)):
            value = repr(value)
        return _phi_call("obs.emit", [value, kind])

    def fetch(self, capture_id):
        """Fetch a stored artifact body by id (art_####); returns the full
        text — print only the part you need."""
        return _phi_call("obs.fetch", [capture_id])


obs = ObsSdk()
"#;

/// The `obs.*` face: emit an observation value, fetch a spilled body
/// (action-executor-design §6.1). No capabilities — recording and re-reading
/// the engine's own observation store touches no system surface (decision
/// key `Pure`), so there is no approval face and nothing lands in the tool
/// menu. Declaration source is [`Self::method_table`] (提示面同源).
pub(crate) struct ObsPack {
    hub: Arc<ArtifactHub>,
}

impl ObsPack {
    pub(crate) fn new(hub: Arc<ArtifactHub>) -> Self {
        Self { hub }
    }

    /// The `obs.*` declarations — the pack's single declaration source.
    pub(crate) fn method_table() -> Vec<MethodSpec> {
        vec![
            m(
                "obs.emit",
                &[],
                "record one observation value: small values ride the observation inline, large ones are stored and referenced (returns {capture_id, summary}) — prefer this over printing big payloads",
                false,
            ),
            m(
                "obs.fetch",
                &[],
                "fetch a stored artifact body by id (art_####); returns the full text — print only the part you need",
                false,
            ),
        ]
    }
}

#[async_trait]
impl NamespaceProvider for ObsPack {
    fn namespaces(&self) -> &'static [&'static str] {
        &["obs"]
    }

    fn methods(&self) -> Vec<MethodSpec> {
        Self::method_table()
    }

    async fn install(&self, sink: &mut dyn WorkerSink) -> Result<(), NsError> {
        sink.register_fn(
            "obs.emit",
            Box::new(EmitCall {
                hub: Arc::clone(&self.hub),
            }),
        )?;
        sink.register_fn(
            "obs.fetch",
            Box::new(FetchCall {
                hub: Arc::clone(&self.hub),
            }),
        )?;
        sink.eval(PY_SHIM).await
    }

    fn summarize(&self, _name: &str, obj: &NsObject) -> Option<String> {
        match obj.kind.as_str() {
            "ObsSdk" => Some(String::new()),
            _ => None,
        }
    }
}

/// Host-side implementation of `obs.emit`.
struct EmitCall {
    hub: Arc<ArtifactHub>,
}

#[async_trait]
impl HostCall for EmitCall {
    async fn call(&self, args: Vec<Value>) -> Result<Value, NsError> {
        let (value, kind) = match args.as_slice() {
            [value] => (value, "text"),
            [value, Value::String(kind)] if !kind.is_empty() => (value, kind.as_str()),
            [_, Value::String(_)] => {
                return Err(NsError::Sink(
                    "obs.emit(value, kind): kind must not be empty".into(),
                ));
            }
            _ => {
                return Err(NsError::Sink(
                    "obs.emit(value, kind=\"text\") expects one value and an optional kind string"
                        .into(),
                ));
            }
        };
        // Strings are the body verbatim; anything else is its compact JSON —
        // one vocabulary, no re-encoding games.
        let text = match value {
            Value::String(s) => s.clone(),
            other => serde_json::to_string(other).unwrap_or_else(|_| other.to_string()),
        };
        if text.chars().count() <= EMIT_INLINE_MAX {
            self.hub.notice(text);
            return Ok(json!({"inlined": true}));
        }
        let r = self.hub.spill(kind, &text).map_err(|why| {
            NsError::Sink(format!(
                "obs.emit could not store the value ({why}); print a slice of it instead"
            ))
        })?;
        Ok(json!({
            "capture_id": r.capture_id,
            "bytes": r.bytes,
            "summary": r.summary,
        }))
    }
}

/// Host-side implementation of `obs.fetch`.
struct FetchCall {
    hub: Arc<ArtifactHub>,
}

#[async_trait]
impl HostCall for FetchCall {
    async fn call(&self, args: Vec<Value>) -> Result<Value, NsError> {
        let [id] = args.as_slice() else {
            return Err(NsError::Sink("obs.fetch(capture_id) expects one id".into()));
        };
        let id = id
            .as_str()
            .ok_or_else(|| NsError::Sink("obs.fetch(capture_id) expects a string id".into()))?;
        self.hub
            .store()
            .fetch(id)
            .map(Value::String)
            .ok_or_else(|| {
                NsError::Sink(format!(
                    "unknown artifact '{id}'; use the id from an `artifact art_…` line"
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn hub() -> (TempDir, ArtifactHub) {
        let tmp = TempDir::new().unwrap();
        let hub = ArtifactHub::new(tmp.path().join("captures"));
        (tmp, hub)
    }

    #[test]
    fn spill_and_fetch_round_trip_with_minted_ids() {
        let (_tmp, hub) = hub();
        let a = hub.spill("stdout", "first body").unwrap();
        let b = hub.spill("stdout", "second body").unwrap();
        assert_eq!(a.capture_id, "art_0001");
        assert_eq!(b.capture_id, "art_0002");
        assert_eq!(a.bytes, "first body".len());
        assert_eq!(hub.store().fetch("art_0001").as_deref(), Some("first body"));
        assert_eq!(
            hub.store().fetch("art_0002").as_deref(),
            Some("second body")
        );
        assert!(hub.store().path_of("art_0001").exists());
    }

    #[test]
    fn fetch_rejects_ids_that_are_not_ids() {
        let (_tmp, hub) = hub();
        hub.spill("stdout", "body").unwrap();
        // An id is not a path: no traversal, no suffix games, no prose.
        for bad in [
            "../art_0001",
            "art_abc",
            "art_",
            "art_0001/x",
            "art_-1",
            "art_0001 ",
        ] {
            assert_eq!(hub.store().fetch(bad), None, "must refuse {bad:?}");
        }
    }

    #[test]
    fn summary_keeps_head_and_tail_within_budget() {
        let body = "H".repeat(200) + &"m".repeat(10_000) + &"T".repeat(200);
        let summary = summary_of(&body);
        assert!(summary.chars().count() <= SUMMARY_MAX, "{}", summary.len());
        assert!(summary.starts_with('H'), "head must survive");
        assert!(summary.ends_with('T'), "tail must survive");
        assert!(
            summary.contains(SUMMARY_MARKER),
            "the elision must be marked"
        );
        // Small bodies pass through verbatim — a summary is for big ones.
        assert_eq!(summary_of("small"), "small");
    }

    /// The pinned model-face line — the same example the rotation extractor
    /// (phi-kernel-tools `handoff.rs`) recognises. If this shape changes,
    /// change that matcher in the same breath.
    #[test]
    fn artifact_line_carries_the_fetch_instruction() {
        let r = ArtifactRef {
            capture_id: "art_0001".into(),
            kind: "stdout".into(),
            bytes: 11,
            summary: "first body".into(),
        };
        assert_eq!(
            artifact_line(&r.capture_id, &r.kind, r.bytes, &r.summary),
            "artifact art_0001 (stdout, 11 bytes): first body — obs.fetch('art_0001') for the full body"
        );
    }

    /// Live acceptance 20261029_a8015baa: a real spill's summary carried
    /// newlines (head\nmarker\ntail, plus the body's own), so the reference
    /// line broke across physical lines and the rotation extractor — which
    /// matches one line — silently dropped every real artifact from the
    /// index. Every summary is one line, so every line is one line.
    #[test]
    fn a_real_spill_line_is_one_physical_line() {
        // The acceptance's `print('B' * 200000)` shape: multi-line body,
        // big enough to be summarized, trailing newline included.
        let body = format!("{}\n", "B".repeat(200_000));
        let summary = summary_of(&body);
        assert!(!summary.contains('\n'), "summary collapses to one line");
        // Even a small multi-line body flattens — the line contract is
        // unconditional.
        assert_eq!(summary_of("a\nb"), "a b");

        let line = artifact_line("art_0002", "stdout", 200_001, &summary);
        assert_eq!(
            line.matches('\n').count(),
            0,
            "the line is one line: {line}"
        );
        assert!(
            line.starts_with("artifact art_0002 (stdout, 200001 bytes): "),
            "{line}"
        );
        assert!(line.contains(SUMMARY_MARKER), "{line}");
        assert!(
            line.ends_with(" — obs.fetch('art_0002') for the full body"),
            "{line}"
        );
    }

    #[test]
    fn spill_queues_the_event_and_notice_queues_a_line() {
        let (_tmp, hub) = hub();
        hub.spill("stdout", "body").unwrap();
        hub.notice("heads up".into());
        let queued = hub.take_queued();
        assert!(matches!(
            &queued[0],
            CellEvent::Artifact { capture_id, kind, bytes, summary }
                if capture_id == "art_0001" && kind == "stdout" && *bytes == 4 && summary == "body"
        ));
        assert!(matches!(&queued[1], CellEvent::Notice { text } if text == "heads up"));
        assert!(hub.take_queued().is_empty(), "drain empties the queue");
    }

    /// `obs.emit` inline vs spill cut-over, and `obs.fetch` — the host side
    /// of the face, no worker needed.
    #[tokio::test]
    async fn emit_splits_small_from_large_and_fetch_returns_the_body() {
        let (_tmp, hub) = hub();
        let hub = Arc::new(hub);
        let emit = EmitCall {
            hub: Arc::clone(&hub),
        };
        let fetch = FetchCall {
            hub: Arc::clone(&hub),
        };

        // Small: one inline notice, nothing stored.
        let out = emit
            .call(vec![json!("short note"), json!("text")])
            .await
            .unwrap();
        assert_eq!(out, json!({"inlined": true}));

        // Large: stored and referenced; the id fetches the body back.
        let big = "x".repeat(EMIT_INLINE_MAX + 1);
        let out = emit
            .call(vec![json!(big.clone()), json!("report")])
            .await
            .unwrap();
        let id = out["capture_id"].as_str().unwrap().to_string();
        assert_eq!(id, "art_0001");
        assert_eq!(out["kind"], Value::Null); // not in the return shape
        let body = fetch.call(vec![json!(&id)]).await.unwrap();
        assert_eq!(body, json!(big));

        // Unknown ids fail with the way back spelled out.
        let err = fetch.call(vec![json!("art_9999")]).await.unwrap_err();
        assert!(err.to_string().contains("art_"), "{err}");
    }

    #[tokio::test]
    async fn emit_accepts_a_bare_value_and_refuses_a_bare_kind() {
        let (_tmp, hub) = hub();
        let emit = EmitCall { hub: Arc::new(hub) };
        assert_eq!(
            emit.call(vec![json!("solo")]).await.unwrap(),
            json!({"inlined": true})
        );
        assert!(emit.call(vec![]).await.is_err());
        assert!(emit.call(vec![json!("v"), json!("")]).await.is_err());
    }
}
