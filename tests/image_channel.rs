//! The multimodal return channel (sdk-assembly §4.2): a declared-multimodal
//! method's return is harvested into `CellEvent::Image` at the dispatch
//! choke point, the `alt` floor line lands in the text stream, and nothing
//! else is asserted — packs do not invent their own image channels.
//!
//! The pack here is a stand-in (`cam.snap` / `cam.tap` / `cam.bad`) so the
//! seam is tested without a browser: real screenshots arrive through the
//! same contract in the assembled layer.

use async_trait::async_trait;
use codexec::{
    Action, CellEvent, CodeCellExecutor, ExecutorBuilder, FileJournal, JournalHandle, Limits,
    MethodPolicy, PolicyDecision, PythonWorker,
};
use phi_cap::{device_capture, device_input};
use phi_ns::{ImageRef, MethodSpec, NamespaceProvider, NsError, NsObject, WorkerSink, m};
use std::sync::Arc;

/// Host side of `cam.snap` / `cam.bad` / `cam.tap`.
struct CamSnap {
    wire: fn() -> serde_json::Value,
}

#[async_trait]
impl phi_ns::HostCall for CamSnap {
    async fn call(&self, _args: Vec<serde_json::Value>) -> Result<serde_json::Value, NsError> {
        Ok((self.wire)())
    }
}

#[async_trait]
impl phi_ns::HostCall for CamTap {
    async fn call(&self, _args: Vec<serde_json::Value>) -> Result<serde_json::Value, NsError> {
        Ok(serde_json::json!({"tapped": true}))
    }
}

struct CamTap;

/// A tiny capture pack: `snap` returns one image, `bad` returns one without
/// an `alt`, `tap` is a same-class device *input* for the policy split.
struct CamPack;

const CAM_SHIM: &str = r#"
class CamSdk:
    def snap(self):
        return _phi_call("cam.snap", [])
    def bad(self):
        return _phi_call("cam.bad", [])
    def tap(self):
        return _phi_call("cam.tap", [])
cam = CamSdk()
"#;

#[async_trait]
impl NamespaceProvider for CamPack {
    fn namespaces(&self) -> &'static [&'static str] {
        &["cam"]
    }

    fn methods(&self) -> Vec<MethodSpec> {
        vec![
            m(
                "cam.snap",
                &[device_capture(&["screen"])],
                "capture a picture; returns an image wire value",
                true,
            ),
            m(
                "cam.bad",
                &[device_capture(&["screen"])],
                "capture a picture but forget its alt (contract violation)",
                true,
            ),
            m(
                "cam.tap",
                &[device_input(&["screen"])],
                "touch the device; returns a small JSON receipt",
                false,
            ),
        ]
    }

    async fn install(&self, sink: &mut dyn WorkerSink) -> Result<(), NsError> {
        sink.register_fn("cam.snap", Box::new(CamSnap { wire: good_wire }))?;
        sink.register_fn("cam.bad", Box::new(CamSnap { wire: bad_wire }))?;
        sink.register_fn("cam.tap", Box::new(CamTap))?;
        sink.eval(CAM_SHIM).await
    }

    fn summarize(&self, _name: &str, obj: &NsObject) -> Option<String> {
        match obj.kind.as_str() {
            "CamSdk" => Some(String::new()),
            _ => None,
        }
    }
}

fn good_wire() -> serde_json::Value {
    ImageRef::from_path("image/png", "/tmp/phi-test-shot.png", "a red export button").to_wire()
}

fn bad_wire() -> serde_json::Value {
    // The bytes exist; the mandatory description does not.
    serde_json::json!({"path": "/tmp/phi-test-shot.png", "mime": "image/png", "alt": "  "})
}

async fn executor_with(
    limits: Limits,
    policy: std::sync::Arc<dyn codexec::Policy>,
    journal_path: &std::path::Path,
) -> CodeCellExecutor<PythonWorker> {
    let journal = FileJournal::open(journal_path).expect("journal opens");
    ExecutorBuilder::new(JournalHandle::new(Box::new(journal)))
        .with_policy(policy)
        .with_limits(limits)
        .with_ns(CamPack)
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

/// Rule 1 + rule 3 together: the event carries the reference, the text
/// stream carries the `alt`, and no image payload smuggles through `stdout`.
#[tokio::test]
async fn multimodal_return_lands_as_an_event_with_an_alt_floor_line() {
    let dir = tempfile::tempdir().unwrap();
    let limits = Limits::default();
    let mut executor = executor_with(
        limits,
        Arc::new(codexec::AllowAll) as Arc<dyn codexec::Policy>,
        &dir.path().join("j.jsonl"),
    )
    .await;

    let obs = executor.execute(cells(&["shot = cam.snap()"])).await;
    assert!(obs.error.is_none(), "{obs:?}");

    assert_eq!(obs.events.len(), 1, "{obs:?}");
    let CellEvent::Image(image) = &obs.events[0] else {
        panic!("expected an image event, got {:?}", obs.events[0]);
    };
    assert_eq!(image.mime, "image/png");
    assert_eq!(image.alt, "a red export button");
    assert_eq!(
        image.source,
        phi_ns::ImageSource::Path("/tmp/phi-test-shot.png".into())
    );

    // The floor line is the model's floor when the picture is trimmed.
    assert!(obs.stdout.contains("image: a red export button"), "{obs:?}");
    // Rule 1: no image payload in the text stream.
    assert!(!obs.stdout.contains("inline_base64"), "{obs:?}");
    assert!(!obs.stdout.contains("iVBOR"), "{obs:?}");
}

/// Rule 3 is enforced at the choke point: no `alt`, no silent drop —
/// the call fails as a contract violation and nothing is harvested.
#[tokio::test]
async fn a_missing_alt_fails_the_call_instead_of_dropping_quietly() {
    let dir = tempfile::tempdir().unwrap();
    let mut executor = executor_with(
        Limits::default(),
        Arc::new(codexec::AllowAll) as Arc<dyn codexec::Policy>,
        &dir.path().join("j.jsonl"),
    )
    .await;

    let obs = executor.execute(cells(&["cam.bad()"])).await;
    let Some(err) = &obs.error else {
        panic!("expected the contract violation to surface, got {obs:?}");
    };
    let text = err.to_string();
    assert!(text.contains("alt"), "{text}");
    assert!(obs.events.is_empty(), "{obs:?}");
}

/// When the event budget runs out the pictures go, their sentences stay.
#[tokio::test]
async fn the_event_budget_drops_pictures_but_never_their_alt_lines() {
    let dir = tempfile::tempdir().unwrap();
    let limits = Limits {
        events_max: 1,
        ..Limits::default()
    };
    let mut executor = executor_with(
        limits,
        Arc::new(codexec::AllowAll) as Arc<dyn codexec::Policy>,
        &dir.path().join("j.jsonl"),
    )
    .await;

    let obs = executor.execute(cells(&["cam.snap()", "cam.snap()"])).await;
    assert!(obs.error.is_none(), "{obs:?}");
    assert_eq!(obs.events.len(), 1, "budget: {events_max}", events_max = 1);
    assert_eq!(
        obs.stdout.matches("image: a red export button").count(),
        2,
        "{obs:?}"
    );
}

/// `MethodPolicy` is the posture "input asks, capture flows" needs: `cam.tap`
/// (device:input) and `cam.snap` (device:capture) both resolve to the `Device`
/// class, so only the method-name table can split them.
#[tokio::test]
async fn method_policy_splits_two_faces_of_one_class() {
    let dir = tempfile::tempdir().unwrap();
    let policy = MethodPolicy::new(PolicyDecision::Allow).with("cam.tap", PolicyDecision::Ask);
    let mut executor = executor_with(
        Limits::default(),
        Arc::new(policy) as Arc<dyn codexec::Policy>,
        &dir.path().join("j.jsonl"),
    )
    .await;

    let held = executor.execute(cells(&["cam.tap()"])).await;
    assert!(held.is_policy_hold(), "{held:?}");
    assert!(held.events.is_empty(), "{held:?}");

    let allowed = executor.execute(cells(&["cam.snap()"])).await;
    assert!(allowed.error.is_none(), "{allowed:?}");
    assert_eq!(allowed.events.len(), 1, "{allowed:?}");
}

/// Cross-cell residency with the pack assembled — the §10 touchstone shape:
/// whatever one cell left behind, the next cell can use.
#[tokio::test]
async fn the_touchstone_shape_still_runs_with_a_pack_assembled() {
    let dir = tempfile::tempdir().unwrap();
    let mut executor = executor_with(
        Limits::default(),
        Arc::new(codexec::AllowAll) as Arc<dyn codexec::Policy>,
        &dir.path().join("j.jsonl"),
    )
    .await;

    let obs = executor
        .execute(cells(&[
            "shots = [cam.snap(), cam.snap()]",
            "print(len(shots), shots[0]['alt'])",
        ]))
        .await;
    assert!(obs.error.is_none(), "{obs:?}");
    assert!(obs.stdout.contains("2 a red export button"), "{obs:?}");
}
