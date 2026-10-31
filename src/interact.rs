//! The cell-interaction seam (action-executor-design OV-6): a cell reaches
//! the human through one host-call throat — a policy `Ask` suspends at the
//! dispatch chokepoint, `ask.user` suspends in its own host call — and this
//! crate stays free of agent-base vocabulary by speaking JSON and a
//! two-method [`InteractionBridge`] that the adapter implements.
//!
//! Suspension discipline lives with the caller's `ExecCtx` (answer / cancel /
//! watchdog); an implementation must release promptly on the run's cancel
//! token, and `Err(reason)` here means the interaction itself failed — the
//! engine refuses fail-closed and the reason rides the model-visible error.

use std::sync::Arc;

use async_trait::async_trait;
use phi_cap::Capability;
use phi_ns::{HostCall, MethodSpec, NamespaceProvider, NsError, NsObject, WorkerSink, m};
use serde_json::Value;

use crate::policy::PolicyDecision;

/// What the consent hook is asked to resolve: policy answered
/// [`PolicyDecision::Ask`] for one call, and the engine suspends until this
/// gives the **final** decision — the journal's one row records that verdict,
/// never an intermediate hold (inventory §3.4: decide → journal → effect).
#[derive(Debug, Clone, Copy)]
pub struct ConsentRequest<'a> {
    /// Coarse class of the held call (the policy key).
    pub cap: Capability,
    /// Injected function name (`"sh.run"`).
    pub fn_name: &'a str,
    /// The call's argument payload — what a human must see to decide.
    /// `None` when the chokepoint only holds a digest (escape hatch).
    pub args: Option<&'a Value>,
    /// Stable argument digest (what the journal records).
    pub args_digest: &'a str,
    /// 0-based cell index within the step.
    pub cell_index: usize,
    /// Step counter (one `execute()` = one step).
    pub step_index: usize,
}

/// The human-in-the-loop seam. Implemented by whoever owns the human
/// relationship (the adapter bridges onto the run's interaction channel);
/// the engine only calls it, at the same single throat policy and journal use.
#[async_trait]
pub trait InteractionBridge: Send + Sync {
    /// Resolve a held call to its final decision. `Err(reason)` = the
    /// interaction could not be answered (cancel / timeout / nothing armed):
    /// the engine refuses fail-closed and the reason rides the hold the model
    /// sees.
    async fn consent(&self, req: &ConsentRequest<'_>) -> Result<PolicyDecision, String>;

    /// Answer a cell's `ask.user(question, options)` call — `options` is the
    /// wire array the cell passed (each `{"id", "label", "note"?}`). Returns
    /// the answer as JSON: `{"picked": {"id", "label"}}` or `{"skipped": true}`.
    async fn ask(&self, question: &str, options: &[Value]) -> Result<Value, String>;
}

/// Tracks in-flight interaction suspensions so the round timeout can tell
/// compute apart from human time (failure table: an unanswered suspension is
/// bounded by the interaction watchdog + cancel token, not by the round's
/// hard timeout — which would kill a slow-but-answered consent).
#[derive(Debug, Default)]
pub struct SuspensionClock {
    /// How many suspensions are in flight right now.
    paused: std::sync::atomic::AtomicUsize,
    /// Bumped on every enter/exit — the wakeup counter for [`Self::bound`].
    version: std::sync::atomic::AtomicU64,
    /// Wakes [`Self::bound`] when `version` moves.
    notify: tokio::sync::Notify,
}

impl SuspensionClock {
    /// True while an interaction is suspended.
    pub fn is_suspended(&self) -> bool {
        self.paused.load(std::sync::atomic::Ordering::SeqCst) > 0
    }

    /// One suspension in flight. The guard freezes the round budget for its
    /// whole lifetime (nested suspensions share one freeze).
    pub fn enter(&self) -> SuspensionGuard<'_> {
        self.paused
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.notify.notify_waiters();
        SuspensionGuard { clock: self }
    }

    /// Wake when `version` has moved past `seen` (registered before the
    /// state re-read, so a change cannot slip between the two).
    async fn changed(&self, seen: u64) {
        let waiter = self.notify.notified();
        tokio::pin!(waiter);
        waiter.as_mut().enable();
        if self.version.load(std::sync::atomic::Ordering::SeqCst) != seen {
            return;
        }
        waiter.await;
    }

    /// Race `work` against a compute budget, freezing that budget for as long
    /// as an interaction is suspended. Returns `None` when the budget runs
    /// out (the caller recycles the worker), `Some(out)` otherwise.
    pub async fn bound<T>(
        &self,
        budget: std::time::Duration,
        work: impl Future<Output = T>,
    ) -> Option<T> {
        tokio::pin!(work);
        let mut left = budget;
        loop {
            let tick = tokio::time::Instant::now();
            let seen = self.version.load(std::sync::atomic::Ordering::SeqCst);
            if self.is_suspended() {
                // Human time: no budget is consumed while suspended.
                tokio::select! {
                    biased;
                    out = &mut work => return Some(out),
                    _ = self.changed(seen) => continue,
                }
            }
            tokio::select! {
                biased;
                out = &mut work => return Some(out),
                _ = self.changed(seen) => {
                    // Whatever elapsed since this tick was compute time.
                    left = left.saturating_sub(tick.elapsed());
                    continue;
                }
                _ = tokio::time::sleep(left) => return None,
            }
        }
    }
}

/// One in-flight suspension ([`SuspensionClock::enter`]'s guard).
pub struct SuspensionGuard<'a> {
    clock: &'a SuspensionClock,
}

impl Drop for SuspensionGuard<'_> {
    fn drop(&mut self) {
        self.clock
            .paused
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        self.clock
            .version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.clock.notify.notify_waiters();
    }
}

/// The bridge plus its clock, as the chokepoint and the `ask.user` host call
/// see it: every suspension freezes the round budget for its duration.
pub(crate) struct InteractionSlot {
    bridge: Arc<dyn InteractionBridge>,
    clock: Arc<SuspensionClock>,
}

impl InteractionSlot {
    pub(crate) fn new(bridge: Arc<dyn InteractionBridge>, clock: Arc<SuspensionClock>) -> Self {
        Self { bridge, clock }
    }

    pub(crate) async fn consent(&self, req: &ConsentRequest<'_>) -> Result<PolicyDecision, String> {
        let _frozen = self.clock.enter();
        self.bridge.consent(req).await
    }

    pub(crate) async fn ask(&self, question: &str, options: &[Value]) -> Result<Value, String> {
        let _frozen = self.clock.enter();
        self.bridge.ask(question, options).await
    }
}

/// Worker-side shim installed by [`NamespaceProvider::install`]: `ask.user`
/// crosses the host seam via `_phi_call` like every other method — the answer
/// is plain JSON (`{"picked": …}` / `{"skipped": true}`).
const PY_SHIM: &str = r#"
class AskSdk:
    def user(self, question, options):
        """Ask the user to pick from options ({id, label, note?}); returns
        {"picked": {"id", "label"}} or {"skipped": true}."""
        return _phi_call("ask.user", [question, options])


ask = AskSdk()
"#;

/// The `ask.*` face: one method, answered by the interaction bridge.
pub(crate) struct AskUserPack {
    slot: Arc<InteractionSlot>,
}

impl AskUserPack {
    pub(crate) fn new(slot: Arc<InteractionSlot>) -> Self {
        Self { slot }
    }

    /// The `ask.*` declarations — the pack's single declaration source.
    /// [`ExecutorBuilder::prompt_face`](crate::ExecutorBuilder::prompt_face)
    /// renders the prompt face from exactly these rows (提示面同源,
    /// sdk-assembly §3.4).
    pub(crate) fn method_table() -> Vec<MethodSpec> {
        vec![
            // No capabilities: asking a human touches no system surface, so
            // the decision key is `Pure` — policy still sees every call, and
            // the journal still records it (the throat has no exceptions).
            m(
                "ask.user",
                &[],
                "ask the user to pick between options ({id, label, note?}); returns {picked:{id,label}} or {skipped:true}",
                false,
            ),
        ]
    }
}

#[async_trait]
impl NamespaceProvider for AskUserPack {
    fn namespaces(&self) -> &'static [&'static str] {
        &["ask"]
    }

    fn methods(&self) -> Vec<MethodSpec> {
        Self::method_table()
    }

    async fn install(&self, sink: &mut dyn WorkerSink) -> Result<(), NsError> {
        sink.register_fn(
            "ask.user",
            Box::new(AskUserCall {
                slot: Arc::clone(&self.slot),
            }),
        )?;
        sink.eval(PY_SHIM).await
    }

    fn summarize(&self, _name: &str, obj: &NsObject) -> Option<String> {
        match obj.kind.as_str() {
            "AskSdk" => Some(String::new()),
            _ => None,
        }
    }
}

/// Host-side implementation of `ask.user`.
struct AskUserCall {
    slot: Arc<InteractionSlot>,
}

#[async_trait]
impl HostCall for AskUserCall {
    async fn call(&self, args: Vec<Value>) -> Result<Value, NsError> {
        let [question, options] = args.as_slice() else {
            return Err(NsError::Sink(
                "ask.user(question, options) expects a string and an option array".into(),
            ));
        };
        let question = question.as_str().ok_or_else(|| {
            NsError::Sink("ask.user(question, options) expects a string question".into())
        })?;
        let options = options.as_array().ok_or_else(|| {
            NsError::Sink("ask.user(question, options) expects an option array".into())
        })?;
        self.slot
            .ask(question, options)
            .await
            .map_err(|reason| NsError::Denied {
                method: "ask.user".to_string(),
                cap: Capability::Pure.to_string(),
                reason,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn the_budget_cuts_unsuspended_work_and_freezes_for_humans() {
        let clock = SuspensionClock::default();

        // No suspension: a slow future exceeds the budget and is cut.
        let slow = async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            "done"
        };
        assert_eq!(clock.bound(Duration::from_millis(100), slow).await, None);

        // Suspended the whole time: the budget never moves, work finishes.
        let guard = clock.enter();
        assert!(clock.is_suspended());
        let slow = async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            "done"
        };
        assert_eq!(
            clock.bound(Duration::from_millis(100), slow).await,
            Some("done")
        );
        drop(guard);
        assert!(!clock.is_suspended());
    }

    #[tokio::test(start_paused = true)]
    async fn a_suspension_in_the_middle_freezes_only_the_human_span() {
        let clock = Arc::new(SuspensionClock::default());

        // 30ms of compute, then a human reads for 1s (way past the budget),
        // then the work finishes — the round must survive the dialog.
        let work = {
            let clock = Arc::clone(&clock);
            async move {
                tokio::time::sleep(Duration::from_millis(30)).await;
                let guard = clock.enter();
                tokio::time::sleep(Duration::from_millis(1_000)).await;
                drop(guard);
                tokio::time::sleep(Duration::from_millis(30)).await;
                "done"
            }
        };
        assert_eq!(
            clock.bound(Duration::from_millis(100), work).await,
            Some("done")
        );
    }
}
