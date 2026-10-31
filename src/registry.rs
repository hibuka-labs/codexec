//! [`NamespaceRegistry`] — where capability packs land and every host call
//! is decided (codexec-design §5.1 / §8.1).
//!
//! Registration is fail-closed: a name must be declared by a pack's
//! `MethodSpec` before any implementation can stand behind it, and dispatch
//! looks that declaration up again — no undeclared call path exists. Every
//! dispatch runs policy + write-ahead journal at this one choke point
//! ("the hook goes on the single throat", not on every method).

use crate::artifacts::ArtifactHub;
use crate::interact::{InteractionBridge, InteractionSlot, SuspensionClock};
use crate::journal::JournalHandle;
use crate::observation::ExecError;
use crate::policy::{CallFacts, Policy, PolicyDecision, decide_and_journal, hold_error};
use phi_cap::Capability;
use phi_ns::capture::{CAPTURE_ID_KEY, CAPTURE_KEY, CaptureLedger, CaptureUse, face_of};
use phi_ns::{
    HostCall, ImageRef, MethodSpec, NamespaceProvider, NsError, check_provider_contract, help_doc,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// One registered host function: its decision key plus its implementation.
pub struct RegisteredFn {
    /// Coarse class used as the policy key (derived at registration).
    pub cap: Capability,
    /// Whether the return may carry images — derived from
    /// [`MethodSpec::multimodal`], so the harvest contract follows the
    /// declaration and is not re-stated per method.
    pub multimodal: bool,
    /// Capture role — derived from [`MethodSpec::capture`]: a `Mint` return
    /// mints a one-use id, a `Consume` call must spend one (inventory §3.2).
    pub capture: CaptureUse,
    /// Host-side implementation.
    pub call: Box<dyn HostCall>,
}

/// One harvested image, still tagged with where it came from.
#[derive(Debug, Clone)]
pub struct ScopedImage {
    /// 0-based cell index that produced it.
    pub cell_index: usize,
    /// The image reference for the model.
    pub image: ImageRef,
}

/// Shared function table (install writes, dispatch reads).
type FnTable = HashMap<String, Arc<RegisteredFn>>;

/// Assembles capability packs and dispatches their host calls.
pub struct NamespaceRegistry {
    fns: RwLock<FnTable>,
    specs: RwLock<HashMap<String, MethodSpec>>,
    roots: RwLock<Vec<String>>,
    packs: RwLock<Vec<Arc<dyn NamespaceProvider>>>,
    policy: Arc<dyn Policy>,
    journal: JournalHandle,
    /// The one-use capture ledger (inventory §3.2) — host-side, so a stub
    /// restart cannot lose it and no dispatch path skips it.
    captures: CaptureLedger,
    step_index: AtomicUsize,
    last_hold: Mutex<Option<HoldRecord>>,
    /// Images harvested from multimodal returns this round (§4.2).
    images: Mutex<Vec<ScopedImage>>,
    /// The human-in-the-loop seam (consent / `ask.user`), when the
    /// application mounted one. Without it, `Ask` stays a hold.
    interaction: Mutex<Option<Arc<InteractionSlot>>>,
    /// The artifact store + this round's queued observation events (M3c,
    /// action-executor-design §6) — mounted when the assembly opts in.
    /// Without it, cut bodies stay truncated exactly as before.
    artifacts: Mutex<Option<Arc<ArtifactHub>>>,
    /// Suspended-interaction clock — the round timeout freezes while a human
    /// is answering ([`SuspensionClock`]).
    clock: Arc<SuspensionClock>,
}

/// What a policy hold looked like — surfaced to the observation stream.
#[derive(Debug, Clone)]
struct HoldRecord {
    decision: PolicyDecision,
    method: String,
    cap: Capability,
    cell_index: usize,
    reason: Option<String>,
}

impl NamespaceRegistry {
    /// Create an empty registry with the application's policy and journal.
    pub fn new(policy: Arc<dyn Policy>, journal: JournalHandle) -> Self {
        Self {
            fns: RwLock::new(FnTable::new()),
            specs: RwLock::new(HashMap::new()),
            roots: RwLock::new(Vec::new()),
            packs: RwLock::new(Vec::new()),
            policy,
            journal,
            captures: CaptureLedger::new(),
            step_index: AtomicUsize::new(0),
            last_hold: Mutex::new(None),
            images: Mutex::new(Vec::new()),
            interaction: Mutex::new(None),
            artifacts: Mutex::new(None),
            clock: Arc::new(SuspensionClock::default()),
        }
    }

    /// The journal handle (the escape hatch and the gate share it).
    pub fn journal(&self) -> &JournalHandle {
        &self.journal
    }

    /// The one-use capture ledger — inspection/tests read it, dispatch writes.
    pub fn captures(&self) -> &CaptureLedger {
        &self.captures
    }

    /// The suspended-interaction clock (the round timeout freezes while a
    /// human is answering).
    pub fn clock(&self) -> &Arc<SuspensionClock> {
        &self.clock
    }

    /// Mount the interaction bridge: `Ask` suspends at the chokepoint, and
    /// the returned slot is what the `ask.user` face calls through (same
    /// clock, so every suspension freezes the round budget). One bridge per
    /// registry — the second mount replaces the first.
    pub(crate) fn mount_interaction(
        &self,
        bridge: Arc<dyn InteractionBridge>,
    ) -> Arc<InteractionSlot> {
        let slot = Arc::new(InteractionSlot::new(bridge, Arc::clone(&self.clock)));
        *self.interaction.lock().expect("interaction poisoned") = Some(Arc::clone(&slot));
        slot
    }

    /// The mounted bridge (the chokepoint's consent path).
    fn interaction(&self) -> Option<Arc<InteractionSlot>> {
        self.interaction
            .lock()
            .expect("interaction poisoned")
            .clone()
    }

    /// Mount the artifact store (M3c): the hub carries both the store the
    /// `obs.*` face reads/writes and the event queue the fold drains. One
    /// hub per registry — the store is never duplicated (§6.1: 词汇一套).
    /// The second mount replaces the first.
    pub(crate) fn mount_artifacts(&self, hub: Arc<ArtifactHub>) {
        *self.artifacts.lock().expect("artifacts poisoned") = Some(hub);
    }

    /// The mounted artifact hub, when the assembly opted in.
    pub fn artifacts(&self) -> Option<Arc<ArtifactHub>> {
        self.artifacts.lock().expect("artifacts poisoned").clone()
    }

    /// Stamp the step counter into subsequent journal rows / policy contexts.
    pub fn set_step_index(&self, step_index: usize) {
        self.step_index.store(step_index, Ordering::SeqCst);
    }

    /// Register a capability pack: validate its contract, pin its
    /// declarations, then let it install through the worker sink. Fail-closed
    /// at every step — nothing lands half-registered.
    pub async fn register_ns(
        &self,
        sink: &mut dyn phi_ns::WorkerSink,
        ns: Arc<dyn NamespaceProvider>,
    ) -> Result<(), NsError> {
        check_provider_contract(ns.as_ref()).map_err(NsError::Contract)?;

        {
            let mut roots = self.roots.write().expect("roots poisoned");
            for r in ns.namespaces() {
                if roots.iter().any(|e| e.as_str() == *r) {
                    return Err(NsError::NamespaceConflict((*r).to_string()));
                }
            }
            roots.extend(ns.namespaces().iter().map(|r| (*r).to_string()));
        }

        {
            let mut specs = self.specs.write().expect("specs poisoned");
            for m in ns.methods() {
                if specs.contains_key(m.name) {
                    return Err(NsError::NamespaceConflict(m.name.to_string()));
                }
                specs.insert(m.name.to_string(), m);
            }
        }

        ns.install(sink).await?;
        install_discovery_docs(sink, &ns.methods()).await?;
        self.packs.write().expect("packs poisoned").push(ns);
        Ok(())
    }

    /// Re-materialize the pinned packs into a fresh worker (worker-loss
    /// path). Declarations stay pinned — this only rebuilds the worker-side
    /// face: proxies, shims, and the help-protocol docs. User state does not
    /// come back across a reset (the `session_reset` contract stands), the
    /// capability names do.
    pub async fn reinstall(&self, sink: &mut dyn phi_ns::WorkerSink) -> Result<(), NsError> {
        for pack in self.packs() {
            let methods = pack.methods();
            pack.install(sink).await?;
            install_discovery_docs(sink, &methods).await?;
        }
        Ok(())
    }

    /// Register one host function by hand — **escape hatch / debug only**
    /// (codexec-design §5.1). Formal capabilities go through
    /// [`NamespaceRegistry::register_ns`], which derives caps from the
    /// declaration source. The explicit cap here is the caller's assertion.
    pub fn register_fn(
        &self,
        name: &str,
        cap: Capability,
        call: Box<dyn HostCall>,
    ) -> Result<(), NsError> {
        if self
            .specs
            .read()
            .expect("specs poisoned")
            .contains_key(name)
        {
            return Err(NsError::NamespaceConflict(format!(
                "{name} is already declared by a pack"
            )));
        }
        self.fns.write().expect("fns poisoned").insert(
            name.to_string(),
            Arc::new(RegisteredFn {
                cap,
                // Escape hatch: no declaration source, so nothing may be
                // harvested from the return and no capture is minted or spent.
                // Both contracts go through `insert_declared`, where the
                // declaration is the single source.
                multimodal: false,
                capture: CaptureUse::None,
                call,
            }),
        );
        Ok(())
    }

    /// Install-time registration from a pack's [`phi_ns::WorkerSink`]: the
    /// name must be one of the pack's declared methods, and its caps come
    /// from that declaration (single source).
    pub fn insert_declared(&self, name: &str, call: Box<dyn HostCall>) -> Result<(), NsError> {
        let spec = self
            .specs
            .read()
            .expect("specs poisoned")
            .get(name)
            .cloned()
            .ok_or_else(|| NsError::UndeclaredMethod(name.to_string()))?;
        let cap = spec.capability();
        self.fns.write().expect("fns poisoned").insert(
            name.to_string(),
            Arc::new(RegisteredFn {
                cap,
                multimodal: spec.multimodal,
                capture: spec.capture,
                call,
            }),
        );
        Ok(())
    }

    /// Declared method names — what the worker materializes proxies for.
    pub fn declared_names(&self) -> Vec<String> {
        self.specs
            .read()
            .expect("specs poisoned")
            .keys()
            .cloned()
            .collect()
    }

    /// The packs, for snapshot assembly and lifecycle fan-out.
    pub fn packs(&self) -> Vec<Arc<dyn NamespaceProvider>> {
        self.packs.read().expect("packs poisoned").clone()
    }

    /// Clear a previous round's policy hold and any undrained images or
    /// queued observation events.
    pub fn clear_hold(&self) {
        *self.last_hold.lock().expect("hold poisoned") = None;
        self.images.lock().expect("images poisoned").clear();
        if let Some(hub) = self.artifacts() {
            hub.take_queued();
        }
    }

    /// Take the round's policy hold, if any.
    pub fn take_hold(&self) -> Option<ExecError> {
        let hold = self.last_hold.lock().expect("hold poisoned").take()?;
        Some(hold_error(
            hold.decision,
            &hold.method,
            hold.cap,
            hold.cell_index,
            hold.reason,
        ))
    }

    /// Take every image harvested this round (cell order preserved).
    pub fn take_events(&self) -> Vec<ScopedImage> {
        std::mem::take(&mut *self.images.lock().expect("images poisoned"))
    }

    /// The single dispatch point: look up the declaration, decide, journal
    /// write-ahead, then call. Undeclared names fail closed.
    pub async fn dispatch(
        &self,
        fn_name: &str,
        args: Vec<serde_json::Value>,
        cell_index: usize,
    ) -> Result<serde_json::Value, NsError> {
        let f = self
            .fns
            .read()
            .expect("fns poisoned")
            .get(fn_name)
            .cloned()
            .ok_or_else(|| NsError::UndeclaredMethod(fn_name.to_string()))?;

        let wire = serde_json::Value::Array(args.clone());
        let args_digest = phi_ns::remote::args_digest(&wire);
        let interaction = self.interaction();
        let (decision, reason) = decide_and_journal(
            self.policy.as_ref(),
            &self.journal,
            &self.captures,
            interaction.as_deref(),
            CallFacts {
                cap: f.cap,
                fn_name,
                capture: f.capture,
                args_digest,
                args: Some(&wire),
                cell_index,
                step_index: self.step_index.load(Ordering::SeqCst),
            },
        )
        .await?;

        if !decision.is_allow() {
            return Err(self.refuse(decision, reason, fn_name, f.cap, cell_index));
        }

        let mut value = f.call.call(args).await?;

        // Multimodal contract (sdk-assembly §4.2): the declaration says the
        // return may carry images, so the choke point — not each pack — turns
        // them into model events. A malformed return is a contract violation,
        // not a silent drop.
        if f.multimodal {
            let images = ImageRef::from_wire(&value)?;
            let mut queue = self.images.lock().expect("images poisoned");
            queue.extend(
                images
                    .into_iter()
                    .map(|image| ScopedImage { cell_index, image }),
            );
        }

        // Capture contract (inventory §3.2): a look's return may carry what it
        // bound (`capture`); the choke point mints the one-use id and stamps it
        // back for the model and the journal. Only a declared `Mint` method may
        // mint — a stray descriptor elsewhere is inert.
        if f.capture == CaptureUse::Mint
            && let Some(obj) = value.as_object_mut()
            && let Some(binding) = obj.get(CAPTURE_KEY).cloned()
        {
            let id = self.captures.mint(face_of(fn_name), fn_name, binding);
            obj.insert(
                CAPTURE_ID_KEY.to_string(),
                serde_json::json!(id.to_string()),
            );
        }
        Ok(value)
    }

    /// The audit seam (layer 2, codexec-design §8.4): one mediated worker
    /// effect — classify, decide, journal write-ahead — then the hook lets
    /// the effect run. Any error here refuses the operation (fail-closed).
    pub async fn audit(
        &self,
        event: &str,
        args: serde_json::Value,
        rw: &str,
        cell_index: usize,
    ) -> Result<(), NsError> {
        let cap = crate::audit::classify(event, rw).ok_or_else(|| NsError::Denied {
            method: event.to_string(),
            cap: String::new(),
            reason: "unclassified audit event (mediation set drift)".into(),
        })?;
        let payload = args;
        let wire = serde_json::json!([event, payload, rw]);
        let args_digest = phi_ns::remote::args_digest(&wire);
        let interaction = self.interaction();
        let (decision, reason) = decide_and_journal(
            self.policy.as_ref(),
            &self.journal,
            &self.captures,
            interaction.as_deref(),
            CallFacts {
                cap,
                fn_name: event,
                capture: CaptureUse::None,
                args_digest,
                args: Some(&payload),
                cell_index,
                step_index: self.step_index.load(Ordering::SeqCst),
            },
        )
        .await?;
        if !decision.is_allow() {
            return Err(self.refuse(decision, reason, event, cap, cell_index));
        }
        Ok(())
    }

    /// Journal a non-host-fn effect (escape hatch) with the same write-ahead
    /// discipline. Returns the final decision (plus any interaction reason)
    /// so the caller can refuse to run.
    pub async fn journal_escape(
        &self,
        cap: Capability,
        fn_name: &str,
        args_digest: String,
        cell_index: usize,
    ) -> Result<(PolicyDecision, Option<String>), NsError> {
        let interaction = self.interaction();
        let resolved = decide_and_journal(
            self.policy.as_ref(),
            &self.journal,
            &self.captures,
            interaction.as_deref(),
            CallFacts {
                cap,
                fn_name,
                capture: CaptureUse::None,
                args_digest,
                args: None,
                cell_index,
                step_index: self.step_index.load(Ordering::SeqCst),
            },
        )
        .await?;
        if !resolved.0.is_allow() {
            *self.last_hold.lock().expect("hold poisoned") = Some(HoldRecord {
                decision: resolved.0,
                method: fn_name.to_string(),
                cap,
                cell_index,
                reason: resolved.1.clone(),
            });
        }
        Ok(resolved)
    }

    /// Record the hold and map it onto the wire error the hook/shim raises.
    fn refuse(
        &self,
        decision: PolicyDecision,
        reason: Option<String>,
        method: &str,
        cap: Capability,
        cell_index: usize,
    ) -> NsError {
        *self.last_hold.lock().expect("hold poisoned") = Some(HoldRecord {
            decision,
            method: method.to_string(),
            cap,
            cell_index,
            reason: reason.clone(),
        });
        match decision {
            PolicyDecision::Deny => NsError::Denied {
                method: method.to_string(),
                cap: cap.to_string(),
                reason: reason.unwrap_or_else(|| "policy denied".into()),
            },
            _ => NsError::Suspended {
                method: method.to_string(),
                cap: cap.to_string(),
            },
        }
    }
}

/// Discovery install (help protocol): push each declaration's `help_doc`
/// view into the worker so `help("sh.run")` answers from the declaration —
/// a shim's docstring is never the answer, and can never drift from
/// `MethodSpec`. Runs at every install and re-install; the payload is a
/// plain `name -> text` map (JSON literals are valid Python literals).
async fn install_discovery_docs(
    sink: &mut dyn phi_ns::WorkerSink,
    methods: &[MethodSpec],
) -> Result<(), NsError> {
    let mut map = serde_json::Map::new();
    for m in methods {
        map.insert(m.name.to_string(), serde_json::Value::String(help_doc(m)));
    }
    let code = format!("_phi_define_docs({})", serde_json::Value::Object(map));
    sink.eval(&code).await
}
