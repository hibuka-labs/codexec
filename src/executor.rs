//! [`CodeCellExecutor`] — one step = one round of blocks against one worker.
//!
//! The engine's outer face: parse → validate → execute → fold everything into
//! an [`Observation`]. It owns the policy-hold precedence (hold wins over any
//! cell error), the round budget, the per-cell `namespace:` snapshot line, and
//! the no-replay reset path (codexec-design §7).
//!
//! Assembly is the [`ExecutorBuilder`] face (sdk-assembly §3.4): one
//! `.with_ns(...)` line per capability pack — add one and a capability
//! appears, remove one and it disappears.

use crate::action::{Action, ParseError, parse_actions};
use crate::artifacts::{ArtifactHub, ObsPack};
use crate::interact::{AskUserPack, InteractionBridge};
use crate::journal::{JournalHandle, cell_entry_for};
use crate::lifecycle::Lifecycle;
use crate::limits::{Limits, RoundBudget, TRUNCATED};
use crate::observation::{CellEvent, ExecError, Observation};
use crate::policy::{DenyAll, Policy};
use crate::protocol::BlockSpec;
use crate::registry::{NamespaceRegistry, ScopedImage};
use crate::worker::{RoundResult, Worker};
use phi_ns::{NamespaceProvider, api_doc, compose_snapshot};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Drives one resident worker through steps of code cells.
pub struct CodeCellExecutor<W: Worker> {
    registry: Arc<NamespaceRegistry>,
    limits: Limits,
    lifecycle: Lifecycle,
    worker: Option<W>,
    spawn: Box<dyn Fn() -> Result<W, ExecError> + Send + Sync>,
    step_index: usize,
    /// Why the last respawn left no usable worker, if it did.
    respawn_error: Option<String>,
}

impl<W: Worker> CodeCellExecutor<W> {
    /// Wrap a live worker. `spawn` builds a replacement after a crash/timeout
    /// — the engine never replays UI across that boundary, it only restarts.
    pub fn new(
        worker: W,
        spawn: impl Fn() -> Result<W, ExecError> + Send + Sync + 'static,
        registry: Arc<NamespaceRegistry>,
        limits: Limits,
    ) -> Self {
        let mut me = Self {
            registry,
            limits,
            lifecycle: Lifecycle::new(),
            worker: Some(worker),
            spawn: Box::new(spawn),
            step_index: 0,
            respawn_error: None,
        };
        me.lifecycle.on_worker_up();
        me
    }

    /// Install a capability pack through the live worker (assembly step).
    pub async fn install(
        &mut self,
        pack: Arc<dyn NamespaceProvider>,
    ) -> Result<(), phi_ns::NsError> {
        let registry = Arc::clone(&self.registry);
        let worker = self
            .worker
            .as_mut()
            .ok_or_else(|| phi_ns::NsError::Sink("no worker to install into".into()))?;
        registry.register_ns(worker, pack).await
    }

    /// True while code can run — what gates the escape hatch.
    pub fn is_session_alive(&self) -> bool {
        self.lifecycle.is_alive() && self.worker.as_ref().is_some_and(|w| w.is_alive())
    }

    /// The registry (policy, journal, packs).
    pub fn registry(&self) -> &Arc<NamespaceRegistry> {
        &self.registry
    }

    /// The round budgets this executor runs with (hosts size their own
    /// watchdogs from this, never from a duplicated constant).
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Session state machine (for hosts that surface `session_reset`).
    pub fn lifecycle(&self) -> &Lifecycle {
        &self.lifecycle
    }

    /// Parse a model response and run it as one step.
    pub async fn execute_text(&mut self, text: &str) -> Result<Observation, ParseError> {
        let actions = parse_actions(text)?;
        Ok(self.execute(actions).await)
    }

    /// Run one step: all cells as one round (D4), shared variables, one quota.
    pub async fn execute(&mut self, actions: Vec<Action>) -> Observation {
        self.step_index += 1;
        self.registry.set_step_index(self.step_index);
        self.registry.clear_hold();

        // Reset path: this cell does not run; the model re-observes first.
        if self.lifecycle.needs_reset_report() {
            self.respawn().await;
            return Observation {
                error: Some(Lifecycle::session_reset_error()),
                ..Observation::empty()
            };
        }

        if self.worker.is_none() {
            self.respawn().await;
        }
        if self.worker.is_none() {
            let why = self
                .respawn_error
                .take()
                .map(|w| format!(" ({w})"))
                .unwrap_or_default();
            return Observation {
                error: Some(ExecError::Worker(format!("no worker available{why}"))),
                ..Observation::empty()
            };
        }

        if actions.is_empty() {
            return Observation::empty();
        }

        // Write-ahead ledger (§8.1): one row per cell before anything runs —
        // pure Python effects never cross the host-call seam, so this row is
        // the only trace a cell is guaranteed to leave. The row means "handed
        // to the worker": a hold or compile error may stop the round early,
        // and whether a cell executed lives in the observation stream. A
        // failed row aborts the step (fail-closed); on a mid-sequence failure
        // the already-written prefix stands as submitted attempts, and the
        // step error below is the cancellation record.
        for (cell_index, a) in actions.iter().enumerate() {
            let entry = cell_entry_for(a.intent(), a.code(), cell_index, self.step_index);
            if let Err(e) = self.registry.journal().record(entry) {
                return Observation {
                    error: Some(ExecError::Journal(format!(
                        "cell row {cell_index}: {e} (fail-closed)"
                    ))),
                    ..Observation::empty()
                };
            }
        }

        let blocks: Vec<BlockSpec> = actions
            .iter()
            .map(|a| BlockSpec {
                intent: a.intent().to_string(),
                code: a.code().to_string(),
            })
            .collect();

        let timeout_ms = self.limits.timeout_ms;
        // The hard timeout bounds compute, never human time: the budget
        // freezes while an interaction is suspended (OV-6 — a consent dialog
        // may read slowly; the worker did not get slower).
        let clock = Arc::clone(self.registry.clock());
        let result = {
            let worker = self.worker.as_mut().expect("worker present above");
            clock
                .bound(Duration::from_millis(timeout_ms), worker.exec(blocks))
                .await
        };

        match result {
            None => {
                self.lose_worker();
                let mut obs = Observation {
                    error: Some(ExecError::Timeout { timeout_ms }),
                    ..Observation::empty()
                };
                // Pictures taken before the kill still happened — fold them.
                self.drain_images_into(&mut obs);
                obs
            }
            Some(Err(e)) => {
                // Protocol/channel failure: the worker is no longer trustworthy.
                self.lose_worker();
                let mut obs = Observation {
                    error: Some(e),
                    ..Observation::empty()
                };
                self.drain_images_into(&mut obs);
                obs
            }
            Some(Ok(round)) => self.fold_round(round),
        }
    }

    /// Fold whatever the round harvested into an out-of-band observation —
    /// images and any queued observation events (the round died mid-flight;
    /// what happened before the kill still happened).
    fn drain_images_into(&self, obs: &mut Observation) {
        let mut budget = RoundBudget::new();
        for scoped in self.registry.take_events() {
            self.fold_image(obs, &mut budget, scoped);
        }
        if let Some(hub) = self.registry.artifacts() {
            for ev in hub.take_queued() {
                if budget.charge_event(&self.limits) {
                    obs.events.push(ev);
                }
            }
        }
    }

    /// Spill a cut body into the artifact store (M3c, action-executor-design
    /// §6): the dropped tail is not dead content — the whole body lands in
    /// the store and the queued event carries summary+ref. Without a mounted
    /// store (or on a store failure) the truncation marker stands, exactly as
    /// before — never silent either way.
    fn spill_cut(&self, kind: &str, body: &str) {
        if let Some(hub) = self.registry.artifacts()
            && let Err(why) = hub.spill(kind, body)
        {
            tracing::warn!(kind, error = %why, "artifact spill failed; the cut body is lost");
        }
    }

    fn lose_worker(&mut self) {
        if let Some(w) = self.worker.as_mut() {
            w.kill();
        }
        self.lifecycle.on_worker_lost();
    }

    async fn respawn(&mut self) {
        self.respawn_error = None;
        if let Some(w) = self.worker.as_mut() {
            w.kill();
        }
        self.worker = (self.spawn)().ok();
        let Some(mut w) = self.worker.take() else {
            return;
        };
        // Capability names survive a worker loss: re-materialize the pinned
        // packs (proxies, shims, help docs) into the fresh interpreter. User
        // state does not come back — the `session_reset` contract stands. A
        // half-materialized worker is worse than none (help would answer
        // from nothing while the prompt advertises the names), so fail
        // closed and say why on the next step's "no worker" error.
        match self.registry.reinstall(&mut w).await {
            Ok(()) => {
                self.worker = Some(w);
                self.lifecycle.on_worker_up();
            }
            Err(e) => {
                w.kill();
                self.respawn_error = Some(format!("pack reinstall failed: {e}"));
            }
        }
    }

    fn fold_round(&mut self, round: RoundResult) -> Observation {
        let mut obs = Observation::empty();
        let mut budget = RoundBudget::new();
        let packs = self.registry.packs();
        let pack_refs: Vec<&dyn NamespaceProvider> = packs
            .iter()
            .map(|p| p.as_ref() as &dyn NamespaceProvider)
            .collect();
        let mut images = self.registry.take_events();

        for block in &round.blocks {
            let (out, cut) = budget.charge_stdout(&block.stdout, &self.limits);
            obs.stdout.push_str(&out);
            if cut {
                obs.stdout.push_str(TRUNCATED);
                self.spill_cut("stdout", &block.stdout);
            }
            let (err, cut) = budget.charge_stderr(&block.stderr, &self.limits);
            obs.stderr.push_str(&err);
            if cut {
                obs.stderr.push_str(TRUNCATED);
                self.spill_cut("stderr", &block.stderr);
            }

            // One `namespace: …` line per cell, folded into the text stream.
            let snap = compose_snapshot(&block.ns, &pack_refs);
            let (snap, cut) = budget.charge_stdout(&snap, &self.limits);
            if !obs.stdout.is_empty() && !obs.stdout.ends_with('\n') {
                obs.stdout.push('\n');
            }
            obs.stdout.push_str(&snap);
            if cut {
                obs.stdout.push_str(TRUNCATED);
            }
            obs.stdout.push('\n');

            // Images this cell produced ride in as events; their `alt` line
            // lands in the text stream right here (sdk-assembly §4.2 rule 3).
            let (mine, rest): (Vec<ScopedImage>, Vec<ScopedImage>) = images
                .into_iter()
                .partition(|s| s.cell_index == block.index);
            images = rest;
            for scoped in mine {
                self.fold_image(&mut obs, &mut budget, scoped);
            }
        }
        // Anything not matched to a block still gets folded — the bytes
        // happened; only their cell attribution is imperfect.
        for scoped in images {
            self.fold_image(&mut obs, &mut budget, scoped);
        }

        // M3c (action-executor-design §6): observation events queued this
        // round — spills minted at the cut points above and values recorded
        // on purpose via `obs.emit`. The summary+ref line lives on the event,
        // the adapters render it; the event budget is the real floor.
        if let Some(hub) = self.registry.artifacts() {
            for ev in hub.take_queued() {
                if budget.charge_event(&self.limits) {
                    obs.events.push(ev);
                }
            }
        }

        // Precedence: a policy hold outranks any cell-level error — the step
        // halted on the audit decision, not on the raise it produced.
        if let Some(hold) = self.registry.take_hold() {
            obs.error = Some(hold);
            return obs;
        }
        if let Some(err) = round.compile_error {
            obs.error = Some(ExecError::CompileError {
                index: round.compile_error_index.unwrap_or(0),
                message: err.message,
            });
            return obs;
        }
        for block in &round.blocks {
            if let Some(e) = &block.error {
                let mut message = e.message.clone();
                if let Some(tb) = &e.traceback {
                    message.push('\n');
                    message.push_str(tb);
                }
                obs.error = Some(ExecError::CellError {
                    index: block.index,
                    kind: e.kind.clone(),
                    message,
                });
                return obs;
            }
        }
        obs
    }

    /// Fold one harvested image: the model gets the event, and the text
    /// stream gets the `alt` floor line — the picture may be dropped by the
    /// event budget, the sentence about it must not be (§4.2 rule 3).
    fn fold_image(&self, obs: &mut Observation, budget: &mut RoundBudget, scoped: ScopedImage) {
        let floor = format!("image: {}\n", scoped.image.alt);
        let (line, cut) = budget.charge_stdout(&floor, &self.limits);
        if !obs.stdout.is_empty() && !obs.stdout.ends_with('\n') {
            obs.stdout.push('\n');
        }
        obs.stdout.push_str(&line);
        if cut {
            obs.stdout.push_str(TRUNCATED);
        }
        if budget.charge_event(&self.limits) {
            obs.events.push(CellEvent::Image(scoped.image));
        }
    }
}

/// The assembly face (sdk-assembly §3.4). The engine never imports a pack;
/// the application lines them up:
///
/// ```ignore
/// let engine = ExecutorBuilder::new(journal)
///     .with_policy(MyPolicy)          // policy always lives outside the engine
///     .with_ns(PhiNsShell::builtin()) // sh.*
///     .with_ns(PhiNsBrowser::new(cfg))// b.*
///     .build(|registry| PythonWorker::spawn(registry, limits))
///     .await?;
/// ```
///
/// No feature-flag branches: remove a `.with_ns` line and the capability is
/// gone.
pub struct ExecutorBuilder {
    policy: Arc<dyn Policy>,
    journal: JournalHandle,
    limits: Limits,
    packs: Vec<Arc<dyn NamespaceProvider>>,
    interaction: Option<Arc<dyn InteractionBridge>>,
    /// A consent-only bridge: `Ask` suspends for a human, but the cell face
    /// gains no `ask.user` (see [`Self::with_consent`]).
    consent: Option<Arc<dyn InteractionBridge>>,
    artifacts_dir: Option<PathBuf>,
}

impl ExecutorBuilder {
    /// Start assembling. Policy defaults to [`DenyAll`] — fail-closed until
    /// the application states its opinion — and the journal is mandatory:
    /// audit cannot be turned off.
    pub fn new(journal: JournalHandle) -> Self {
        Self {
            policy: Arc::new(DenyAll),
            journal,
            limits: Limits::default(),
            packs: Vec::new(),
            interaction: None,
            consent: None,
            artifacts_dir: None,
        }
    }

    /// The application's decision maker (the engine only calls it).
    pub fn with_policy(mut self, policy: impl Policy + 'static) -> Self {
        self.policy = Arc::new(policy);
        self
    }

    /// Round quotas and the hard timeout.
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Line one capability pack in. Installing happens at [`Self::build`].
    pub fn with_ns(mut self, pack: impl NamespaceProvider + 'static) -> Self {
        self.packs.push(Arc::new(pack));
        self
    }

    /// Mount the human-in-the-loop face (action-executor-design OV-6): a
    /// policy `Ask` suspends at the chokepoint and `ask.user` answers from the
    /// bridge. One line on; without it neither exists and `Ask` stays a hold.
    pub fn with_interaction(mut self, bridge: Arc<dyn InteractionBridge>) -> Self {
        self.interaction = Some(bridge);
        self
    }

    /// Mount a **consent-only** bridge: a policy `Ask` still suspends at the
    /// chokepoint and consults the bridge, but the cell face gains no
    /// `ask.user` — the host's tool road already has the picker as a tool,
    /// and a face that grows a name the host never asked for is a prompt cost
    /// on every run.
    ///
    /// [`Self::with_interaction`] wins when both are mounted: the ask face is
    /// the richer mount.
    pub fn with_consent(mut self, bridge: Arc<dyn InteractionBridge>) -> Self {
        self.consent = Some(bridge);
        self
    }

    /// Mount the artifact store (M3c, action-executor-design §6): cut bodies
    /// spill into `dir` and the `obs.emit` / `obs.fetch` face is installed.
    /// One line on; without it, cuts truncate exactly as before and there is
    /// no `obs.*` face.
    pub fn with_artifacts(mut self, dir: impl Into<PathBuf>) -> Self {
        self.artifacts_dir = Some(dir.into());
        self
    }

    /// The prompt face of what this engine will expose (提示面同源,
    /// sdk-assembly §3.4): `api_doc()` over exactly the packs [`Self::build`]
    /// installs — `with_interaction` / `with_artifacts` included. The
    /// application splices this into the system prompt, so the prompt can
    /// never advertise a name the worker won't have, nor miss one it will.
    /// Declaration source is `MethodSpec` either way; docs arrive on demand
    /// via `help(name)`.
    pub fn prompt_face(&self) -> String {
        let mut methods = Vec::new();
        for pack in &self.packs {
            methods.extend(pack.methods());
        }
        if self.interaction.is_some() {
            methods.extend(AskUserPack::method_table());
        }
        if self.artifacts_dir.is_some() {
            methods.extend(ObsPack::method_table());
        }
        api_doc(&methods)
    }

    /// Materialize: one registry, one worker, every pack installed through the
    /// worker seam (fail-closed — nothing lands half-registered).
    ///
    /// `spawn` builds the worker and is called again after a crash/timeout;
    /// it receives the registry the packs install into.
    pub async fn build<W: Worker>(
        self,
        spawn: impl Fn(Arc<NamespaceRegistry>) -> Result<W, ExecError> + Send + Sync + 'static,
    ) -> Result<CodeCellExecutor<W>, phi_ns::NsError> {
        let limits = self.limits;
        let registry = Arc::new(NamespaceRegistry::new(self.policy, self.journal));
        // One artifact hub per engine — mounted before anything can spill,
        // shared with the `obs.*` face installed below.
        let hub = self
            .artifacts_dir
            .map(|dir| Arc::new(ArtifactHub::new(dir)));
        if let Some(hub) = &hub {
            registry.mount_artifacts(Arc::clone(hub));
        }
        let worker = spawn(Arc::clone(&registry))
            .map_err(|e| phi_ns::NsError::Sink(format!("could not start worker: {e}")))?;

        // Respawn path: same factory, same registry the packs live in.
        let spawn_reg = Arc::clone(&registry);
        let mut executor = CodeCellExecutor::new(
            worker,
            move || spawn(Arc::clone(&spawn_reg)),
            registry,
            limits,
        );
        for pack in self.packs {
            executor.install(pack).await?;
        }
        if let Some(bridge) = self.interaction {
            // Same slot for the chokepoint and the `ask.user` face — both
            // suspensions freeze the round budget through its clock.
            let slot = executor.registry().mount_interaction(bridge);
            executor.install(Arc::new(AskUserPack::new(slot))).await?;
        } else if let Some(bridge) = self.consent {
            // Consent only: the chokepoint can still hold a call for a human,
            // but no `ask.user` face is installed (the face stays exactly what
            // the packs declare).
            executor.registry().mount_interaction(bridge);
        }
        if let Some(hub) = hub {
            executor.install(Arc::new(ObsPack::new(hub))).await?;
        }
        Ok(executor)
    }
}
