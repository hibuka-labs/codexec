//! Policy seam (codexec-design §8.1): the engine **calls** policy, never
//! implements it. No domain rules live here — what "risky" means is the
//! application's opinion, not the engine's.
//!
//! Also the adapter side that hooks this seam onto `phi-ns::remote::Gate`
//! ("policy.rs — the side that hooks into the Gate"), so in-process and
//! remote packs share one decision vocabulary and one audit trail.

use crate::interact::{ConsentRequest, InteractionSlot};
use crate::journal::{ActionOutcome, JournalHandle, entry_for};
use crate::observation::ExecError;
use phi_cap::Capability;
use phi_ns::NsError;
use phi_ns::remote::{GateCtx, GateDecision, GateEntry, GateJournal, GatePolicy};
use std::collections::HashMap;
use std::sync::Arc;

/// What policy answers for one side-effecting call. The one decision
/// vocabulary — journal rows, errors, and the remote gate all speak it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    /// Run it.
    Allow,
    /// Refuse; the step halts.
    Deny,
    /// Hold — the engine suspends and waits for a human/upstream decision.
    Ask,
}

impl PolicyDecision {
    /// True when the effect may run.
    pub const fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Journal/observation outcome paired with this decision.
    pub const fn outcome(self) -> ActionOutcome {
        if self.is_allow() {
            ActionOutcome::Dispatched
        } else {
            ActionOutcome::Blocked
        }
    }
}

impl core::fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Ask => "ask",
        })
    }
}

/// What the engine shows policy: who is asking, for what, where, when.
#[derive(Debug, Clone, Copy)]
pub struct CallCtx<'a> {
    /// Injected function name (`"sh.run"`).
    pub fn_name: &'a str,
    /// Stable argument digest (summary, not payload).
    pub args_digest: &'a str,
    /// 0-based cell index within the step.
    pub cell_index: usize,
    /// Step counter (one `execute()` = one step).
    pub step_index: usize,
}

/// Application-side decision maker. Called before every side effect.
pub trait Policy: Send + Sync {
    /// Decide one call.
    fn allow(&self, cap: Capability, ctx: &CallCtx<'_>) -> PolicyDecision;
}

/// One call's facts at the chokepoint — what policy decides on and what the
/// journal row records, bundled so the throat takes one argument per seam.
#[derive(Debug, Clone)]
pub(crate) struct CallFacts<'a> {
    /// Coarse class used as the policy key.
    pub cap: Capability,
    /// Injected function name.
    pub fn_name: &'a str,
    /// Capture role from the declaration (`inventory §3.2`).
    pub capture: phi_ns::CaptureUse,
    /// Stable argument digest (summary, not payload).
    pub args_digest: String,
    /// The argument payload itself — only consulted when policy holds a call
    /// and a human has to see what they are deciding on ([`ConsentRequest`]).
    pub args: Option<&'a serde_json::Value>,
    /// 0-based cell index within the step.
    pub cell_index: usize,
    /// Step counter (one `execute()` = one step).
    pub step_index: usize,
}

// Shared handles delegate, so `with_policy(some_arc)` and
// `with_policy(SomePolicy)` are the same call.
impl Policy for Arc<dyn Policy> {
    fn allow(&self, cap: Capability, ctx: &CallCtx<'_>) -> PolicyDecision {
        (**self).allow(cap, ctx)
    }
}

impl Policy for Box<dyn Policy> {
    fn allow(&self, cap: Capability, ctx: &CallCtx<'_>) -> PolicyDecision {
        (**self).allow(cap, ctx)
    }
}

/// Allow everything — useful for development, never a silent default.
pub struct AllowAll;

impl Policy for AllowAll {
    fn allow(&self, _cap: Capability, _ctx: &CallCtx<'_>) -> PolicyDecision {
        PolicyDecision::Allow
    }
}

/// Deny everything — the fail-closed posture.
pub struct DenyAll;

impl Policy for DenyAll {
    fn allow(&self, _cap: Capability, _ctx: &CallCtx<'_>) -> PolicyDecision {
        PolicyDecision::Deny
    }
}

/// A decision table keyed by coarse class — the mechanism an application
/// composes its own posture from. The engine ships this table **empty of
/// opinions**: whatever the application put in is what applies; unlisted
/// classes fall through to the constructed default.
pub struct ClassPolicy {
    table: HashMap<Capability, PolicyDecision>,
    default: PolicyDecision,
}

impl ClassPolicy {
    /// Start a table with an explicit fall-through decision.
    pub fn new(default: PolicyDecision) -> Self {
        Self {
            table: HashMap::new(),
            default,
        }
    }

    /// Hold/allow one class.
    pub fn with(mut self, cap: Capability, decision: PolicyDecision) -> Self {
        self.table.insert(cap, decision);
        self
    }
}

impl Policy for ClassPolicy {
    fn allow(&self, cap: Capability, _ctx: &CallCtx<'_>) -> PolicyDecision {
        self.table.get(&cap).copied().unwrap_or(self.default)
    }
}

/// A decision table keyed by injected method name, with a fall-through —
/// the second granularity an application composes a posture from.
///
/// Why both: the coarse class is the decision key (O7), but one class can
/// cover faces an application wants to treat differently — `b.click` and
/// `b.screenshot` both resolve to `Device`, and "input asks, capture flows"
/// is a posture only a name-keyed (or hand-written) policy can express.
/// Same contract as [`ClassPolicy`]: shipped **empty of opinions**.
pub struct MethodPolicy {
    table: HashMap<String, PolicyDecision>,
    default: PolicyDecision,
}

impl MethodPolicy {
    /// Start a table with an explicit fall-through decision.
    pub fn new(default: PolicyDecision) -> Self {
        Self {
            table: HashMap::new(),
            default,
        }
    }

    /// Hold/allow one method by its injected name (`"b.click"`).
    pub fn with(mut self, fn_name: &str, decision: PolicyDecision) -> Self {
        self.table.insert(fn_name.to_string(), decision);
        self
    }
}

impl Policy for MethodPolicy {
    fn allow(&self, _cap: Capability, ctx: &CallCtx<'_>) -> PolicyDecision {
        self.table.get(ctx.fn_name).copied().unwrap_or(self.default)
    }
}

/// Decide (with the interaction seam folded in), spend the capture if the
/// method is capture-bound, then journal write-ahead — one choke point shared
/// by the registry (host functions) and the gate (remote packs). Journal
/// failure aborts before the effect (fail-closed), and the order is the audit
/// contract (inventory §3.2/§3.4):
///
/// 1. an `Ask` **suspends before anything is recorded** — the bridge answers
///    with the final decision, so the row below is the one and only row and it
///    carries that verdict (never an intermediate hold);
/// 2. a held call never consumes — nothing was authorized to act;
/// 3. a capture-bound call consumes **before** the row lands, so a refused
///    reuse journals `blocked` and still nothing reaches the wire;
/// 4. the row carries the spent capture id — consumption is recorded at this
///    throat, not in the pack and not on the device.
///
/// The returned reason (when there is one) rides the model-visible hold:
/// "consent refused", or why the interaction itself failed.
pub(crate) async fn decide_and_journal(
    policy: &dyn Policy,
    journal: &JournalHandle,
    ledger: &phi_ns::CaptureLedger,
    interaction: Option<&InteractionSlot>,
    facts: CallFacts<'_>,
) -> Result<(PolicyDecision, Option<String>), NsError> {
    let CallFacts {
        cap,
        fn_name,
        capture,
        args_digest,
        args,
        cell_index,
        step_index,
    } = facts;
    let mut decision = policy.allow(
        cap,
        &CallCtx {
            fn_name,
            args_digest: &args_digest,
            cell_index,
            step_index,
        },
    );
    let mut reason: Option<String> = None;
    if decision == PolicyDecision::Ask
        && let Some(slot) = interaction
    {
        // Ask is a suspension, not a verdict (PolicyDecision::Ask docs).
        let request = ConsentRequest {
            cap,
            fn_name,
            args,
            args_digest: &args_digest,
            cell_index,
            step_index,
        };
        decision = match slot.consent(&request).await {
            Ok(PolicyDecision::Allow) => PolicyDecision::Allow,
            Ok(_) => {
                reason = Some("consent refused".into());
                PolicyDecision::Deny
            }
            Err(why) => {
                reason = Some(why);
                // Fail-closed: an unanswered interaction is a refusal.
                PolicyDecision::Deny
            }
        };
    }
    // No bridge configured: `Ask` stays a hold (the refuse path journals
    // it) — engines without a human keep today's behavior.
    if !decision.is_allow() {
        // A hold journals its own row and leaves the capture untouched.
        let entry = entry_for(
            cap,
            fn_name,
            args_digest,
            decision,
            decision.outcome(),
            cell_index,
            step_index,
        );
        journal
            .record(entry)
            .map_err(|e| NsError::Journal(e.to_string()))?;
        return Ok((decision, reason));
    }

    let mut entry = entry_for(
        cap,
        fn_name,
        args_digest,
        PolicyDecision::Allow,
        ActionOutcome::Dispatched,
        cell_index,
        step_index,
    );
    if capture == phi_ns::CaptureUse::Consume {
        match ledger.consume(phi_ns::face_of(fn_name), fn_name) {
            Ok(spent) => {
                entry.set_call_outcome(ActionOutcome::Dispatched, Some(spent.id.to_string()))
            }
            Err(refusal) => {
                entry.set_call_outcome(
                    ActionOutcome::Blocked,
                    refusal.id().map(|id| id.to_string()),
                );
                journal
                    .record(entry)
                    .map_err(|e| NsError::Journal(e.to_string()))?;
                return Err(NsError::Capture {
                    method: fn_name.to_string(),
                    reason: refusal.reason(),
                });
            }
        }
    }
    journal
        .record(entry)
        .map_err(|e| NsError::Journal(e.to_string()))?;
    Ok((decision, reason))
}

/// Map a held decision onto the observation error the next model turn sees.
pub(crate) fn hold_error(
    decision: PolicyDecision,
    method: &str,
    cap: Capability,
    cell_index: usize,
    reason: Option<String>,
) -> ExecError {
    match decision {
        PolicyDecision::Deny => ExecError::PolicyHold {
            method: method.to_string(),
            cap: cap.to_string(),
            decision: PolicyDecision::Deny,
            cell_index,
            reason,
        },
        PolicyDecision::Ask => ExecError::PolicyHold {
            method: method.to_string(),
            cap: cap.to_string(),
            decision: PolicyDecision::Ask,
            cell_index,
            reason,
        },
        PolicyDecision::Allow => ExecError::Worker("unreachable: allow is not a hold".into()),
    }
}

// ---- Gate adapters (the remote chokepoint shares policy + journal) ----

/// Adapts the engine's [`Policy`] onto `phi-ns`'s gate seam.
pub struct GatePolicyAdapter {
    /// The application policy being adapted.
    pub policy: Arc<dyn Policy>,
}

impl GatePolicy for GatePolicyAdapter {
    fn decide(&self, ctx: &GateCtx<'_>) -> GateDecision {
        // Remote calls carry no cell/step index yet (P3 wires the real ones);
        // the decision vocabulary is the same.
        match self.policy.allow(
            ctx.cap,
            &CallCtx {
                fn_name: ctx.method,
                args_digest: ctx.args_digest,
                cell_index: 0,
                step_index: 0,
            },
        ) {
            PolicyDecision::Allow => GateDecision::Allow,
            PolicyDecision::Deny => GateDecision::Deny,
            PolicyDecision::Ask => GateDecision::Ask,
        }
    }
}

/// Adapts the engine's journal onto `phi-ns`'s gate seam — one audit trail
/// for in-process and remote packs.
pub struct GateJournalAdapter {
    /// The engine journal being adapted.
    pub journal: JournalHandle,
}

impl GateJournal for GateJournalAdapter {
    fn record(&self, entry: GateEntry) -> Result<(), NsError> {
        let decision = match entry.decision {
            GateDecision::Allow => PolicyDecision::Allow,
            GateDecision::Deny => PolicyDecision::Deny,
            GateDecision::Ask => PolicyDecision::Ask,
        };
        let result = match entry.outcome {
            phi_ns::remote::GateOutcome::Dispatched => ActionOutcome::Dispatched,
            phi_ns::remote::GateOutcome::Blocked => ActionOutcome::Blocked,
        };
        // The gate already stamped time/digest; rebuild the engine row so the
        // journal stays one format regardless of which chokepoint wrote it.
        let mut row = entry_for(
            entry.cap,
            &entry.method,
            entry.args_digest.clone(),
            decision,
            result,
            0,
            0,
        );
        row.time_ms = entry.time_ms;
        row.time = crate::journal::utc_text(entry.time_ms);
        self.journal
            .record(row)
            .map_err(|e| NsError::Journal(e.to_string()))
    }
}
