//! Round limits (codexec-design §4.4 D4 / §8.1).
//!
//! Quotas and the hard timeout are counted **per round (step)**, never per
//! block — otherwise a model could dodge the quota by splitting work across
//! blocks. Over-quota output is truncated and marked, never silently dropped.

/// Per-round budgets. Defaults match the protocol draft (codexec-design §9.1).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// stdout quota per round, bytes.
    pub stdout_max: usize,
    /// stderr quota per round, bytes.
    pub stderr_max: usize,
    /// Event-count quota per round.
    pub events_max: usize,
    /// Single RPC payload ceiling, bytes.
    pub rpc_max: usize,
    /// Hard round timeout; on expiry the worker is recycled.
    pub timeout_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            stdout_max: 262_144,
            stderr_max: 65_536,
            events_max: 256,
            rpc_max: 67_108_864,
            timeout_ms: 120_000,
        }
    }
}

/// Running usage for one round.
#[derive(Debug, Default)]
pub struct RoundBudget {
    stdout_used: usize,
    stderr_used: usize,
    events_used: usize,
}

impl RoundBudget {
    /// Start a fresh budget for a new round.
    pub fn new() -> Self {
        Self::default()
    }

    /// Charge stdout; returns the (possibly truncated) chunk to keep, plus
    /// whether it was cut.
    pub fn charge_stdout(&mut self, chunk: &str, limits: &Limits) -> (String, bool) {
        let (text, cut) = take_quota(chunk, limits.stdout_max.saturating_sub(self.stdout_used));
        self.stdout_used += text.len();
        (text, cut)
    }

    /// Charge stderr; same contract as [`RoundBudget::charge_stdout`].
    pub fn charge_stderr(&mut self, chunk: &str, limits: &Limits) -> (String, bool) {
        let (text, cut) = take_quota(chunk, limits.stderr_max.saturating_sub(self.stderr_used));
        self.stderr_used += text.len();
        (text, cut)
    }

    /// Charge one event slot. False when the event budget is exhausted.
    pub fn charge_event(&mut self, limits: &Limits) -> bool {
        if self.events_used >= limits.events_max {
            return false;
        }
        self.events_used += 1;
        true
    }
}

/// Cut `chunk` to `budget` bytes at a UTF-8 boundary; the tail is dropped.
pub fn take_quota(chunk: &str, budget: usize) -> (String, bool) {
    if chunk.len() <= budget {
        return (chunk.to_string(), false);
    }
    let mut end = budget;
    while end > 0 && !chunk.is_char_boundary(end) {
        end -= 1;
    }
    (chunk[..end].to_string(), true)
}

/// Truncation marker appended when a quota bites (never silent).
pub const TRUNCATED: &str = "\n…[truncated]";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotas_accumulate_across_blocks() {
        let limits = Limits::default();
        let mut budget = RoundBudget::new();
        let big = "x".repeat(limits.stdout_max);
        let (first, cut1) = budget.charge_stdout(&big, &limits);
        let (second, cut2) = budget.charge_stdout("more", &limits);
        assert!(!cut1);
        assert_eq!(first.len(), limits.stdout_max);
        assert!(cut2);
        assert!(second.is_empty());
    }

    #[test]
    fn truncation_is_marked_not_silent() {
        let (text, cut) = take_quota("hello world", 5);
        assert_eq!(text, "hello");
        assert!(cut);
    }
}
