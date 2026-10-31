//! Escape hatches (codexec-design §13.5): `execute_command` **downgraded**.
//!
//! In a tool-menu world `execute_command` was a first-class tool; in a
//! CodeAct world it is a last resort — only surfaced when the worker session
//! is dead and code cannot run at all. It is not on the menu otherwise, and
//! it still goes through policy + journal (audit cannot be closed).

use crate::observation::ExecError;
use crate::registry::NamespaceRegistry;
use phi_cap::Capability;

/// A last-resort capability shown to the model only in broken states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscapeHatch {
    /// Tool name as the model sees it.
    pub name: &'static str,
    /// When/why it exists.
    pub doc: &'static str,
}

/// The raw command hatch.
pub const EXECUTE_COMMAND: EscapeHatch = EscapeHatch {
    name: "execute_command",
    doc: "run one raw shell command; only exposed when the code session is dead",
};

/// Which hatches are visible for a given session state.
///
/// `is_session_alive() == true` → nothing; the model writes code instead.
pub fn escape_hatches(is_session_alive: bool) -> Vec<&'static EscapeHatch> {
    if is_session_alive {
        Vec::new()
    } else {
        vec![&EXECUTE_COMMAND]
    }
}

/// The hatch itself: one raw command, outside the worker, policy-gated and
/// journaled like any other side effect.
pub async fn execute_command(
    registry: &NamespaceRegistry,
    cmd: &str,
) -> Result<CommandOutput, ExecError> {
    let digest = phi_ns::remote::args_digest(&serde_json::json!([cmd]));
    let (decision, reason) = registry
        .journal_escape(Capability::Process, EXECUTE_COMMAND.name, digest, 0)
        .await
        .map_err(|e| ExecError::Journal(e.to_string()))?;
    if !decision.is_allow() {
        return Err(ExecError::PolicyHold {
            method: EXECUTE_COMMAND.name.to_string(),
            cap: Capability::Process.to_string(),
            decision,
            cell_index: 0,
            reason,
        });
    }
    let out = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .await
        .map_err(|e| ExecError::Worker(format!("escape hatch could not spawn: {e}")))?;
    Ok(CommandOutput {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    })
}

/// What the hatch returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Captured stdout.
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
    /// Exit code.
    pub code: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hatch_hidden_while_the_session_lives() {
        assert!(escape_hatches(true).is_empty());
        let hatches = escape_hatches(false);
        assert_eq!(hatches.len(), 1);
        assert_eq!(hatches[0].name, "execute_command");
    }
}
