//! Actions: `<intent><code>` blocks (codexec-design §4.4).
//!
//! The model does not emit tool calls; it emits fenced intent/code blocks in
//! text. One *step* may carry several blocks; the whole step is validated
//! before anything runs (D2).

use thiserror::Error;

/// One unit of work for the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// A code cell: what it is for, and the code itself.
    CodeCell {
        /// The model's intent note — for the journal and the transcript.
        intent: String,
        /// Source in the current worker's language (D5: no per-cell mixing).
        code: String,
    },
}

impl Action {
    /// The code of this action.
    pub fn code(&self) -> &str {
        match self {
            Self::CodeCell { code, .. } => code,
        }
    }

    /// The intent note of this action.
    pub fn intent(&self) -> &str {
        match self {
            Self::CodeCell { intent, .. } => intent,
        }
    }
}

/// Why a model response could not become actions.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    /// No `<intent><code>` pair found at all.
    #[error("no <intent><code> block found in the response")]
    NoBlocks,
    /// A block is malformed (unclosed tag, empty code, nesting).
    #[error("malformed block #{index}: {detail}")]
    Malformed {
        /// 1-based block position in the text.
        index: usize,
        /// What exactly is wrong.
        detail: String,
    },
}

/// Extract every `<intent>…</intent><code>…</code>` pair from `text`, in
/// order. Strict: an unclosed tag or empty code fails the whole parse — the
/// engine never executes a partially understood step.
pub fn parse_actions(text: &str) -> Result<Vec<Action>, ParseError> {
    let mut actions = Vec::new();
    let mut rest = text;
    let mut index = 0usize;

    while let Some(pos) = rest.find("<intent>") {
        rest = &rest[pos + "<intent>".len()..];
        index += 1;

        let Some(intent_end) = rest.find("</intent>") else {
            return Err(ParseError::Malformed {
                index,
                detail: "unclosed <intent> tag".into(),
            });
        };
        let intent = rest[..intent_end].trim().to_string();
        rest = &rest[intent_end + "</intent>".len()..];

        let Some(code_start) = rest.find("<code>") else {
            return Err(ParseError::Malformed {
                index,
                detail: "<intent> without a following <code> block".into(),
            });
        };
        rest = &rest[code_start + "<code>".len()..];

        let Some(code_end) = rest.find("</code>") else {
            return Err(ParseError::Malformed {
                index,
                detail: "unclosed <code> tag".into(),
            });
        };
        let code = rest[..code_end].to_string();
        rest = &rest[code_end + "</code>".len()..];

        if code.trim().is_empty() {
            return Err(ParseError::Malformed {
                index,
                detail: "empty <code> block".into(),
            });
        }
        actions.push(Action::CodeCell { intent, code });
    }

    if actions.is_empty() {
        return Err(ParseError::NoBlocks);
    }
    Ok(actions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiple_blocks_in_order() {
        let text = "intro\n<intent>a</intent>\n<code>\nx = 1\n</code>\n\n<intent>b</intent>\n<code>print(x)</code>";
        let actions = parse_actions(text).unwrap();
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].intent(), "a");
        assert_eq!(actions[0].code(), "\nx = 1\n");
        assert_eq!(actions[1].code(), "print(x)");
    }

    #[test]
    fn rejects_unclosed_tags_and_empty_code() {
        assert!(matches!(
            parse_actions("<intent>a</intent><code>x=1"),
            Err(ParseError::Malformed { .. })
        ));
        assert!(matches!(
            parse_actions("<intent>a</intent><code>   </code>"),
            Err(ParseError::Malformed { .. })
        ));
        assert_eq!(parse_actions("plain prose"), Err(ParseError::NoBlocks));
    }
}
