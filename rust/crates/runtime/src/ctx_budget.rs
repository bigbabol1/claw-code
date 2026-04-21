//! CtxBudget — per-turn context-window accountant.
//!
//! The local-LLM backend (Ollama/Qwen3.5 @ num_ctx=32768) silently drops to
//! finish_reason=length once the KV cache saturates. Wave 1 recovers post-facto
//! via forced compaction; this module prevents the saturation in the first
//! place by (a) triggering pre-send compaction at a soft ratio and (b)
//! truncating oversized tool outputs before they enter the session history.
//!
//! The budget is deliberately conservative — a false-positive compaction costs
//! a summary round-trip, a false-negative costs a full turn crash.
use std::borrow::Cow;

/// Default context window for claw-code:latest on RTX 3090 (see Modelfile).
pub const DEFAULT_MODEL_CTX: usize = 32_768;

/// Tokens reserved for the assistant's reply. Qwen3.5 tool-heavy turns usually
/// emit < 1k, but reasoning blocks can balloon — 2k leaves headroom without
/// significantly shrinking the usable input budget.
pub const DEFAULT_RESERVE_OUTPUT: usize = 2_048;

/// Trigger pre-send compaction once estimated prompt tokens exceed this
/// fraction of the available-for-messages window.
pub const DEFAULT_SOFT_RATIO: f32 = 0.85;

/// Refuse to append a tool output that would push total estimated tokens above
/// this fraction; truncate instead.
pub const DEFAULT_HARD_RATIO: f32 = 0.95;

/// Verdict returned by [`CtxBudget::check`] describing the relation between
/// current estimated prompt tokens and the configured thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetVerdict {
    /// Comfortably below the soft threshold — proceed.
    Ok,
    /// Past the soft threshold — pre-send compaction is recommended.
    Soft,
    /// Past the hard threshold — must shed load before sending.
    Hard,
}

#[derive(Debug, Clone, Copy)]
pub struct CtxBudget {
    model_ctx: usize,
    reserve_output: usize,
    reserve_system: usize,
    soft_ratio: f32,
    hard_ratio: f32,
}

impl CtxBudget {
    #[must_use]
    pub fn new(model_ctx: usize) -> Self {
        Self {
            model_ctx,
            reserve_output: DEFAULT_RESERVE_OUTPUT,
            reserve_system: 0,
            soft_ratio: DEFAULT_SOFT_RATIO,
            hard_ratio: DEFAULT_HARD_RATIO,
        }
    }

    #[must_use]
    pub fn with_system_reserve(mut self, tokens: usize) -> Self {
        self.reserve_system = tokens;
        self
    }

    /// Tokens usable for conversation messages, after subtracting reservations.
    /// Returns 0 if the reservations already exceed the context window (a
    /// misconfiguration, but we clamp instead of panicking).
    #[must_use]
    pub fn available_for_messages(&self) -> usize {
        self.model_ctx
            .saturating_sub(self.reserve_output)
            .saturating_sub(self.reserve_system)
    }

    #[must_use]
    pub fn check(&self, current_tokens: usize) -> BudgetVerdict {
        let avail = self.available_for_messages();
        if avail == 0 {
            return BudgetVerdict::Hard;
        }
        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
        let soft = (avail as f32 * self.soft_ratio) as usize;
        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
        let hard = (avail as f32 * self.hard_ratio) as usize;
        if current_tokens >= hard {
            BudgetVerdict::Hard
        } else if current_tokens >= soft {
            BudgetVerdict::Soft
        } else {
            BudgetVerdict::Ok
        }
    }

    /// Fit a tool output into the remaining budget. If the output would push
    /// total tokens past the hard ratio, truncate the middle and insert an
    /// explicit English marker so the model can reason about the elision.
    ///
    /// The rough-token estimator used across the runtime treats ~4 chars per
    /// token, so we work in characters here to stay consistent with
    /// `estimate_session_tokens`.
    pub fn fit_tool_output<'a>(&self, output: &'a str, current_tokens: usize) -> Cow<'a, str> {
        let avail = self.available_for_messages();
        if avail == 0 {
            return Cow::Borrowed(output);
        }
        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
        let hard_tokens = (avail as f32 * self.hard_ratio) as usize;
        let remaining_tokens = hard_tokens.saturating_sub(current_tokens);
        // 4 chars/token heuristic (matches estimator). Leave a small margin for
        // the marker itself.
        let remaining_chars = remaining_tokens.saturating_mul(4);
        if output.len() <= remaining_chars {
            return Cow::Borrowed(output);
        }
        // Very tight budget — just return a truncation notice instead of
        // producing garbage.
        if remaining_chars < 256 {
            return Cow::Owned(format!(
                "[tool output suppressed: ctx budget exhausted ({} bytes; \
                 compact session and retry)]",
                output.len()
            ));
        }
        // Preserve head and tail around a middle elision. Heads carry tool
        // schema/header info, tails carry the most recent state — both
        // usually matter more than the middle.
        let keep = remaining_chars.saturating_sub(128);
        let head_chars = keep / 2;
        let tail_chars = keep - head_chars;
        let head = safe_char_prefix(output, head_chars);
        let tail = safe_char_suffix(output, tail_chars);
        let elided = output.len().saturating_sub(head.len()).saturating_sub(tail.len());
        Cow::Owned(format!(
            "{head}\n\n[…truncated {elided} bytes by ctx budget; showing head + tail…]\n\n{tail}"
        ))
    }
}

impl Default for CtxBudget {
    fn default() -> Self {
        Self::new(DEFAULT_MODEL_CTX)
    }
}

fn safe_char_prefix(s: &str, max_chars: usize) -> &str {
    let end = s
        .char_indices()
        .nth(max_chars)
        .map_or(s.len(), |(idx, _)| idx);
    &s[..end]
}

fn safe_char_suffix(s: &str, max_chars: usize) -> &str {
    let total = s.chars().count();
    if max_chars >= total {
        return s;
    }
    let skip = total - max_chars;
    let start = s
        .char_indices()
        .nth(skip)
        .map(|(idx, _)| idx)
        .unwrap_or(s.len());
    &s[start..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_subtracts_reservations() {
        let budget = CtxBudget::new(32_768).with_system_reserve(1_000);
        assert_eq!(
            budget.available_for_messages(),
            32_768 - DEFAULT_RESERVE_OUTPUT - 1_000
        );
    }

    #[test]
    fn available_clamps_to_zero_on_over_reservation() {
        let budget = CtxBudget::new(1_000).with_system_reserve(10_000);
        assert_eq!(budget.available_for_messages(), 0);
    }

    #[test]
    fn verdict_progression() {
        let budget = CtxBudget::new(10_000);
        let avail = budget.available_for_messages();
        assert_eq!(budget.check(0), BudgetVerdict::Ok);
        assert_eq!(
            budget.check((avail as f32 * 0.5) as usize),
            BudgetVerdict::Ok
        );
        assert_eq!(
            budget.check((avail as f32 * 0.90) as usize),
            BudgetVerdict::Soft
        );
        assert_eq!(
            budget.check((avail as f32 * 0.99) as usize),
            BudgetVerdict::Hard
        );
    }

    #[test]
    fn fit_tool_output_passes_small_payload_unchanged() {
        let budget = CtxBudget::new(32_768);
        let out = "small output";
        let fitted = budget.fit_tool_output(out, 100);
        assert!(matches!(fitted, Cow::Borrowed(_)));
        assert_eq!(fitted, out);
    }

    #[test]
    fn fit_tool_output_preserves_head_and_tail() {
        let budget = CtxBudget::new(32_768);
        let huge = format!(
            "HEADER_MARKER_{}\n{}\nTAIL_MARKER_{}",
            "A".repeat(10),
            "x".repeat(200_000),
            "Z".repeat(10)
        );
        // Simulate near-saturated current state so truncation kicks in.
        let current = budget.available_for_messages().saturating_sub(2_000);
        let fitted = budget.fit_tool_output(&huge, current);
        let text = fitted.as_ref();
        assert!(text.contains("HEADER_MARKER_"), "head preserved");
        assert!(text.contains("TAIL_MARKER_"), "tail preserved");
        assert!(
            text.contains("truncated") && text.contains("ctx budget"),
            "marker present: {text:?}"
        );
        assert!(text.len() < huge.len(), "actually shortened");
    }

    #[test]
    fn fit_tool_output_emits_suppression_notice_when_budget_is_starved() {
        let budget = CtxBudget::new(32_768);
        let huge = "x".repeat(50_000);
        // Push current past the hard ratio.
        let current = budget.available_for_messages() + 1_000;
        let fitted = budget.fit_tool_output(&huge, current);
        assert!(fitted.contains("ctx budget exhausted"));
    }
}
