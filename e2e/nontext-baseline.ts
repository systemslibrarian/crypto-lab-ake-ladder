/**
 * Non-text contrast ratchet. New or worsening findings fail; stale entries
 * must be removed. An empty baseline exempts no known findings.
 * NT_BASELINE_CAPTURE=1 prints findings for inspection without asserting them.
 * Absolutely positioned pseudo-elements are marked unverified because their
 * host backdrop may differ from the backdrop beneath their painted pixels.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {};
