---
name: ext-comment-proportionality
description: How to weigh a long explanatory comment added to an upstream ext/ file against the "every touched line is a future merge conflict" rule.
metadata:
  type: feedback
---

CLAUDE.md's `ext/` guidance says keep diffs minimal and surgical because every touched line is a
future upstream-merge conflict. That doesn't mean *zero* comments — it means weigh the conflict cost
against what's lost if the reasoning isn't recorded in the file itself.

**Why:** reviewed a 1-line fix to `ext/analysis-net/Model/ThreeAddressCode/Operands.cs`
(`Dereference.Type`, 2026-07-27) that shipped with a 15-line comment explaining a genuinely
non-obvious design call — returning `null` instead of the task's suggested `PlatformTypes.Unknown`,
because `Unknown` would permanently pin a result the fixed-point pass could otherwise self-heal. That
rationale is *not* derivable by reading the surrounding code alone (you have to know the fixed point's
retry semantics and that `Unknown` is a distinct non-null sentinel nothing overwrites). Judged the
comment proportionate: it sits entirely inside the one changed getter (doesn't touch any other line
that would exist in an upstream diff), and the alternative — leaving the reasoning only in
`docs/agent/measurements/*.md` — means a future upstream merge conflict on this exact line would have
to be resolved by someone who can't see *why* the guard exists, risking a well-intentioned "helpful"
merge that reintroduces the unguarded cast or swaps in `Unknown`.

**How to apply:** don't flag a comment merely for being long in `ext/`. Check instead: (1) does it
sit only on lines that are *already* part of the diff (not spreading onto untouched lines), and (2)
does it carry information a future reader/merger genuinely needs and can't get from the linked
measurement doc alone (e.g. because the doc might not survive, or because the comment is exactly what
stops a merge from silently reverting the fix). If both hold, the comment earns its keep. If the
doc's existence alone would suffice (e.g. a comment that just restates the diff), trim it and point to
the doc instead.

**Extended to five sibling guards in one file (2026-07-27, `typeinference-nullguard-fixes.md`,
`TypeHelper.cs`'s `BinaryLogicalOperationType`/`UnsignedEquivalent`/`BinarySignedNumericOperationType`
plus `Operands.cs`'s `ArrayElementAccess.Type`, alongside the already-reviewed `Dereference.Type`).**
The proportionality test above still held at all five — none of it spread onto untouched lines, and
each genuinely explains the non-obvious "why null not `Unknown`" call. But two of the five
(`BinaryLogicalOperationType` and `BinarySignedNumericOperationType`) restate that same rationale
almost verbatim in ~8-10 lines each, rather than following the pattern the *other* three sites used
(`ArrayElementAccess.Type` says "same shape as `Dereference.Type`, see that comment" in one line;
`UnsignedEquivalent`'s comment is 4 lines because it only states a fact about its own caller). Flagged
this as a Warning, not Critical: recommend collapsing the near-duplicate to one canonical explanation
with a cross-reference, the same "explain once, point to it elsewhere" pattern the author already used
successfully for 3 of the 5 sites. Each duplicated line is still a future merge-conflict line per
CLAUDE.md's own `ext/` rule, so redundant restatement is a real (if minor) cost even when every
individual comment is independently justified.
