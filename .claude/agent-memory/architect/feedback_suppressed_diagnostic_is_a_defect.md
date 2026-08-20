---
name: suppressed-diagnostic-is-a-defect-signal
description: When a subagent suppresses a compiler diagnostic and explains why it is safe, treat the explanation as a defect signal — the compiler is usually right; verify the claim by executing it
metadata:
  type: feedback
---

**A subagent reporting "I suppressed warning X and here is why it is safe" is a defect signal, not a
resolution.** Verify the claim by running it before accepting the change.

**Why:** observed 2026-08-20. A `dotnet-implementer` suppressed `CS8714`/`CS8621` in
`CapabilityDiffReport.ByAssemblyNameAndFramework` with a comment asserting that
`Dictionary<TKey,TValue>` "accepts a null key at runtime for a reference-type TKey". **That is false**
— `Dictionary.Add` throws `ArgumentNullException` on a null key unconditionally, whatever the
nullable-reference annotation says. `CS8714` exists to warn about exactly that.

I read the justification, found it plausible, and approved it. The result: the most ordinary use of
the new `capability-diff` verb (comparing two `analyze --snapshot` files, which always carry a null
target framework) crashed with an unhandled exception. A `test-engineer` found it, refused to weaken
the tests, and reported it.

**Compounding failure worth remembering separately:** I had *also* written the same false claim into
the task spec — "null is just another framework value" — as prose, with no executable check. So the
subagent's wrong justification and my wrong spec agreed with each other, and agreement between two
unexecuted assertions reads exactly like verification.

**How to apply:**
- Treat any nullable-analysis suppression (`CS8714`, `CS8600`, `CS8618`, `!` null-forgiving) as
  requiring a demonstrated runtime check, not an argument.
- When a subagent's report contains a confident factual claim about BCL behaviour, ask for the
  executed evidence, or spot-check it yourself. Plausibility is not verification.
- Never let a *design* claim about runtime behaviour live only in a spec. If the spec says "X handles
  Y correctly", that sentence needs a test, or it is a hypothesis wearing a decision's clothes.
- A wrong explanatory comment is worse than none — it persuades the next reader. Delete it, do not
  soften it.

Related: [[inert-guard-defect-class]], [[record-decisions-at-dispatch-time]], [[measure-before-designing]]
