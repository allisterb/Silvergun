---
name: empty-is-not-clean
description: Five defects in this codebase have had one shape — an empty result set from a scan that never really ran, reported as clean. ADR-0030 is the consolidated invariant; ask the "name every way this returns empty" question of any new analysis source.
metadata:
  type: project
---

**The recurring defect in Silvergun is not bad detection logic — it is `empty` being used to mean
"clean" when it means "we don't know".** Five separate incidents, same shape (ADR-0030 consolidates
them): OSV chunk failure; the YARA backend failing to load; YARA rules built from a poisoned compiler;
a YARA hit dropped because a filename could not round-trip through the output format; and `yara -r`
failing to start / exiting non-zero / **timing out**. Three were attacker-reachable, and the last was
*cheaper to trigger* than the elaborate attack the previous ADR had just closed.

**Why it keeps happening:** the buggy code looks defensive. `catch { return Array.Empty<T>(); }`
satisfies a "never throws" contract, reads as hostile-input hardening, and produces a green scan.
Our own guard helpers and never-throws contracts actively encourage it.

**How to apply:**
- On any new or changed analysis source, ask — of the implementer and of myself — **"name every way
  this can return empty, and say which of them mean clean."** Mixed together ⇒ defect.
- Three outcomes, never two: `NotChecked` / `Completed` / `Unavailable`. Empty is only meaningful
  under `Completed`.
- **Timeouts are the most-missed case**, because a timeout arrives on the *success* path of a
  `Wait`/`Join` and looks like a normal return.
- Status must come from what happened, not from the absence of an exception — a backend that swallows
  its own errors makes "it didn't throw" carry zero information.
- **A test asserting "returns empty when X fails" is probably pinning this bug.** One was found doing
  exactly that, defended by a comment that was factually wrong
  ([[suppressed-diagnostic-is-a-defect-signal]]).

**Two-sided (added 2026-08-22):** `Unavailable` must mean "we could not tell", never "we could tell
and threw it away". An over-firing fail-closed guard turned a definite malware detection into an
incompleteness — and under `--strict --allow-incomplete` that is **exit 2 → exit 0**. Ask both
questions of every guard: can it report clean when it shouldn't, *and* can it report unknown when it
already knows?

**Review heuristic that would have caught three of these:** when a fix excludes/filters on a *derived*
key, check that **both sides of the comparison are produced by the same function**. Three consecutive
Criticals in the YARA CLI backend were all this shape — `Ordinal` grouping vs `OrdinalIgnoreCase`
lookup, then a whole-normalised-target compared against a set of truncated echo keys. The design was
right every time; the equality relation was not.

Related: [[hostile-input-threat-model]], [[inert-guard-defect-class]], [[detection-calibration]]
