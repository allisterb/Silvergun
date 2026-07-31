---
name: measure-before-designing
description: In this codebase, architect assumptions about ext/analysis-net and BCL/compiler behaviour have been falsified by measurement repeatedly — spike first, and have subagents report numbers
metadata:
  type: project
---

**Send a measurement spike before designing on top of any claim about `ext/analysis-net`,
CCI, or compiler/BCL behaviour — including claims I made confidently in an earlier
session.** Ask subagents to *measure and report numbers*, not to implement against an
assumption.

**Why:** on 2026-07-24/25 this pattern caught seven wrong assumptions, several of them
mine, each of which would have been expensive mid-implementation:
- The TAC-lifter root cause was recorded as an EH stack-model bug; measurement showed it
  is `PlatformTypes.Void` pinned to `mscorlib` (60–97% of failures). See
  [[analysisnet-disassembler-gaps]].
- A cited failure figure ("49 of 49 methods skipped") did not reproduce (51/161).
- `ClassHierarchyAnalysis` fails *silently* (empty graph), not just loudly.
- `IBasicType.GetFullName()` reverses nested-type chains at depth ≥ 3.
- `[LibraryImport]` was already detected — the planned work was unnecessary.
- A specced test baseline (net472 `1/1/0`) was wrong (`3/3/0`) because Roslyn embeds
  attribute types when the target BCL lacks them.
- CAS demands in the reference source were far denser than I claimed.

**It happened again on 2026-07-26 (8th instance), so treat this as the norm, not a
one-off session:** the `capability-shapes-across-tfms` spec asserted three APIs would be
*detected*; they are not, because `CapabilityAnalysis` reads the legacy in-code `Catalog`
and those entries live only in the (still-inert) `capabilities.cm`. **The specific trap
to generalize: a spec that names concrete APIs must state which detection seam is
expected to fire, and that seam must be verified live — "it is in the map file" does not
mean "it is detected."** The subagent handled it correctly by pinning the true negatives
in a canary test that is *designed to fail* when the gap closes; prefer that over
asserting the desired-but-false behaviour or dropping the case.

**⚠️ NEW AND IMPORTANT (2026-07-28): measuring is not enough — VERIFY THE REPORT AGAINST THE
RAW OUTPUT.** Three times in one session a subagent's headline contradicted its own data files:

- "Non-termination 21 → 0" — the raw results showed **21 → 3 still timing out, plus 14
  terminating without converging**. The agent had conflated "no longer infinite" with "no
  longer times out".
- Quoted absolutes (65,010 → 65,014) came from a different phase with a different denominator
  than the run being reported.
- A cost measurement claimed "statistically indistinguishable" — true for benign input,
  meaningless for the adversarial case that actually mattered (it later measured 50× worse).

Each was caught in minutes by aggregating the raw per-assembly result files myself
(`grep -h "^METRIC " results/*/*.txt | awk '{s+=$2} END {print s}'`). **Budget for this: when a
report gives gate numbers, re-aggregate them from the raw files before relaying them.** Ask
subagents for "numbers, not adjectives", and tell them explicitly to flag anything that missed
target rather than rounding it to success — that framing visibly improved later reports.

**Corollary:** a cost/perf measurement over *benign* input says nothing about the hostile case.
On any hostile-input path, require the worst case to be measured explicitly and separately.

**Delegation corollary learned the same day:** when a spec adds members to a fixture
assembly whose tests pin *assembly-wide* counts, a "phase 1: shapes only, don't touch
existing tests" split **cannot** leave the suite green — the baselines break by
construction. Either let phase 1 own the baseline update, or tell it the red tests are
expected. Do not ask a subagent for both.

**⚠️ 2026-07-30/31 — A SECOND, DISTINCT FAILURE SHAPE: asserting ENVIRONMENTAL facts in dispatch
prompts.** The entries above are wrong claims about *behaviour*. Five more this session were wrong
claims about *what exists*, each stated confidently in a task prompt and each caught by the subagent:

- *"`InternalsVisibleTo` is already on the assembly"* — **it was not.** Had the agent not checked,
  `internal` would have been a no-op and a security fix would have shipped unfalsifiable by its suite.
- *"ILSpy raises a typed `EnumUnderlyingTypeResolveException` on cyclic enums"* — it raises nothing;
  it degrades silently. (The *structural* half of the claim was right, the signal half wrong.)
- *"CCI's `GetFullName` defects are what `CciNames` must avoid reproducing"* — those defects live in
  analysis-net's `Model/Extensions.cs`, which `CciNames.Walk` never calls. Wrong layer.
- *"Cecil's `DefaultAssemblyResolver` throws on missing dependencies"* — on the read path it never
  throws; it **over-reaches**, binding refs to files in the analyzer's own output directory.
- *"Reader-resolution asymmetry is likely the largest source of naming divergence"* — measured **0**.

**The shape: I pattern-match from neighbouring code and state the result as fact.** Four of the five
would have caused real damage if believed. **How to apply: an environmental claim in a dispatch
prompt — does this file/attribute/API exist, is this configured — costs one `grep` to verify and I
should verify it, OR mark it explicitly as unverified so the agent checks.** The line
*"if the code contradicts this prompt, the code wins — say so plainly"* is what surfaced all five;
keep it in every dispatch.

**How to apply:** for anything touching `ext/`, metadata reading, or compiler-generated
shapes, write a spike spec whose deliverable is *a table of measured numbers plus a
verdict*, and say explicitly that **a negative result is a successful spike**. Prefer
"verify before implementing" phases in task specs. When a subagent's measurement
contradicts my spec, the measurement wins — correct the doc, and say so plainly rather
than quietly adjusting. Two concrete techniques that worked: a throwaway harness in a
scratchpad *outside* the repo, and a deliberately **hostile** probe assembly (it found a
`CalledApi` contract violable from plain C#, and an attribute-ordering evasion).
