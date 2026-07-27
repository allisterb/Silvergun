---
name: project-analysisnet-workflow
description: How ext/analysis-net fixes get proposed, measured, and reviewed in this repo — spike docs, isolation constraints, review technique
metadata:
  type: project
---

`ext/analysis-net` bug fixes in this repo follow a spike-first workflow: a measurement doc lands in
`docs/agent/measurements/` (e.g. `tac-platformtypes-spike.md`) with reproduction data, root cause,
options considered/rejected, before/after corpus numbers, and correctness spot-checks of real lifted
TAC — before the actual `ext/` diff is left uncommitted for review. Treat these docs as claims to
re-verify, not trust: grep independently for "did you get all the affected call sites" claims, and
where a doc claims "N of M tests go red on revert," actually revert-rebuild-test-restore to check the
exact split, since that's cheap and catches both undercounting and a wrong root-cause story.

**ADR-0021 constraint**: CCI (`ext/analysis-net/cci`) can `Environment.FailFast` uncatchably via
`Debug.Assert`/`Debug.Fail`. Spikes and any reviewer verification that drives analysis over multiple
assemblies must isolate one assembly per child process and check exit codes — a single bad input can
otherwise kill the whole batch with no managed exception to catch.

Cross-reference: [[project-platformtypes-void-fix]] for the specific fix this pattern was observed on.
