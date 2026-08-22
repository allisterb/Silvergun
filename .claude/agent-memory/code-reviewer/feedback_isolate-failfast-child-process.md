---
name: feedback_isolate-failfast-child-process
description: How to safely re-verify a regression test whose whole point is that reverting the fix kills a process (ADR-0021 FailFast class)
metadata:
  type: feedback
---

When a task explicitly warns that re-running a check against a *reverted* fix will kill the
process running it (ADR-0021's `Environment.FailFast` class — exit 35 or an OS-specific
abnormal code, no managed exception, no `catch` anywhere), don't just trust the diff and the
claimed exit code — **actually revert, rebuild, and run it**, but only as a genuine child
process of the Bash tool (a fresh `dotnet build`/`dotnet test`/direct `.exe` invocation), never
in-process. The Bash tool's own subprocess boundary is sufficient isolation; nothing extra is
needed. Then restore the fix and diff-check the restore is byte-identical before moving on.

**Why:** this is the only way to actually confirm two things the diff alone can't show: (1)
the test truly goes red on the old code — not vacuously green — and (2) the surrounding test
host (`dotnet test`'s vstest process) survives the child's abnormal exit and reports a clean
failure rather than itself dying. Observed directly on the ADR-0021/0022 Stage 0 regression
test (2026-07-27): reverting the 2-line CCI fix produced exit `-2146232797` through the vstest
host and exit `35` running the built apphost directly — two different OS-level codes for the
same underlying FailFast, which is exactly why the test's own assertion (`ExitedCleanly` =
"exited 0", not a magic number) is the right design and confirms [[project_cci_signature_decoding]].

**How to apply:** whenever a review task calls out a FailFast-shaped test, budget the extra
few minutes to revert -> rebuild -> run -> observe both output and host survival -> restore ->
diff-check the restore, rather than accepting "the implementer reported X" as given. This is
"verify, don't accept" applied specifically to uncatchable-crash regression tests.

**Corollary — the tree-copy variant is strictly better than revert-in-place, and is an
acceptable way for an implementer to establish "red".** Seen 2026-08-22 (ADR-0029 round 5): the
author tar-copied `src/ ext/ tests/` into a scratch dir, restored the *defective* predicate in the
copy, and measured there — repo never mutated, so there is no restore to forget or diff-check.
Accept it when the numbers are self-validating: "N of the new cases fail" proves the mutation
actually reached the compiled output, which is the one thing a copied tree can silently get wrong
(a copied `obj/project.assets.json` holds absolute paths back to the original). Also check the
report names which mutation each test caught — one mutation caught by exactly one test is evidence
of targeting; the pre-existing suite passing under the mutation is the blind spot, measured.
Repo-root files outside the copied set (here `nuget.config`) are a restore-only risk that fails
loudly, not a silent one.

**Corollary — a FailFast fixture goes blunt once the crash it names is point-fixed.** A *new*
test that reuses an existing pathological shape to guard a *different* property is often
non-discriminating, because the shape no longer crashes anything. Seen 2026-07-31 on
capability-map phase 2: a child-process test claimed to guard "`Match` must key on
`ContainingType`, never `IMethodReference.Parameters`" using the `TypedReference*` fixture — but
ADR-0022 Stage 0 had already added `case ElementType.TypedReference`, so the forbidden
composition runs clean too. Verify by building a throwaway console in the scratchpad that
performs the *forbidden* operation on the same fixture and checking its exit code; if it exits 0,
the test is a smoke test, not a regression detector, and its doc comment must say so.
