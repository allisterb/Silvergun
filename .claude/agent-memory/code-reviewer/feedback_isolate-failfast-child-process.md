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
