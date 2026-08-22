---
name: task-wait-timeout-fault-path
description: Review rule — when code bounds a blocking native call with Task.Run + Wait(timeout), check the FAULT path separately from the timeout path; Wait(timeout) throws AggregateException, so a try/catch placed after the Wait does not catch it.
metadata:
  type: feedback
---

When reviewing the `Task.Run(...)` + `task.Wait(bound)` shape that Silvergun uses to put a wall-clock
bound on an uncancellable native call, always trace **three** exits, not two: completed, timed out, and
**faulted**. `Task.Wait(TimeSpan)` calls `ThrowIfExceptional` once the wait succeeds, so a faulted task
throws `AggregateException` **out of the `Wait` call itself** — not out of a later `task.Result`. A
`try { var r = task.Result; } catch { }` placed *after* the `Wait` therefore never runs, and the fault
escapes the method.

**Why:** found exactly this in `LibYaraScanner.ScanFile` (2026-08-21, ADR-0028 implementation). The
`Wait` sat outside the try and the `.Result` line carried a comment claiming "rethrows a faulted task's
exception here (wrapped), caught below" — which is false. Because `IYaraScanner` contracts to *never
throw* except one deliberate `TimeoutException`, that turned any per-file native libyara error
(`ErrorUtility::ThrowOnError` → `YaraException`, or the wrapper's `FileNotFoundException` on an
unopenable file) into an escaping exception that downgrades a whole package to
`YaraScanStatus.Unavailable`. Verified empirically with a throwaway console app rather than from docs.

**How to apply:** whenever you see `Wait(`, `WaitAsync`, or `.Result` guarding a native/interop call,
locate the try boundary relative to the `Wait`. The correct shape keeps the `Wait` **inside** the
try/catch and throws the intended `TimeoutException` **after** the catch, so the timeout escape stays
the only escape. ADR-0028 decision 9 explicitly blesses "the same `Task.Run` + `Wait(bound)` shape",
so future code will copy it — check every copy. Related: [[project_yara-compiler-poisoning-review]].
