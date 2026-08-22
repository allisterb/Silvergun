---
name: test-the-shipping-configuration
description: Verify you are exercising the configuration the design assumes — a whole session of measurements ran against an AnyCPU build the ADR never intended, invalidating a result
metadata:
  type: feedback
---

**Before trusting a measurement, check that it ran in the configuration the design actually
specifies.** Not the configuration that is convenient to run.

**Why:** observed 2026-08-21. ADR-0016 decision 1 says the Windows YARA backend ships **per-RID**
(`win-* publish -> in-process`). Every measurement, every scan and every diagnosis for an entire
session ran against a plain `dotnet build` **AnyCPU, no-`RuntimeIdentifier`** output — a configuration
the ADR never intended to work. In that layout the mixed-mode `libyara.NET.dll` and its `Ijwhost.dll`
IJW shim stay under `runtimes/win-x64/{lib,native}/`, where the native loader cannot find the shim, so
**the backend failed to load on every scan**.

Consequences that cost real time:
- A whole prevalence row ("YARA: not measured") was an artifact of the build configuration.
- A debugger diagnosed "the native libyara core is missing from the publish output". **Wrong** —
  there is no separate native libyara; `libyara.NET.dll` is mixed-mode and contains the engine. The
  only external native piece is `Ijwhost.dll`, and it ships in the package. Someone acting on that
  diagnosis would have hunted for a file that does not exist.
- A `dotnet publish -r win-x64` flattens both DLLs into the output root and the load simply works.
  No dependency to add.

**How to apply:**
- When an optional/native/mixed-mode backend "does not work", **check the build configuration before
  the code**. AnyCPU + no RID is the usual culprit on Windows for anything mixed-mode or RID-scoped.
- When an ADR specifies a deployment model (per-RID, self-contained, a particular TFM), **say so in
  the measurement spec** and confirm the run used it. A measurement in the wrong configuration is not
  a weak result, it is a wrong one.
- Re-read the ADR that owns a component before diagnosing that component. ADR-0016 contained the
  answer the whole time.

**Corollary — a "before" number must say which tree it came from (2026-08-21).** I wrote an ADR whose
before/after read "34.9 s → 7.0 s", but the 34.9 s baseline was an *uncommitted working-tree* state
(a timeout someone had added earlier that day); against committed `HEAD` the real before-behaviour was
an unbounded hang. A reviewer caught it by diffing against `HEAD`. Anyone later trying to reproduce
the baseline from `master` would have failed and doubted the whole result. **When this repo has
uncommitted `src/` changes at the start of a session — which is usual, since we never commit
automatically — name the three states explicitly: `HEAD`, working tree at start, working tree after.**

Related: [[inert-guard-defect-class]], [[measure-before-designing]]
