---
name: project-cci-signature-decoding
description: ADR-0022's staged plan to fix CCI's signature decoder (FailFast crashes) using SRM as reference/source
metadata:
  type: project
---

ADR-0022 (`docs/agent/decisions/0022-modernize-cci-metadata-reading-with-srm.md`) plans a
staged replacement of CCI's `SignatureConverter.GetTypeReference()` in
`ext/analysis-net/cci/PEReaderAndWriter/PEReader/PEFileToObjectModel.cs`, because CCI's
`Debug.Assert`/`Debug.Fail` route to `Environment.FailFast` (exit 35, unmanaged-catchable) —
see ADR-0021.

- **Stage 0** (reviewed 2026-07-27): add missing `case ElementType.TypedReference:` arm to
  `GetTypeReference()`, returning `PlatformType.SystemTypedReference`. Landed clean — see
  [[feedback-ext-signature-decoder-review]] for the verification approach that held up.
- **Stage 0 regression coverage** (reviewed 2026-07-27, same day): added
  `tests/Silvergun.CodeAnalysis.IL.Tests.PathologicalSignatureProbe` (self-analyzing console
  probe) + `ChildProcessProbe`/`TypedReferencePointerRegressionTests` in
  `Silvergun.CodeAnalysis.IL.Tests`. Verified genuinely regression-detecting by physically
  reverting the Stage 0 fix, rebuilding, and re-running: all 4 facts failed cleanly (exit
  -2146232797 observed via `dotnet test`'s vstest host; exit 35 observed running the apphost
  directly — `ChildProcessProbe.ExitedCleanly` correctly keys on "exited 0", not a magic
  number, which is why both shapes are caught) with the xUnit host itself surviving to report
  all 4 failures — not a host crash. Fix was restored and reconfirmed identical (+2/-0). See
  [[feedback_isolate-failfast-child-process]] for how to safely re-run this class of check.
- **Stage 1** (not yet done): centralize `Debug.Assert`/`Debug.Fail` policy via a
  `global using Debug = Microsoft.Cci.CciDebug;` + one new file, so all 195 call sites rebind
  with zero upstream-file edits (zero merge conflicts against the asnarnd fork).
- **Stage 2** (not yet done): port SRM's `Ecma335/SignatureDecoder.cs` into the CCI fork as new
  files, with CCI's entry points delegating to it. Placement rule is binding: new files only,
  upstream files touched solely to add the delegation call. Requires MIT attribution
  (.NET Foundation header + NOTICE-style note) since it's copied/adapted from
  `reference/projects/dotnet-runtime/System.Reflection.Metadata` — user has already approved
  this copying, scoped to this port.
- **Why this matters for review:** each stage after 0 will touch many more lines of
  `PEFileToObjectModel.cs`/`ILReader.cs`. Check future diffs against the "new files, minimal
  upstream touch" placement rule, and check attribution headers land on any file adapted from
  SRM.

**How to apply:** when reviewing future CCI signature-decoder changes, check which ADR-0022
stage they belong to and hold them to that stage's stated scope/placement rule.
