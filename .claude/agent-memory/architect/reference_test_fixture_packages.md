---
name: test-fixture-packages
description: Real nuget.org packages authored by the user, useful as live smoke-test fixtures (e.g. transitive-vuln package for resolver-lite)
metadata:
  type: reference
---

Real packages the user authored, published on nuget.org, useful as **live** end-to-end
smoke-test fixtures (not unit tests — the live paths like resolver-lite orchestration /
`OsvClient` / `NuGetPackageDependencyFetcher` have no injection seam by design).

- **`Jumbee.Console.Snapshot`** (author: Allister Beharry; net10.0). Has a **transitive**
  known vulnerability, ideal for the resolver-lite `--depth` path. As of 0.1.5:
  direct deps = `Jumbee.Console`, `SixLabors.Fonts [2.1.3,)`, `SixLabors.ImageSharp.Drawing
  [2.1.6,)`. The vuln lives at **depth 2**: `ImageSharp.Drawing 2.1.6` → `SixLabors.ImageSharp
  3.1.8`, which carries **GHSA-rxmq-m78w-7wmc / CVE-2025-54575** (Moderate, GIF-decoder
  infinite loop). Confirmed 2026-07-24: `scan-package --depth 0` and `--depth 1` report 0
  vulns; `--depth 2` surfaces exactly 1 (tagged `[dependency]`), `DependencyResolution=Complete`.
  So it exercises depth-gating precisely (vuln invisible until depth ≥ 2). Related: [[resolver-lite]].

**How to run a live smoke:** download the `.nupkg` from the flat-container API
(`https://api.nuget.org/v3-flatcontainer/{id-lower}/{ver}/{id-lower}.{ver}.nupkg`), then
`dotnet run --project src/Silvergun.CLI -f net10.0 -- scan-package <win-path> --depth 2 --json`.
Use `cygpath -w` for the path (the CLI is a Windows .NET process). Verify with `git log`/re-query
before relying on version-specific facts above — nuget.org and advisories change over time.

Observation from that run (NOT a resolver-lite issue): the script/content scanner (ADR-0012,
OSSGadget backdoor rules over `.nuspec`) flagged 11 LOLBAS/"Backdoor: Long Strings" findings on
this benign package's own nuspec — false positives. Data point for the calibration/corpus work.
