---
name: capability-map-phase2-gate
description: Open decision for capability-map phase 2 — the legacy catalog's StartsWith over-matches produce findings the v2 map has no entry for, and phase 1's tests structurally cannot catch it.
metadata:
  type: project
---

Phase 2 of the capability map (wiring `CapabilityAnalysis.Match` onto `CapabilityMap`) will **lose
findings** for types the legacy catalog only matched by accident, via
`typeName.StartsWith(api.TypePrefix)`. Raised in the 2026-07-25 phase-1 review; not yet resolved.

Concretely, `System.IO.File` / `System.IO.Directory` / `System.Net.Dns` / `System.Diagnostics.Process`
as `StartsWith` prefixes also match `FileNotFoundException`, `FileLoadException`, `FileStreamOptions`,
`DirectoryNotFoundException`, `DnsEndPoint`, `ProcessModule(Collection)`, `ProcessThread(Collection)` —
none of which have `capabilities.cm` entries. `throw new FileNotFoundException(...)` is a `newobj` on a
very common type, so this is not theoretical.

**Why:** the phase-2 acceptance gate in `docs/agent/tasks/capability-map.md` says a disappeared finding
"must be explained, never accepted". The phase-1 data test
(`CapabilityMapDataTests.RepresentativeKey`) synthesizes its probe key *from the catalog entry itself*,
so it can only prove the literal entry text is represented and is blind to over-matches by construction.

**How to apply:** when reviewing phase 2, do not accept "all IL tests green" as evidence the gate held —
require the actual before/after finding diff on a real assembly, and check these specific types. The
resolution is a deliberate choice (add explicit entries, or list them as accepted false-positive
removals), not a test tweak. Related: [[canonical-name-parity]].
