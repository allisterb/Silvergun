---
name: external-intel-optional-keys
description: Silvergun enriches analysis with optional user-provided API keys for external intel (libraries.io, OSS Index, Sonatype…); degrade gracefully to keyless when absent — enrichment, never a hard dependency
metadata:
  type: project
---

Design principle the user articulated (2026-07-16): external package-intel sources should be
**optional, user-configured, and graceful**.

**Why:** most useful intel sources (libraries.io, OSS Index, Sonatype, Snyk, deps.dev) are no
longer open-access but offer **free API keys on registration**. A user who supplies a key gets a
materially better security posture (e.g. SourceRank/dependents_count for stronger squat scoring,
reputation/known-malicious cross-checks); a user without one must still get a working tool.

**How to apply:** design intel integrations as *enrichment* behind an abstraction (e.g.
`IPackagePopularitySource` already exists; a future reputation source similarly). Read keys from
config/env; when a key is absent or the service is down, **fall back to the free/keyless path**
(NuGet.Protocol) and never fail the analysis. Never make an external keyed service a hard
dependency of a scan. First concrete candidate: `LibrariesIoPopularitySource` (SourceRank +
dependents) as a second `IPackagePopularitySource` for squat detection — see the research journal
([[research-journal]]) "External intel sources" entry. Ties to the planned OSS Index/Sonatype
reputation layer.
