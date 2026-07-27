---
name: project-positioning-differentiated-lane
description: Silvergun's core lane is static + dynamic analysis NuGet/VS don't do; VS/NuGet vuln-data parity (e.g. resolver-lite) is completeness, not the differentiator
metadata:
  type: project
---

Silvergun's differentiated value is **static and package analysis, and hunting
things NuGet and Visual Studio don't surface** (capability/obfuscation/YARA/
script-content/squat detection). Matching the vulnerability-data comprehensiveness
of the NuGet and VS interfaces — the resolver-lite transitive walk ([[resolver-lite]]
work, ADR 0018) and OSV/NuGet-inline vuln data (ADR 0017) — is a **completeness /
parity** goal, not the core product.

**Why:** the user did not originally see Silvergun as replacing NuGet/VS vuln
reports. Two reasons to pursue parity anyway: (1) users will assume that running
the Silvergun analyzer gives them everything they already see in the NuGet/VS UIs,
so falling short is a surprise; (2) the data and core techniques are public, so it's
not much effort. But this data is **commodity** — other tools surface it too, so it
is not a differentiator.

**How to apply:** when prioritizing or scoping, favor the differentiated
static/dynamic-hunting capabilities over VS/NuGet-parity features. Treat parity work
(vuln data, transitive resolution) as bounded, best-effort completeness — worth doing
because it's cheap and expected, but not worth large investment or letting it become
a hard dependency of the core scan (consistent with ADR 0018 keeping resolver-lite
optional and [[project-external-intel-optional-keys]] degrading gracefully). If a
parity feature starts demanding heavy effort, flag the tradeoff rather than chasing
NuGet/VS feature-for-feature.
