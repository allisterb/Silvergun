---
name: project-hostile-input-threat-model
description: Silvergun ingests potentially-malicious packages/assemblies by design — treat all package/assembly input as hostile and apply defense-in-depth
metadata:
  type: project
---

Silvergun's core purpose is analyzing **potentially malicious** NuGet packages and .NET
assemblies *before* a developer installs them. So its own input-handling code operates on a
hostile-input threat model — untrusted archives, crafted metadata, adversarial IL.

**Why:** it's a security tool whose whole value is inspecting attacker-controlled artifacts; a
parsing/extraction bug in Silvergun itself is directly exploitable. Concrete instance: the
package-intake reviewer flagged a zip-slip (`../../evil.dll`) path-traversal in `.nupkg`
extraction — fixed with canonicalize-and-verify-containment before writing any file.

**How to apply:** for any task touching package/assembly ingestion (extraction, path handling,
metadata parsing, script/manifest reading), specs and review must call out the hostile-input
angle explicitly — validate/sandbox untrusted paths, don't trust upstream library defenses
alone, add a malicious-input regression test. Don't rely on "benign fixture passed" as
sufficient. Relates to [[reference-pdf-books]] (static-analysis theory) and the recall-over-
precision stance in ADR 0002.
