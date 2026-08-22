---
name: dogfood-constraint
description: Silvergun must not do anything Silvergun would flag as a finding — no runtime download-and-execute of external binaries, even for its own engines; vendoring inside the signed artifact is the acceptable form
metadata:
  type: feedback
---

**Silvergun may not ship a behaviour that Silvergun's own rules would flag.** The concrete case the
user raised (2026-08-21): a plan to have the tool acquire `yara.exe` from an external location.
"Having a NuGet package or tool download an exe from an external location seems exactly the behavior
or capability a scanner like Silvergun would flag as a finding."

**Why:** credibility is the product. A supply-chain scanner that performs download-and-execute has
disarmed its own argument, and any user who ran Silvergun on Silvergun would see it. This is not
hypothetical — dynamic acquisition of an executable is squarely inside our existing capability
categories.

**How to apply:**
- **Runtime acquisition of a binary is out**, in all forms: first-run download, install script,
  bootstrapper, "we'll fetch it if it's missing". Not negotiable by convenience.
- **Vendoring is different and is acceptable**: a third-party binary that ships *inside* the artifact
  the user already chose to install, pinned and attributed, involves no acquisition at scan time.
  It costs artifact size and a redistribution/licence obligation — raise those, don't hide them.
- **A package-manager prerequisite is acceptable where one genuinely exists** (`apt`/`dnf`/`apk` on
  Linux). The user's point is that **Windows has no comparable universally-present equivalent**, so
  "just require it on PATH" is a Linux-only answer dressed up as a cross-platform one.
- Corollary that resolved the actual design question: an **in-process engine arriving as an ordinary
  NuGet dependency is the cleanest Windows story** precisely because there is no external
  acquisition at all — which is why ADR-0016's per-platform split (in-process on Windows, `yara` CLI
  on Linux) survived scrutiny rather than being consolidated away.
- Generalise beyond YARA: apply the same test to any future engine, ruleset update channel, or
  intel feed that would fetch and execute code. Fetching *data* is a different question, but ask it.

Related: [[positioning-differentiated-lane]], [[hostile-input-threat-model]]
