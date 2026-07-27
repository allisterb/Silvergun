---
name: script-rule-precision-review
description: Reviews of the nuspec prose-redaction / script-finding aggregation precision fix (docs/agent/tasks/script-rule-precision.md) — base pass 2026-07-24, follow-up pass (regex -> linear scan + non-element constructs) 2026-07-24; records the ReDoS-measurement and hostile-input fuzzing techniques
metadata:
  type: project
---

The `scan-package` script-rule precision fix (prose redaction in `ScriptRuleScanner`,
`(RuleId, RelativePath)` aggregation, `ScriptFindingSource` gate separation) passed review
on 2026-07-24, and its two follow-ups passed the same day: (A) `RedactProse` rewritten from
two `Regex`es to a hand-rolled monotonic forward pass with a `uint unclosed` memo bitmask,
(B) `SkipNonElement` for comment/CDATA/PI/`<!…>`. Tests green at 322 / 105.

**Why:** the fix was driven by measured false positives (11 findings from one benign
package's `.nuspec` prose, breaking `--strict`), and the follow-up by a reviewer Warning that
a hostile-but-under-cap nuspec could force the regex timeout — and a timeout *skipped the
file*, letting a package suppress its own metadata findings.

**How to apply:**
- **Prior ReDoS/evasion Warning is closed.** No regex remains in `ScriptRuleScanner`. Do not
  reintroduce one for lexical blanking; `RegexOptions.NonBacktracking` is unusable while the
  pattern carries a backreference (`</\1>`).
- **Technique worth reusing — measure, don't eyeball.** For regexes: drive the real pattern
  with the same options/timeout over hostile input under the size cap (a wall-clock equal to
  the timeout proves reachable degeneracy). For hand-rolled scanners: reflect the `internal`
  method out of the built DLL in a scratchpad console app (resolve deps from the *test*
  bin dir via `AssemblyLoadContext.Default.Resolving`) and fuzz token-concatenations,
  asserting length/newline/only-blanked invariants plus a per-input time bound. ~200k cases
  + megabyte degenerate shapes ran in seconds and is far stronger than reading the loop.
- **Reachability argument that resolved the residual quote-derailment worry:**
  `PackageScanner`/`NuGetPackage.Open` construct `PackageArchiveReader.NuspecReader`, which
  parses the manifest XML eagerly, so a malformed nuspec fails `Open` and never reaches
  `ScanPackageMetadata`. In well-formed XML, attribute values are always quoted and text
  cannot contain a raw `<`, so the "stray apostrophe read as an attribute quote" abort is
  unreachable once comments/CDATA/PIs are skipped. Re-check this if the scanner ever gains a
  path that rule-scans a nuspec without NuGet parsing it first.
- **Known open limitation (flagged, not fixed):** prose/`repository` matching compares the
  whole XML name, so namespace-prefixed forms (`<nu:description>`) are not redacted while
  NuGet still reads them as prose. Precision-only (metadata findings are advisory and never
  gate `--strict`). Same class as the accepted `<!DOCTYPE>`-internal-subset limitation.
- Open, accepted trade-off to re-examine if the corpus work lands: prose redaction also
  hides genuine URL/IOC text inside `<description>`/`<releaseNotes>`. Spec option 2 (a
  narrow nuspec ruleset) was deferred and is the tracked follow-up.

Related: [[project_hostile_input_never_throws]], [[feedback_spectre_reports_review]].
