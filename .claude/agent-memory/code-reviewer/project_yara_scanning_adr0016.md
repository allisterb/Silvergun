---
name: project-yara-scanning-adr0016
description: YARA scanning feature (ADR 0016) phases 1-3 review history and verification technique for multi-target TFM isolation
metadata:
  type: project
---

Silvergun added YARA malware-signature scanning (`ext/reversinglabs-yara-rules` submodule, MIT) across three
phases: Phase 1 (core `IYaraScanner` abstraction + Windows in-process `LibYaraScanner`, both projects go
`net10.0;net10.0-windows`), Phase 2 (`YaraCliScanner` classic `yara`/`yarac` CLI backend + `YaraRuleIndex`
rule-metadata parser, ported from `reference/projects/Yara` with user approval 2026-07-17), Phase 3 (wiring
into `PackageScanner.Scan`/`--no-yara`, `PackageCapabilityReport.YaraFindings`, `--strict` gate, report
rendering, `Silvergun.CLI` goes multi-target too). Reviewed 2026-07-21, Phase 3 — clean pass, two Warnings:
`Yara/IYaraScanner.cs` methods aren't wrapped in `#region Methods` (the codebase's own interface convention,
e.g. `Squats/IMutator.cs`, does wrap); and the new `--no-yara`-unavailable stderr note in `Program.cs`
duplicates the `YaraCliScanner.Locate()` Warn-logged note (via `WithFileAndConsoleLogging`'s Serilog console
sink) when `SILVERGUN_YARA_PATH` is unset in non-json/default mode — same pre-existing pattern as `--health`'s
note, not a new deviation, just worth a dedupe pass. Also flagged (informational, not blocking): a new
test-engineer JSON-round-trip test compared full `YaraFinding` records containing `Tags` typed
`IReadOnlyList<string>`, where the original is a `string[]` and the JSON-deserialized copy is a `List<string>`
— record default equality is not structural across those concrete types, so the test fails even though the
round-trip itself is correct; the fix belongs in the test (compare `Tags` via `SequenceEqual`), not the source.

**Why:** Recurring facts worth remembering for future YARA-related reviews in this repo, and a verification
technique that generalizes to any future multi-target isolation check.

**How to apply:**
- **Verifying TFM isolation via `project.assets.json` (not `dotnet list package`, per env rule):** the file's
  top-level `"libraries"` section lists every package resolved across ALL TFMs (a naive whole-file grep for a
  Windows-only package will always find it there and give a false "leak" signal). The load-bearing section is
  `"targets"` → find the per-TFM keys (e.g. `grep -n '^    "' obj/project.assets.json` restricted to before the
  `"libraries"` line) and confirm the package appears only under the Windows-suffixed target block (e.g.
  `net10.0-windows7.0`), never under the plain `net10.0` one. Cross-check with `bin/<config>/<tfm>/` — the
  final CLI (Exe) output is what matters for the Linux-loadable guarantee; a referenced class library's own
  `bin/` folder may legitimately NOT copy a transitive native package locally even when its `.deps.json`
  correctly lists it (that's expected SDK behavior for library projects, not a leak).
- Record additive-JSON-back-compat pattern used for `PackageCapabilityReport.YaraFindings`: redeclare the
  record's auto-property with an explicit `init` initializer (`YaraFindings ?? Array.Empty<YaraFinding>()`)
  referencing the primary-constructor parameter — normalizes missing/`null` JSON to an empty list without a
  custom converter. Same technique would apply to any future additive-list report field.
- See [[project_project_health_intel_review]] for the sibling ADR 0015 review and [[feedback_spectre_reports_review]]
  for the shared `ReportTheme.Esc` escaping pattern this feature's renderer also follows correctly.
