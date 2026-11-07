# Packaging anomalies + coverage-loss prevalence (top-100 benign corpus, 2026-08-22)

Raw data: `packaging-anomalies-top100-2026-08-22.tsv` (100 rows). Spec:
`docs/agent/tasks/containment-claim-and-escaping-round2.md`. Decisions under test: **ADR-0031**
(packaging anomalies) and **ADR-0030 sixth instance** (lexical containment / coverage loss).
Code: `HEAD df94310` **plus the uncommitted ADR-0030/0031 working tree**.

## Result

| Question | Answer |
| --- | --- |
| Anomaly prevalence, all 7 categories | **0 / 100 packages, 0 anomalies over 2,287 declared entries** |
| `UninventoriedCount > 0` (the new coverage-loss signal) | **0 / 100** |
| Exit-code distribution | **95 × 0, 5 × 3 — identical to the earlier run, package by package** |
| Benign packages flipping 0 → 3 | **none** |
| Child health | 0 timeouts, 0 crashes, 0 missing reports, all codes in {0, 3} |
| Wall clock | 524 s (400 s in children); slowest child 14.2 s = 4.7 % of the 300 s bound |

**This closes the rule I broke.** ADR-0031 decision 3 says nothing changes a verdict until its benign
prevalence is measured, and the containment fix shipped a verdict change (exit 0 → 3, *regardless of
`--strict`*) without one. Measured: it changes no benign verdict. The five exit-3 packages are the
same five, incomplete for the same pre-existing reason (native binaries that produce no analysis), not
via the new signal.

## The zero is falsifiable — three independent checks

1. **Positive control through the same binary and the same parse path:** a synthetic `.nupkg` with one
   entry per category reports **7 anomalies, one per category**, plus **2 uninventoried entries**. Both
   channels are live.
2. **Independent re-derivation:** a probe written straight from ADR-0031's table against the zip
   central directory, calling **no Silvergun code**, agrees — 0 on the corpus, 7 on the control.
3. **Arithmetic closes:** 855 inventoried assemblies − 848 with a capability report = 7, exactly the 7
   files named in the 5 incompleteness messages. Zero `Skipping extracted file` warnings across all
   100 packages, so nothing was lost in the other direction either.

⚠️ **The first version of check 2 was inert, and it is worth knowing why.** Implemented in Windows
PowerShell 5.1, whose .NET Framework `ZipArchive` **silently truncates entry enumeration at a name
containing a control character** — it returned 1 null name for the 10-entry control package. Rewritten
on .NET 10, it worked. **Any zip tooling in this repo must run on .NET 10, not Windows PowerShell 5.1**,
and a probe that returns "nothing found" on a control package is not a result.

## What the 0/100 does not cover

- **Long paths are not exercised.** Longest declared name is 104 chars; worst-case extracted path is
  221, i.e. 39 under `MAX_PATH`. The corpus cannot produce a long-path refusal, so this measurement is
  silent on that failure mode.
- **Non-ASCII entry names are not exercised.** All 2,287 declared names are pure ASCII — verified by
  walking the raw central-directory records, not the decoded strings — so the `ZipFile`-vs-extractor
  name-decoding mismatch (a candidate false coverage-loss) is *excluded for this corpus* rather than
  disproved in general.
- Benign corpus ⇒ this is the false-positive column only. Nothing here speaks to detection rate.

## Defect found by this measurement (routed, not fixed here)

**`InvisibleCharacter` anomalies are reported with the invisible character still in them** — ADR-0031
decision 4 is violated by the one category whose entire premise is "you cannot see this".
`YaraPathSafety.NeedsEscape` covers C0, DEL, C1, U+2028/9 and bidi, but not U+200B–U+200D, U+FEFF,
U+00AD or the astral Tag block. Measured: the human-readable report contains the literal bytes
`E2 80 8B`. The JSON looks correct only **by accident** — `System.Text.Json` escapes non-ASCII by
default, so that escaping is STJ's, not ours. And `Escape` iterates `char`, so the Tag block's
surrogate halves miss every predicate — which is exactly why an escaper "property-tested over the BMP"
did not catch it.

## Provenance

Build: `dotnet build src/Silvergun.CLI/Silvergun.CLI.csproj -c Release -f net10.0-windows -r win-x64`,
run per-RID (ADR-0016). Backend liveness confirmed **per package, not assumed**: 100/100 reports
`YaraScanStatus = Completed` and 100/100 children logged `Compiled 309 embedded YARA rule file(s)`.
Command: `scan-package <nupkg> --json --strict --depth 0 --output <file>`, OSV on, one child per
package, 300 s bound, 1.2 s between packages; 100/100 `VulnerabilitiesStatus = Completed`, no 429, no
403. Corpus: the same 100 `(Id, Version)` pairs as `yara-corpus-top100-2026-08-22.tsv`, warm cache,
zero downloads. `DeclaredEntryCount` counts **all** central-directory entries (matching the product's
`DeclaredEntryNames`), where the earlier TSV's `FilesScanned` counted file entries only — they agree on
99 packages; `Google.Protobuf` 3.35.1 is the only one shipping explicit directory entries (27 vs 17).
