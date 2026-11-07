# Differential test — CLI YARA backend on Linux vs in-process on Windows (top-100, 2026-08-22)

Raw data: `yara-cli-backend-linux-2026-08-22.tsv` (100 rows). Spec:
`docs/agent/tasks/yara-cli-backend-corpus-wsl.md`. Counterpart:
`yara-corpus-top100-2026-08-22.md` (Windows in-process). Commit under test: **`cc8e6da`**.

## Headline

**A newline in a package entry name silently suppresses a genuine YARA hit on the Linux backend,
while the scan still reports `Completed`.** Attacker-controlled false negative in the backend that
ships to Linux CI. Not on the pre-registered list of expected differences — it is the reason this run
was worth doing. Root cause, remedy and reasoning: **ADR-0029**; fix task:
`docs/agent/tasks/yara-cli-unsafe-path-names.md`.

`yara -r` echoes the matched path on its header line and `YaraCliOutput.ParseAll` splits stdout on
`'\n'`, so a newline in the name splits one hit across two physical lines:

```
Win32_Trojan_HermeticWiper [tc_detection,malicious] /tmp/silvergun/pkg-…/lib/net8.0/nl
Win32_Trojan_HermeticWiper [x] /etc/passwd.bin
```

Measured on a synthetic package with the same matching sample at three paths: **2 findings returned,
not 3**, status `Completed`, no warning. Newlines are legal in zip entry names and RecursiveExtractor
writes them verbatim. Windows is structurally immune (per-file scanning; NTFS cannot hold the name),
which is exactly why Windows-only testing could never surface it — **the second Linux-only defect this
project has found by running on Linux**, after the backslash-normalisation bug.

**Two defences held under active attack, and that is worth recording.** The attacker-authored second
line parses as a new header with an attacker-chosen rule name, but `TargetMatches` requires the echoed
target to resolve to a real file under the scanned root, so `/etc/passwd.bin` was rejected — the
`EndsWith` → normalised-exact-equality fix did precisely the job it was added for. Forging a hit
against a different *real* file is not practically reachable either: the target must equal an absolute
path under a per-run random temp root. **The exploitable outcome is the false negative, not a forged
finding.**

## Backend agreement — 100/100 identical

| Comparison | Result |
| --- | --- |
| Row keys `(Id, Version)` | identical sets, 100/100 |
| Identical finding set | **100** |
| Linux-only / Windows-only / different | **0 / 0 / 0** |
| `YaraStatus` | `Completed` ×100 on both |
| `FilesScanned` | 0 mismatches; totals **2,277 = 2,277** |
| Incompleteness set | identical — same 5 packages, same unanalysable native DLLs |

Both backends: **0 findings over 2,277 files**. Two independent implementations over the same 310 rule
files agreeing exactly is the first real correctness evidence either backend has had — until now the
only evidence was that they produced *something*.

Backend selection was proved positively, not inferred: all 100 children logged
`Compiled 310 embedded YARA rule file(s) with yarac`, a line only `YaraCliScanner` emits
(`BackendSelected = YaraCliScanner/yarac:310` on every row). `yara`/`yarac` 4.1.3.

## The pre-registered expectations, resolved

1. **310 vs 309 rule files — confirmed by measurement**, and the one dropped file on Windows is the
   ELF rule (`virus.Linux.Virus.Vit.yara`). It matched nothing here, so the Windows coverage gap is
   **real but unexercised** by this corpus.
2. Version skew 4.1.3 vs 4.5.5 — produced no observable divergence on this corpus.
3. **`Namespace` null — expectation was wrong.** It is null on *both* backends (libyara.NET's `Rule`
   wrapper does not surface it either), so this is a shared gap, not a CLI-backend one.
4. Batch `yara -r` vs per-file — no divergence in findings; see the headline for where it *does* matter.
5. Cost profile — confirmed, quantified below.

## Path attribution — made non-vacuous on purpose

With 0 corpus hits there were 0 paths to verify, so the check was performed against a synthetic
package carrying a known-matching sample at three stress paths plus three suffix-named decoys. Linux
returned 3 findings, all correctly attributed: **deep nesting**, **a path with a space**, and **a
non-ASCII segment** (`content/uni-café/`). No decoy sibling was attributed. The same package on the
Windows in-process backend returns the identical 3 findings, same rule, tags, family, detection name
and category. That is the only genuine two-implementation finding-set comparison this run produced,
and the backends agree exactly.

Also checked and clean: a **backslash** in an entry name is materialised by the extractor as a real
directory separator on Linux, so `PackageScanner.PackageRelativePath`'s unconditional
`Replace('\\','/')` causes no corruption.

## Cost

Per-package elapsed on Linux (re-aggregated from the TSV by the architect: **median 2,450 ms**, min
1,561, max 7,594; agent reported median 2,469 — median-index convention, same data). **Total wall
clock 298 s for 100 packages.** This includes a full `yarac` recompilation of all 310 rule files on
**every invocation**.

- `yarac` alone over the concatenated source, 5 warm runs: median **437 ms**. ⚠️ My earlier 2.9 s
  figure was **cold-cache and should not be quoted** — warm, it is ~440 ms.
- YARA's whole contribution, measured by switching the backend off over a 10-package subset:
  **median 420 ms** per package (max 1,553 ms on `AWSSDK.Core`, whose 5 MB of XML dominates the scan).

Not directly comparable to Windows (different OS, filesystem, Defender, exit path). For reference the
Windows in-process contribution is ≈800 ms fixed + ≈4 ms/file. **The two constants are the same order
of magnitude — the CLI backend's per-invocation rule compilation is not the disqualifier it looked
like.** That is relevant to any future backend-strategy discussion, though not decisive on its own.

## Scope limit

Benign corpus. This measures false-positive rate (0/100 on both backends) and cost. It says nothing
about detection rate. The synthetic positive controls establish that both engines *can* match and
attribute correctly — one column of a confusion matrix, not the matrix.

## Provenance

WSL2 Ubuntu, kernel 6.18.33.2, .NET SDK 10.0.103, `yara`/`yarac` 4.1.3 from `/usr/bin`. CLI built
`-f net10.0`; `SILVERGUN_YARA_PATH=/usr/bin/yara`. Command:
`scan-package <nupkg> --json --depth 0 --no-vulns --output <file>`, one child per package, 300 s
bound. `--no-vulns` is why all 100 exit 3 — **exit codes and vulnerability columns are deliberately
not comparable to the Windows run.** Corpus copied to `C:\Temp\silvergun-corpus\` (173 nupkg, 291 MB,
outside the repo) because WSL cannot read `%LOCALAPPDATA%\Silvergun` on this machine. Zero downloads.
