# YARA-X (`yr` 1.22.0) spike: can it replace classic YARA? (input to ADR-0016 d4) — 2026-10-21

Spec: `docs/agent/tasks/yara-x-spike.md`, Part 2. Raw rows: `yara-x-spike-2026-10-21.tsv`, 4,700+ data rows, using the
isolation measurement's schema `Section Mode Label Iter Round Metric Value Note`. Facts only; no recommendation.

Baselines:
- **Windows:** libyara.NET 4.5.5 in-process. The Windows numbers below come from the timing probe's `--worker` /
  `--inproc-host` modes, which build the engine the way `LibYaraScanner` does (pass 1 / pass 2 / canary).
- **Linux:** classic `yara`/`yarac` 4.1.3 in WSL.
  - Through the product: `Silvergun.CLI scan-package`, i.e. `YaraCliScanner`.
  - Directly with `YaraCliScanner`'s recursive-pass flags (`-C -r -s -g -N --timeout=30`), where the comparison has
    to be per file.

Conventions: median = `statistics.median`; p90 = nearest rank ⌈0.9·N⌉. Times are in ms and memory in MiB.

## Headline

| Question | Result |
| --- | --- |
| **Q1** rule compatibility | **310/310 files compile with `yr` on Windows and Linux**, default mode and `--relaxed-re-syntax`, with 0 errors. The whole set is **1,240 rules**, the same count as classic `yarac` 4.1.3 (310/310). Warnings only: 932× `deprecated_field`, 8× `duplicate_pattern_value`, and +15× `duplicate_import` when the product's concatenated framing is used. Windows in-process classic: 309 files / 1,239 rules (no ELF module) |
| **Q2** synthetic positives | **Identical verdicts** for 8 positives and 4 negatives in every engine: `yr` source, `yr` compiled, and classic (in-process on Windows, CLI on Linux). This covers a `pe.entry_point` rule, jumps/alternations, a `wide` string, the `elf` module and a **certificate-blocklist** rule. The Vit ELF positive could only be run on Linux (Defender, see below) |
| **Q2** benign corpus (100 pkgs, 2,277 files, 339 MB) | **0 hits** in `yr` (Windows and Linux) and in classic (in-process Windows, CLI Linux). Coverage was 2,277/2,277 in all four. The product path on Linux (`scan-package`, YaraCliScanner) gave 100/100 `Completed`, 0 findings |
| **Q3** per-file failures | Unreadable files, unreadable directories, missing targets and a Defender-blocked file are reported **only as free-text `error:` lines on stderr**: no NDJSON record, and **exit code 0**. `--skip-larger` skips files with **no message at all** |
| **Q3** timeouts | **`--timeout` is one global deadline**, not per file. Files still queued at the deadline are **silently dropped**: they appear in neither stdout nor stderr, and the exit code is 0. Example: `-p 1 --timeout 1` covered **1/49**, with 1 timeout line and **47 silent**, in 3/3 runs on both OSes. In-flight files get `error: scanning "…": timeout` |
| **Q3** crash at the deadline | With default threads and `--timeout 3`, `yr` **panicked** (`scan.rs:960:46`, `SendError`, exit 1) and **lost already-produced records** (1–4 lines instead of 8) in **11/20** runs on Windows and **1/20** on Linux. With `--timeout 1` there were 0/40 panics |
| **Q3** hostile names | NDJSON escapes LF, CR, TAB, ESC, `"`, `\` and U+202E faithfully, and they round-trip. **A name that is not valid Unicode panics the NDJSON writer** (`scan.rs:927:43`, exit 1). That is a lone UTF-16 surrogate on Windows, or invalid UTF-8 on Linux. **Records for the other files in the same scan are lost too** (0–15 of 41 emitted). `--output-format json` writes `"file": ""` and text writes U+FFFD; both exit 0 |
| **Q3** symlinks | `-r` follows **no** symlink (to a file, to a directory, dangling, or a loop) on Linux, and no Windows junction. They are skipped **without any message**. There is no follow/no-follow option. A symlink given as the target *is* followed |
| **Q4** 20 trees, one process per tree, compiled rules | **Windows `yr` 5.55 s** (p90 6.56) vs **in-process libyara 3.44 s** scan-only (4.23 s for the whole host process, including the 0.56 s engine build), interleaved. **Linux `yr` 5.50 s** vs **classic `yara -C` 1.92 s**, interleaved |
| **Q4** per-process floor | Loading the 2.36 MB compiled ruleset costs **~150–170 ms per `yr` process** on both OSes. An empty-file scan takes 174 ms vs 24 ms with a one-rule set on Windows, and 183 vs 11 ms on Linux. `yr --version` takes 15–24 ms (Windows) and 2 ms (Linux). The smallest tree (xunit, 7 files) costs ~200–250 ms |
| **Q4** compile | `yr compile` of the 310-file source: **1.55 s** Windows, **1.91 s** Linux (N=7 each), peak 150 / 186 MiB. Classic `yarac` takes 0.30 s for the same source (a single sample from the Q1 run; M5 measured a 286 ms median). Scanning with source rules recompiles on every invocation: 35.6 s (Windows) and 26.6 s (Linux) for the 20 trees |
| **Q5** provenance | `yr.exe` is **NotSigned** (no Authenticode, no version resource). The Linux `yr` is **statically linked** (no `GLIBC_` symbol versions) and runs on the dev WSL (Ubuntu 22.04.5, glibc 2.35). Neither archive ships a licence file |
| **Side effect** | **Microsoft Defender detected the synthetic Vit ELF sample `C:\Temp\sg-yrx\positives\vit_elf.bin` as `Virus:Linux/Vit.4096`** (threat ID 2147577113). `Get-MpThreatDetection` holds two records: 2026-10-21T08:35:33Z with ThreatStatusID 102 and ActionSuccess False, and 08:36:02Z with ThreatStatusID 1 and ActionSuccess True. Access to the file was blocked. The file was deleted afterwards, and the entries remain in Windows Security history (see Q2) |

## Provenance and machine

| Fact | Value |
| --- | --- |
| `yr.exe` | from `yara-x-v1.22.0-x86_64-pc-windows-msvc.zip`. Archive sha256 `eac36a58699b94d3732a7fe1d8453fe89e0077bb18ac2c99b4c2ee102a431f2e` (matches the GitHub digest; `build/fetch-yara.ps1 -Engine YaraX -SkipDownload` printed "zip verified … matches pin" and refused to install, exit 3, empty pin). Only member: `yr.exe`, 26,424,320 bytes, sha256 **`e2e431175174158fc74c8709896c6d4a6667592bbb65a8132dea624ba125d76f`**, re-hashed after extraction to `C:\Temp\sg-yrx\bin\` and before the first run. `yr --version`: `yara-x-cli 1.22.0` |
| Linux `yr` | from `yara-x-v1.22.0-x86_64-unknown-linux-gnu.tar.gz`. Archive sha256 `7f470770b2c1a0d97f02298fc194978d999074d147d003d33dd62775761439db` (matches; the fetch script verified it the same way). Only member: `yr`, mode 0755, 31,923,480 bytes, sha256 **`73656c1f7b48326ddad393166a3ed14479412246bd3fe804abe6bf8ff1e6b43f`**, re-hashed in `~/sg-yrx/bin/` before the first run |
| Extraction | Python `zipfile`/`tarfile`. Only the expected member, written to a name the script chose. Nothing was installed into `artifacts/tools/`, and the pins in `build/fetch-yara.ps1` were not filled in |
| Authenticode | `Get-AuthenticodeSignature`: `NotSigned`. PE security directory size 0. FileVersion/ProductName/CompanyName empty |
| ELF | `ldd`: "statically linked". No `GLIBC_x.y` version strings in the binary. Runs on WSL2 Ubuntu 22.04.5 LTS, kernel 6.18.54.1-microsoft-standard-WSL2, glibc 2.35 |
| Licence | Neither archive contains a COPYING/LICENSE file. YARA-X is BSD-3-Clause per its source tree |
| Config | `yr` reads `${HOME}/.yara-x.toml` by default (`-C/--config`). None existed on Windows or WSL |
| Classic baselines | libyara.NET `Microsoft.O365.Security.Native.libyara.NET.Core` 4.5.5 (assembly `libyara.NET, Version=4.5.1.0`). WSL `/usr/bin/yara` and `yarac` 4.1.3 |
| Rules | `ext/reversinglabs-yara-rules` at `e0a0be54aa1e11ccfd6854e4f19e9476f328fd84`: 310 `.yara` files, and no custom rules (`Resources/YaraRules/Custom` holds only `.gitkeep`). The concatenated product framing comes from the probe's `--dump-rules`: 3,461,532 bytes, sha256 `94189a275ae70bdbafcf203bebc41ee844fb7687c3b96516229bd83b2178d8e8` |
| Code under test | `860c3f3` plus the uncommitted probe files (`Program.cs`, `IsolationCost.cs`). The probe exe was built 2026-10-21T00:34Z and **not rebuilt or modified**. The Linux CLI was built from a copy of that tree in WSL (`dotnet build -c Release -f net10.0`, 0 errors) |
| Machine | i5-10300H, 4C/8T; 63.8 GiB; Windows 10 Home 22H2 build 19045.7807; Balanced power plan; Defender RTP on (engine 1.1.26090.9, signatures 1.461.118.0); .NET SDK 10.0.101; WSL2 with 8 vCPU |
| Corpus | `C:\Temp\silvergun-corpus\`, 100 `.nupkg`, read-only, **no downloads**. Extracted top-level only (nested archives were not expanded) with Python `zipfile` on each side. The Windows and WSL manifests (path, size, sha256 per file) were **byte-identical**: 2,277 files, 339,334,305 bytes |

## Q1 — rule compatibility

Method: each of the 310 files went through `yr compile FILE -o X` alone, in default mode and with `--relaxed-re-syntax`.
On Linux each file also went through `yarac FILE X` (4.1.3). Then the whole set was compiled as the directory and as the
product's concatenated dump, with and without `--relaxed-re-syntax` / `--ignore-invalid-rules`. Rules were counted
with `yr scan -C -n <compiled> <empty file>` (classic: `yara -C -n`).

v1.22 compat flags (from `yr help scan` / `yr help compile`): `--relaxed-re-syntax`, `--ignore-invalid-rules`,
`-I/--ignore-module`, `-w/--disable-warnings`, `--path-as-namespace`. The ruleset contains **no regex strings**, and only
3 text strings, so the regex flag has nothing to act on. Everything else is hex patterns.

| | Windows `yr` | Linux `yr` | Linux `yarac` 4.1.3 | Windows libyara 4.5.5 in-process |
| --- | ---: | ---: | ---: | ---: |
| files compiling alone, default | **310/310** | **310/310** | 310/310 | 309/310 (Vit: no `elf` module) |
| files compiling alone, `--relaxed-re-syntax` | 310/310 | 310/310 | – | – |
| rules in the whole set | **1,240** | **1,240** | 1,240 | 1,239 |
| errors | 0 | 0 | 0 | 1 file |
| whole-set compile, directory / dump | rc 0 / rc 0 | rc 0 / rc 0 | rc 0 | – |

**Every diagnostic** (identical on both OSes, in both modes; all are warnings):

| File | Warning | Count |
| --- | --- | ---: |
| `certificate/blocklist.yara` | `deprecated_field`: field `number_of_signatures` is deprecated | 931 |
| `exploit/Win32.Exploit.CVE20200601.yara` | `deprecated_field`: `number_of_signatures` | 1 |
| `ransomware/Win32.Ransomware.GandCrab.yara` | `duplicate_pattern_value` | 7 |
| `ransomware/Win32.Ransomware.CryptoLocker.yara` | `duplicate_pattern_value` | 1 |
| concatenated dump only | `duplicate_import`: duplicate import statement (`import "pe"` repeated across files) | 15 |

Classic `yarac` printed no diagnostics for any file.

## Q2 — detection parity

**Synthetic positives.** These are inert byte patterns, never executed. They were built by
`scratchpad/yrx/make_positives.py`, which renders each hex string **from the rule text at run time**: `??` becomes 00,
a nibble `?` becomes 0, a jump becomes 00 filler, and an alternation takes its first or last branch. Each pattern is
placed where the rule's condition looks, inside a minimal non-runnable PE32 or ELF32 container. The certificate sample
is that minimal PE with an Authenticode signature (`Set-AuthenticodeSignature`, SHA-256). The signing certificate is
self-signed and throwaway, with subject `CN=AND LLC` and serial `77:01:9a:08:23:85:e4:b7:3f:56:95:69:c9:f8:7b:b8`. Both
values were parsed from the rule text of `cert_blocklist_77019a082385e4b73f569569c9f87bb8`. Signature status is
`UnknownError` (untrusted root). No certificate store was touched. Every sample's sha256 was identical on Windows and
WSL (TSV `Q2pos`).

| Sample | Rule it targets | Windows: `yr` src / `yr` compiled / libyara in-proc | Linux: `yr` src / `yr` compiled / `yara` 4.1.3 | Linux `scan-package` (YaraCliScanner) |
| --- | --- | --- | --- | --- |
| `hermeticwiper.bin` (MZ + `$corrupt_physical_drive`, the test fixture's construction) | Win32_Trojan_HermeticWiper | hit / hit / hit | hit / hit / hit | hit |
| `elerad_pe.exe` (body at `pe.entry_point`) | Win32_Virus_Elerad | hit / hit / hit | hit / hit / hit | hit |
| `awfull_pe_min.exe` (shortest jumps, first alternatives) | Win32_Virus_Awfull | hit / hit / hit | hit / hit / hit | hit |
| `awfull_pe_max.exe` (longest jumps `[0-256]`, last alternatives) | Win32_Virus_Awfull | hit / hit / hit | hit / hit / hit | hit |
| `archiveus_pe.exe` (EP string + 2 hex + `wide` text) | Win32_Ransomware_Archiveus | hit / hit / hit | hit / hit / hit | hit |
| `domaiq.bin` (text + hex) | Win32_PUA_Domaiq | hit / hit / hit | hit / hit / hit | hit |
| `cert_blocklist_signed.exe` (`pe.signatures[i].subject/serial/not_after`) | cert_blocklist_77019a08… | hit / hit / **hit** | hit / hit / hit | hit |
| `vit_elf.bin` (`elf.entry_point` + text) | Linux_Virus_Vit | **not run (Defender)** | hit / hit / hit | hit |
| `elerad_pe_offby1_negative.exe` (body 1 byte past EP) | none | – / – / – | – / – / – | – |
| `cert_blocklist_unsigned.exe`, `empty_negative.bin`, `mz_only_negative.bin`, `manifest.json` | none | – / – / – | – / – / – | – |

- No sample hit any rule other than its target, in any engine.
- On Windows, Defender blocked opening `vit_elf.bin` (`os error 225`, "contains a virus"). `yr.exe` reported this as
  an `error: scanning …` line and exited 0. The detection was **Virus:Linux/Vit.4096**. The file was deleted, and the Vit
  sample was then generated only on the WSL-native filesystem.
- libyara 4.5.5 in-process cannot compile this rule in any case: it is the one file pass 1 drops.

**Benign corpus.** The ruleset was compiled together with a match-everything rule `SpikeCoverageAll` (namespace `cov`
for `yr`; for `yarac` 4.1.3 the default namespace, because it rejects `ns:file`). Every scanned file must therefore
appear in the output. Real hits are any other rule.

| Engine | Files covered | Files with real hits | stderr errors | rc | wall |
| --- | ---: | ---: | ---: | ---: | ---: |
| Windows `yr.exe -C -r`, default threads, one process | **2,277/2,277** | **0** | 0 | 0 | 1.32 s |
| Windows libyara 4.5.5 in-process (probe `--worker`, 309 files) | 2,277/2,277 | **0** | 0 | 0 | 6.12 s incl. build |
| Linux `yr -C -r`, default threads | **2,277/2,277** | **0** | 0 | 0 | 1.25 s |
| Linux `yara -C -r -s -g -N --timeout=30` | 2,277/2,277 | **0** | 0 | 0 | 1.06 s |
| Linux `scan-package` ×100, through YaraCliScanner (`yarac:310`) | YARA status `Completed` 100/100 | **0 findings** | – | CLI exit 3 (the existing IL-completeness gate, not YARA) | 260 s for 101 packages |

`yr` without the coverage rule printed 0 NDJSON lines on both OSes.

## Q3 — output and failure semantics

**NDJSON schema** (`--output-format ndjson`; one line per **matching** file only):

```
{"path": str, "rules": [{"identifier": str,
                         "namespace": str,             // with -e
                         "meta": [[str, str|int|bool]],// with -m; an array of [key, value] pairs
                         "tags": [str],                // with -g
                         "strings": [{"identifier": str, "offset": int, "match": str}]  // with -s; match is escaped text, e.g. "M\\x00"
                        }]}
-c/--count:   {"path": str, "count": int}            // only files with count > 0
-n/--negate:  {"path": str, "rules": [...]}          // non-matching rules
--output-format json: {"version": "1.22.0", "matches": [{"rule", "file", "meta": {k: v}, "tags", "strings"}]} // printed once at the end
```

- **Files with no match produce no line** in any format, including with `-c`. The only way to observe coverage is a
  match-everything rule. **`all` is a reserved keyword** in both YARA dialects: `rule all { condition: true }` fails
  with `E001 expecting identifier, found 'all'`.
- `path` echoes the target argument as given (relative or absolute), with the OS separator.
- Errors and warnings never appear in the NDJSON stream. They go to stderr as rustc-style text
  (`error[E009]: …`, `--> file:line:col`, `warning[code]: …`). `-w` silences warnings.

**Per-file errors and exit codes** (identical on both OSes unless noted; TSV `Q3errors`, `Q3exit`):

| Situation | stdout | stderr | exit |
| --- | --- | --- | ---: |
| unreadable file (Linux mode 000 / Windows exclusive share lock / Defender block) | no record | `error: scanning "<path>": can not open …: Permission denied (os error 13)` / `(os error 32)` / `(os error 225)` | **0** |
| unreadable directory inside the tree (Linux mode 000 / Windows deny-RX ACL) | no record for its files | `error: IO error for operation on <dir>: … (os error 13 / 5)` | **0** |
| file larger than `-z/--skip-larger` | no record | **nothing** | **0** |
| file still in flight at the `--timeout` deadline | no record (no partial matches) | `error: scanning "<path>": timeout` | 0 |
| file still queued at the `--timeout` deadline | no record | **nothing** | 0 |
| the scan target does not exist | nothing | `error: can't open …: (os error 2)` | **0** |
| the rules file does not exist | nothing | `error: can't open …` | 1 |
| rule compile error | nothing | `error[E009] …` + `error: 1 error(s) found` | 1 |
| compile error with `--ignore-invalid-rules` | (scan proceeds) | the `error[E009]` diagnostic | 0 |
| unknown flag | nothing | clap usage | 2 |
| non-Unicode file name (NDJSON) | records lost | `thread '<unnamed>' panicked at cli/src/commands/scan.rs:927:43: called Option::unwrap() on a None value` | 1 |
| shutdown race after a `--timeout` | records lost | `panicked at cli/src/commands/scan.rs:960:46: … SendError(..)` | 1 |

`--recursive` defaults to 0: without `-r`, a directory target scans only its top-level files.

**Timeouts: the shape that broke classic `yara -r`.**
- **Tree:** 48 identical slow files plus `zz_payload.bin`.
- **Rules:** `match_all` (`condition: true`) plus `slow_quadratic`, a nested `for any i/j in (0..filesize-1)` loop.
  `yr` compiles it with a `potentially_slow_loop` warning.
- **Calibration:** each file takes ~0.65–0.9 s alone at `-p 1`. That is 6,368 bytes on Windows `yr`, 6,065 bytes on
  Linux `yr`, and 3,706 bytes for classic.
- **Classification:** "covered" = has a `match_all` record; "error-named" = named on stderr; **"silent" = neither**.

| Engine / OS | Threads, `--timeout` | Runs | Covered (of 49) | Error-named | **Silent** | Payload covered | rc | Wall |
| --- | --- | ---: | ---: | ---: | ---: | --- | --- | ---: |
| `yr` Windows | `-p 1`, 1 s | 3 | 1, 1, 1 | 1, 1, 1 | **47, 47, 47** | no | 0 | 1.02–1.03 s |
| `yr` Windows | `-p 4`, 1 s | 3 | 0, 0, 0 | 4, 4, 4 | **45, 45, 45** | no | 0 | 1.02–1.03 s |
| `yr` Windows | default, 1 s | 3 | 0, 0, 0 | 6, 4, 6 | **43, 45, 43** | no | 0 | 1.05–1.11 s |
| `yr` Windows | default, 3 s | 3 | 8, 8, 3 | 4, 2, 1 | **37, 39, 45** | no | 0, 0, **1 (panic)** | 2.15–3.10 s |
| `yr` Linux | `-p 1`, 1 s | 3 | 1, 1, 1 | 1, 1, 1 | **47, 47, 47** | no | 0 | 1.01 s |
| `yr` Linux | `-p 4`, 1 s | 3 | 4, 3, 0 | 3, 4, 4 | **42, 42, 45** | no | 0 | 1.01 s |
| `yr` Linux | default, 1 s | 3 | 0, 0, 0 | 7, 2, 2 | **42, 47, 47** | no | 0 | 1.02 s |
| `yr` Linux | default, 3 s | 3 | 8, 8, 8 | 7, 4, 1 | **34, 37, 40** | no | 0 | 3.01–3.03 s |
| classic `yara` 4.1.3 Linux | `-p 1`, 1 s | 3 | 2, 1, 1 | 0, 0, 0 | **47, 48, 48** | no | 0 | 0.78–1.66 s |
| classic `yara` 4.1.3 Linux | `-p 4`, 1 s | 3 | 0, 0, 0 | 4, 4, 4 | **45, 45, 45** | no | 0 | 1.01 s |
| classic `yara` 4.1.3 Linux | default (32), 1 s / 3 s | 3 + 3 | 1 | 32 | **16** | yes | 0 | 1.09–3.19 s |

- Without `--timeout`, the same tree completes with all 49 records (Windows 14.1 s, Linux 11.7 s).
- **`--timeout` is global**: wall time tracks the timeout, not files × per-file time.
- **Panic frequency** (separate run; default threads; 20 trials per cell):

  | | `--timeout 1` | `--timeout 3` |
  | --- | --- | --- |
  | Windows | 0/20 panics, 0 lines every time | **11/20** panics, with 1–4 records emitted vs 8 in the 9 clean runs |
  | Linux | 0/20 | **1/20** (1 record vs 8) |

  Every panic was at `scan.rs:960:46` with exit 1.

**Symlinks and junctions.**
- **Linux:** tested a symlink to a file outside the tree, one to a directory outside, a dangling one, and a loop to the
  parent. `yr scan -r` (and `-r=2`) reported only the one regular file. None of the four links produced a record or a
  stderr line, and the loop did not hang (13 ms).
- **Windows:** two directory junctions (one outside, one a loop) behaved the same way: not traversed and not mentioned.
  Creating symlinks on Windows failed with `WinError 1314` (privilege not held), so Windows symlinks are untested.
- **No follow or no-follow option** exists in `yr scan`.
- When the **target argument itself** is a symlink (file or directory), it **is** followed, and the record carries
  the link's path.

**Hostile file names** (TSV `Q3names`; names were written only as escapes).

| Name (OS) | NDJSON | Round-trips to the real path | `json` | text |
| --- | --- | --- | --- | --- |
| LF, CR, TAB, ESC `\x1b[31m`, U+202E, `"`, `\`, LF in a directory name (Linux) | rc 0, escaped (`\n`, `\u001b`, `\u202e` …) | **yes** | escaped | **raw**: LF splits the line and ESC reaches the terminal |
| U+202E, U+200B, U+1F600, `'` `;` `&` `%` (Windows) | rc 0 | **yes** | ok | ok |
| LF / TAB / ESC (Windows) | not creatable (`Errno 22`) | – | – | – |
| **invalid UTF-8 `\xff\xfe`, or a CESU surrogate `\xed\xa0\x80` (Linux); lone surrogate U+D800/U+DC00 in a file or directory name (Windows)** | **panic, rc 1** | – | rc 0, `"file": ""` | rc 0, U+FFFD |
| the same bad name plus 40 normal files in one directory (NDJSON) | **0 of 41** records (Windows and Linux, file case); 1/41 (Linux CESU); 13/41 and 15/41 (bad *directory* name, Windows / Linux) | – | – | – |

`--scan-list` reads paths one per line. A path containing LF is split into two (`can't open …` ×2), and invalid UTF-8
in the list stops reading (`stream did not contain valid UTF-8`). Both cases exit 0.

## Q4 — performance

Setup:
- **Trees:** the same 20 as `yara-process-isolation-cost-2026-10-20.md` (826 files, 186,064,929 bytes, counts
  re-checked). Windows read them from `C:\Temp\sg-yrx\corpus\<pkg>`; Linux read WSL-native copies.
- **Invocation:** one `yr scan -C -r --output-format ndjson <compiled> <tree>` process per tree.
- **Runs:** 10 iterations with an alternating mode order, after one warm-up of everything.
- **Interleaving:** the baseline was interleaved in the same iterations. On Windows that was one `--inproc-host` process
  (one round over the 20 trees) per iteration; on Linux, classic `yara -C` per tree.
- **Memory:** peak = the child's peak working set (Windows, `GetProcessMemoryInfo`) or `ru_maxrss` (Linux).
- **Results:** every scan returned 0 hits and rc 0.

| Total for the 20 trees (ms) | N | Windows median | p90 | min–max | Linux median | p90 | min–max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **`yr` compiled, default threads** | 10 | **5,552** | 6,557 | 5,176–8,112 | **5,497** | 6,673 | 4,707–7,522 |
| `yr` compiled, `-p 1` | 10 | 7,644 | 8,421 | 6,861–9,021 | 6,464 | 9,304 | 6,062–9,474 |
| `yr` **source** rules (recompiles every process) | 3 | 35,650 | 41,243 | 32,132–41,243 | 26,597 | 27,814 | 25,803–27,814 |
| **baseline, Windows:** libyara 4.5.5 in-process, scan only (sum of per-tree ms reported by the host) | 10 | **3,436** | 3,501 | 3,195–3,524 | | | |
| baseline, Windows: in-process host, whole process (start, 0.56 s engine build, 20 trees, exit) | 10 | 4,230 | 4,325 | 3,945–4,437 | | | |
| **baseline, Linux:** classic `yara -C -r -s -g -N --timeout=30` per tree | 10 | | | | **1,923** | 2,645 | 1,809–2,682 |

| Single invocation | Windows median (N) | Linux median (N) |
| --- | ---: | ---: |
| `yr --version` | 23.7 ms (15), 6.6 MiB | 2.0 ms (15), 11.9 MiB |
| `yr compile` of the 310-file dump (2,356,808-byte `.yarc`) | **1,552 ms** (7), p90 1,790, peak 150 MiB | **1,909 ms** (7), p90 2,279, peak 186 MiB |
| `yr scan -C` empty file, **full** compiled set (`Q4floor`) | 174 ms (15) | 183 ms (15) |
| `yr scan -C` empty file, one-rule compiled set | 24 ms (15) | 11 ms (15) |
| smallest tree (xunit, 7 files), `yr` compiled | 203 ms (10), 41 MiB | 252 ms (10), 47 MiB |
| largest tree by files (ApiDescription.Server, 253 files), `yr` compiled / `-p 1` | 527 / 1,165 ms, 43 MiB | 461 / 1,015 ms, 54 MiB |
| the same tree, baseline | libyara in-proc 1,126 ms | classic `yara -C` 359 ms, 22 MiB |
| peak memory per tree, `yr` compiled (range of medians) | 41–63 MiB | 47–74 MiB |
| peak memory per tree, classic `yara -C` | – | 14–36 MiB |
| peak memory, in-process host (whole run) | 65.4–66.0 MiB | – |

Per-tree medians for every mode are in the TSV (`Q4.win.*`, `Q4.linux.*`).

Comparison with the isolation measurement:
- **M2 (a)** (in-process, 3.77 s interleaved, 4.5 s in the main run): today's interleaved in-process total is **3.44 s**.
- **M5d** (`yara -C` per package, 1.34 s): today's **1.92 s**, measured in the same iterations as `yr`. That
  measurement already noted run-to-run drift, so compare within a run.
- On both OSes, `yr` per package costs about **2.9× classic `yara -C` (Linux)** and **1.6× the in-process scan
  (Windows)**. Each `yr` process pays ~150–170 ms to load the compiled 1,240-rule set: 20 × (174 − 24) ≈ 3.0 s on Windows and
  20 × (183 − 11) ≈ 3.4 s on Linux, of the ~5.5 s for 20 trees. One `yr` process over the whole 100-package corpus (2,277 files) took 1.25–1.32 s with default threads
  (Q2).

## What this means (facts, no recommendation)

- **Rule compatibility and detection:** the embedded RL ruleset compiles unchanged under `yr` 1.22 on both OSes, with
  the same 1,240 rules as classic. That includes the ELF rule the Windows in-process build lacks. Verdicts matched
  classic on every synthetic positive and negative, including the `pe.signatures` blocklist and the `elf` rule. The
  100-package benign corpus gave 0 hits in every engine.
- **Failure semantics:** `yr`'s exit code does not distinguish a complete scan from a partial one. Unreadable files,
  unreadable directories and a missing target all exit 0, reported only as free text on stderr. `--skip-larger` and
  the files dropped at a `--timeout` deadline leave no trace at all. Symlinks and junctions under a recursive target
  are also skipped without a trace. A file with no match produces no output line, so coverage is only observable
  through a match-everything rule (named something other than `all`), as with the ADR-0032 sentinel.
- **Hostile input:**
  - A single non-Unicode file name in the tree makes `yr`'s NDJSON writer panic. That is invalid UTF-8 on Linux, or a
    lone surrogate on Windows, both legal names on their file systems. Records for other files in the same process
    are lost, with exit 1.
  - Hitting the `--timeout` deadline can also panic and lose already-produced records (Windows 11/20, Linux 1/20).
  - Valid-Unicode control and bidi characters are escaped faithfully and round-trip.
- **Cost:** one `yr` process per package costs ~5.5 s for these 20 packages on both OSes, against 3.4 s for the
  current Windows in-process scan and 1.9 s for Linux `yara -C`. ~150–170 ms of every invocation is loading the
  compiled ruleset. `yr compile` takes ~1.6–1.9 s, about 5–6× `yarac`.
- **Provenance:** `yr.exe` carries no Authenticode signature, so its integrity rests on the GitHub asset digest and
  the recorded member hash. The Linux binary is static and runs on the dev WSL.
- **Environment:** Defender on the dev machine flags at least one inert byte pattern derived from an RL rule (Vit).
  On Windows that turns into a per-file "virus" open error, which `yr` reports on stderr with exit 0.

## Not done / gaps

- **Windows symlinks:** not created (no privilege). Junctions were tested.
- **Files > 4 GiB, or mmap/truncation (`--no-mmap`):** not tested.
- **Stock classic `yara.exe` on Windows:** not run (not approved). The Windows baseline is libyara.NET in-process.
- **Windows `scan-package` CLI baseline:** not run, because the probe's in-process engine stands in for it. The Vit
  positive was not run on Windows at all (Defender).
- **A reboot-cold first run of `yr.exe` under Defender:** not measured. Every `yr` timing excludes one warm-up.
- **Rule count for in-process 4.5.5:** inferred. 1,239 = 1,240 minus the single rule in the dropped Vit file; it was
  not counted directly.

## Method notes and cleanup

- **Harness:** all in `scratchpad/yrx/` (Python under `-I`, and PowerShell 5.1 via `-File`). No repository code was
  changed: the probe was used as built.
- **Processes:** every child was started by these scripts, waited on, and bounded by a watchdog that killed only that
  child.
- **Scratch:** `C:\Temp\sg-yrx\` (binaries, corpus extraction, samples) and WSL `~/sg-yrx/` (binary,
  corpus copy, repo copy, samples) were deleted at the end (see the hand-off report).
- **Spec deviation:** the spec's `rule all { condition: true }` coverage rule cannot compile (reserved word), so it was
  named `match_all` / `SpikeCoverageAll`.
