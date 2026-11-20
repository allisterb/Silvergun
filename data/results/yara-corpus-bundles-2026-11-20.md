# YARA over the four corpora, with unpacked single-file bundles (2026-11-20)

Commit under test: native-binaries-4 (YARA over unpacked bundle files), committed by the user 2026-11-19.
Backend: YARA-X worker (default `net10.0-windows`), embedded ruleset. Command per package (guarded, offline):
`scan-package <nupkg> --json --no-vulns --allow-incomplete --output <json>`. Packages from the local corpus cache
(`%LOCALAPPDATA%\Silvergun\benign-corpus\packages`, manifests in `data/corpus/`); nothing downloaded.

## Result

| Corpus | Packages | YaraScanStatus Completed | Packages with hits | Hits | Packages with unpacked bundle content |
| --- | ---: | ---: | ---: | ---: | ---: |
| C100 (benign-top) | 100 | 100 | 0 | 0 | 0 |
| C100+ (benign-top-ext) | 100 | 100 | 0 | 0 | 0 |
| C-build | 50 | 50 | 0 | 0 | 0 |
| C-suspect (benign-suspect) | 68 | 68 | 0 | 0 | 1 (Clowd.Squirrel 2.11.1) |

- 318/318 Completed, 0 Unavailable, 0 guard kills, every run exited 0.
- The YARA prevalence row stays **0** across all corpora, now including bundled content: Clowd.Squirrel's two bundles
  (`tools/Squirrel.exe`, 118 entries; `tools/Update.exe`, 83 entries) were unpacked and every extracted file was
  scanned in the second pass, with no hit.

## The zero is real: positive control (same binary, same backend)

A synthetic `.nupkg` (`Silvergun.Control.Bundle 1.0.0`) with one file, `tools/App.exe`: a minimal native PE32+ host,
the .NET bundle signature, and a v6 bundle holding one **deflated** entry `payload.bin`. The entry is inert: `MZ` plus
the `$corrupt_physical_drive` hex string of `Win32_Trojan_HermeticWiper` (ReversingLabs rules, embedded) with `??`
filled by `00` — the derivation `tests/.../HermeticWiperSample.cs` uses. The payload does not occur raw in the host,
so only the unpacked-file pass can see it. Result: `Completed`, **1 finding**, `Win32_Trojan_HermeticWiper` /
HERMETICWIPER / MALWARE at `tools/App.exe!/payload.bin`. Generator: a throwaway Python script (session scratchpad),
not kept in the repo.

## Not measured
- Per-package YARA cost of the second pass (one bundle package in the corpora; Clowd.Squirrel whole scan with YARA:
  38 s, 417 MB peak on 2026-11-19).
- Linux / classic `yara` CLI backend: not run (no yara binary on this machine).
