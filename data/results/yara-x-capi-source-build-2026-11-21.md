# YARA-X C API built from source, Windows x64 (2026-11-21)

Source: `ext/yara-x` submodule (upstream https://github.com/VirusTotal/yara-x), tag **v1.22.0** = commit
`e27597f2c05e13fe1c2bb459781aef8899afc485` (lightweight tag; the commit is signed by its author, signature not verified
locally: no key). Chosen to match the prebuilt v1.22.0 C API Silvergun ships today (`build/fetch-yara.ps1 -Engine
YaraXCapi`), so the two can be compared. v1.22.1 (regex-compiler panic fixes, wasmtime 48.0.7) and v1.24.0 exist.

Codepoint scan of the checkout (CLAUDE.md): 1,968 text files; no bidi controls, Unicode Tag characters or zero-width
characters. 9 benign format characters (U+0600/U+0601 in a .NET module test-data expected output; one emoji variation
selector in a blog post). Windows Defender quarantined one upstream test-data file on read,
`lib/src/modules/vba/tests/testdata/7c1bfa4a…eef73.out` (`Trojan:VBS/Redirector.ZRF!AMTB`, not executed) — the VBA
macro text of a malicious sample, used only by upstream's VBA module tests; not needed by the build. Since then the
submodule is checked out by `build/init-yara-x.ps1` with all 1,569 `testdata/` files (19 directories) excluded:
every reference to them is in `#[cfg(test)]` modules, `tests/` or `benches/`.

## Build
Mirrors upstream `release.yaml` (Windows job: `cargo cbuild --profile release-lto`, `RUSTFLAGS=-C target-feature=+crt-static`,
default features) with plain cargo instead of cargo-c:

`cargo build -p yara-x-capi --profile release-lto --target x86_64-pc-windows-msvc --locked -j 6`
with `RUSTFLAGS=-C target-feature=+crt-static`, `CARGO_TARGET_DIR=artifacts/build/yara-x`.
Toolchain: rustc 1.98.1 (48a229cea 2026-09-01), cargo 1.98.1, stable-x86_64-pc-windows-msvc.
13.3 min, peak 5.25 GB (process-tree sampled, 16 GB kill limit).

## Comparison with the published v1.22.0 DLL

| | Published (`yara-x-capi-v1.22.0-x86_64-pc-windows-msvc.zip`) | Ours |
| --- | --- | --- |
| `yara_x_capi.dll` size | 23,207,424 | 22,243,840 |
| sha256 | `bb5c112bf479d1b1706fbecf85275d3806321ee2912dea4f36750289d0294848` | `9475034222f611db1fdf9aacb18be5056c0b1156a7a9397ac37387e301bb5865` |
| Exports (dumpbin) | 55 | 55, identical names |
| Imported DLLs | KERNEL32, api-ms-win-core-synch-l1-2-0, bcryptprimitives, ntdll | same |
| `yara_x.h` | — | identical except the three `YARA_X_MAJOR/MINOR/PATCH` defines cargo-c adds |

Not byte-identical (no reproducible-build guarantee; cargo vs cargo-c link settings), as expected.

## Behaviour with our DLL (swapped into the test and CLI output directories, then restored)
- `Silvergun.PackageAnalysis.NuGet.Tests`, net10.0-windows, filter `Yara`: **1,211 passed, 0 failed, 73 skipped**
  (DLL sha256 checked before and after the run: ours).
- `scan-package` on the bundle positive control (`yara-corpus-bundles-2026-11-20.md`): Completed, 1 finding,
  `Win32_Trojan_HermeticWiper` at `tools/App.exe!/payload.bin` — identical to the published DLL.

## Linux x64 (WSL2 Ubuntu 22.04.5, glibc 2.35, kernel 6.18.58.1-microsoft-standard-WSL2)
Toolchain: rustup, rustc 1.98.1 (48a229cea 2026-09-01), installed by the user. Same source and tag.
`cargo build -p yara-x-capi --profile release-lto --target x86_64-unknown-linux-gnu --locked -j 6` (no crt-static:
not applicable to a glibc cdylib), target dir `~/build/yara-x` in WSL, outputs copied to
`artifacts/build/yara-x/x86_64-unknown-linux-gnu/`. 8 min 53 s, peak RSS 5.5 GB.

| | |
| --- | --- |
| `libyara_x_capi.so` | 28,571,312 bytes, sha256 `a31a13ba3742be6533adb7d29acea69ca4428739d104b266ebff26b18d5a868b` |
| `libyara_x_capi.a` | 234,633,684 bytes |
| Exports | 55 `yrx_*`, the same 55 names as the Windows DLL (and no other defined functions) |
| NEEDED | libgcc_s.so.1, libm.so.6, libc.so.6, ld-linux-x86-64.so.2; no SONAME (plain cargo, not cargo-c) |
| Highest glibc symbol version | GLIBC_2.34 (so: Ubuntu 22.04+, Debian 12+, RHEL 9+) |
| `yara_x.h` | identical to the Windows-built header (ignoring line endings) |

No published Linux C API exists to compare against, and the YARA-X worker is `#if WINDOWS`, so this proves the library
builds with the right interface only; scanning with it comes with the Linux worker port.

Both builds regenerate `capi/include/yara_x.h`, `lib/src/modules/modules.rs` and `lib/src/modules/protos/generated/*.rs`
in the submodule with LF endings (content unchanged); they were restored with `git checkout` afterwards.

## Not done
CI workflow written (`.github/workflows/yara-x-capi.yml`, 2026-11-22), not yet run on GitHub. Switching fetch-yara.ps1 / the csproj to the source-built DLL. Linux worker port (ADR 0033 decision 5).
