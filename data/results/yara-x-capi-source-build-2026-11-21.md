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

## CI build (`.github/workflows/yara-x-capi.yml`)
Run https://github.com/allisterb/Silvergun/actions/runs/45035746101 (2026-11-22, Silvergun 89614cb0, both jobs
succeeded, all checks passed). Artifacts expire 2027-02-20.

| Artifact | zip bytes | zip sha256 (GitHub digest) |
| --- | --- | --- |
| `yara-x-capi-v1.22.0-x86_64-pc-windows-msvc` | 9,409,746 | `ed0ebbc347bcd7e660b7591aaf0345128291f7e605335ab34cd602b8a68c5280` |
| `yara-x-capi-v1.22.0-x86_64-unknown-linux-gnu` | 8,506,355 | `8e20bdea14b61350351c883df194f9f35ad6a9c0d139dec1a2061ce01e2d3573` |

Linux artifact, downloaded by the user and re-checked locally on 2026-11-24 (zip digest matches; SHA256SUMS matches
every file; `check-yara-x-capi.py` passes in WSL; header byte-identical to the local build's; max GLIBC_2.34; same
NEEDED). Runner ubuntu-22.04 image 20261116.365.1, rustc 1.98.1.
- `libyara_x_capi.so`: 28,570,544 bytes, sha256 `8bd73385e237648348d7eaf9bd4a837f4383d2621524a52c12610e2455507977`
  (768 bytes smaller than the local WSL build: not reproducible across machines, as expected)
- `yara_x.h`: sha256 `116e01b76aa14b7f53f9e3e6ccf26a3568237de0823228abb519ba9772705e7e`

Windows artifact, downloaded by the user and re-checked locally on 2026-11-24 (zip digest matches; SHA256SUMS matches
every file; `check-yara-x-capi.py` passes: 55 exports, imports within the allowlist, so no MSVC runtime; header
byte-identical to the Linux artifact's). Runner windows-2022 image 20261116.370.1, rustc 1.98.1, `+crt-static`.
- `yara_x_capi.dll`: 22,245,888 bytes, sha256 `74943f71327cbdd29b467343ae358eb455a3466916840de2bedcba00fa12c82b`
- `yara_x_capi.dll.lib`: sha256 `d3c59133c930822bfd9652bc55bf0dea6009a6dc30dc2e097d62f6fb66904fba`
- `yara_x_capi.pdb`: sha256 `1bf989a8444ba0fdb733a42ac1bc96f7bedfae43543d33d7a29442e366535e79`
- `yara_x.h`: sha256 `116e01b76aa14b7f53f9e3e6ccf26a3568237de0823228abb519ba9772705e7e` (same as Linux)
- `LICENSE` is 1,534 bytes vs 1,509 on Linux: CRLF line endings from the Windows runner's checkout, same text.

Behaviour: with the CI DLL swapped into the test output directory, `Silvergun.PackageAnalysis.NuGet.Tests`
(net10.0-windows, filter `Yara`) gave **1,211 passed, 0 failed, 73 skipped**, identical to the published and local
DLLs; DLL sha256 checked after the run, then the published DLL (`bb5c112b`) restored.

## Release and switch (2026-11-24)
The user published both zips unchanged as release `yara-x-capi-v1.22.0` of allisterb/Silvergun (tag on 89614cb0,
pre-release); the release asset sizes and digests equal the CI artifacts'. `build/fetch-yara.ps1 -Engine YaraXCapi`
now installs from it (win-x64 and linux-x64), pinned to the hashes above; the csproj copies the installed DLL as before.
After the switch, the NuGet tests (net10.0-windows, filter `Yara`) built with the new DLL in their output: 1,211 passed,
0 failed, 73 skipped; the CLI output carries the same DLL (`74943f71`).

## Not done
Linux worker port (ADR 0033 decision 5). fetch-yara.ps1 runs only on Windows, so a Linux build host gets the `.so` from
a Windows checkout (e.g. WSL `/mnt/c`) or by copying `artifacts/tools/yara-x-capi/linux-x64/`.
