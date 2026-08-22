---
name: linux-only-defects
description: Two real defects in path/OS-sensitive code were invisible to Windows-only testing and only appeared when run in WSL — treat a Linux run as mandatory for anything touching paths, filenames or process output parsing
metadata:
  type: project
---

**Anything that parses paths, filenames, or subprocess output must be exercised on Linux before it is
believed. Windows cannot represent the inputs that break it.**

**Why:** two for two, both attacker-relevant, both green on Windows forever:
1. `YaraCliScanner.Normalize` folded `\` → `/` unconditionally — correct on Windows, **wrong on Linux**
   where `\` is a legal filename character, causing a false negative. Found by the first WSL suite run.
2. **ADR-0029 (2026-08-22):** a **newline in a zip entry name** splits `yara -r`'s echoed-path output
   across two lines, so the hit is dropped while the scan still reports `Completed` — an
   attacker-controlled false negative in the backend that ships to Linux CI. NTFS cannot hold such a
   name, so no Windows test could ever have found it.

**How to apply:**
- When a change touches path handling, filename handling, separators, casing, or parsing the stdout of
  a child process, **run the suite in WSL** (`wsl -e bash -lc 'cd /mnt/c/Projects/Silvergun && dotnet test <proj> -f net10.0'`)
  and say so in the acceptance criteria. A Windows-green result on that class of change is not evidence.
- Regression tests for these live in a strange place: they can only *run* on Linux. A Windows CI run
  reports green on a test that never executed — state that explicitly rather than assuming coverage.
- The general shape: **the hostile input is the filename**, not the file contents. When reviewing a
  parser, ask what happens if a path contains the parser's own delimiter.
- WSL cannot read `%LOCALAPPDATA%\Silvergun` on this machine (`AppData` lists, `Local/Silvergun` does
  not resolve). Stage corpora to `C:\Temp\...` (outside the repo) and read them via `/mnt/c/Temp/...`.

Related: [[hostile-input-threat-model]], [[test-the-shipping-configuration]], [[inert-guard-defect-class]]
