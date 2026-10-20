# tests/scripts

## wsl-test.ps1 - persistent WSL test mirror

Runs a test project inside WSL from one persistent mirror, `~/silvergun-wsl`, which is rebuilt
incrementally. Spec: `docs/agent/tasks/wsl-test-mirror.md`. When to use it: `docs/agent/testing-tiers.md`.

```
powershell -NoProfile -ExecutionPolicy Bypass -File tests\scripts\wsl-test.ps1 -Project <repo-relative csproj> [-Framework net10.0] [-Filter <xunit filter>] [-NoSync]
powershell -NoProfile -ExecutionPolicy Bypass -File tests\scripts\wsl-test.ps1 -SelfTest
```

What it does:

1. **Sync:** `rsync -a --delete` copies the repo root (as seen from WSL, `/mnt/c/Projects/Silvergun/`) to
   `~/silvergun-wsl/`. It excludes `.git`, `bin/`, `obj/`, `.vs/`, `TestResults/`, `/reference/`,
   `/docs/agent/` and `scratch*`. There is no `--delete-excluded`, so the mirror's Linux `bin/` and `obj/`
   persist and the next build is incremental.
2. **Test:** runs `dotnet test ~/silvergun-wsl/<Project> -f <Framework> [--filter <Filter>]` in WSL, streams
   the output and exits with the `dotnet test` exit code.
3. Prints the elapsed time for each step: preflight, sync, test, and total.

Exit codes:

| Code | Meaning |
| --- | --- |
| `dotnet test` exit code | The test step ran. |
| 2 | An argument or the safety guard was refused. Nothing was synced. |
| 3 | rsync failed. No tests were run. |
| 4 | Timed out after 20 min waiting for another run of the script. Runs are serialized by a mutex. |

Safety, because the script runs `rsync --delete`:

- The destination is computed from `$HOME` in WSL and must be exactly `/home/<user>/silvergun-wsl`.
  `Get-MirrorDestinationError` refuses an empty value, `/`, `..`, `//`, trailing slashes and whitespace,
  another user's home, and anything else.
- After that check, `realpath -m` in WSL must return the destination unchanged, so no symlink can redirect it.
- The source must be the repo root. That means `src/Silvergun.sln` must exist on the Windows side and also
  be visible from WSL.
- `-SelfTest` exercises those guards with fake values and never calls WSL or rsync.

Notes:

- Windows PowerShell 5.1 can't pass embedded double quotes or empty strings to a native command intact,
  so `-Filter` refuses double quotes. `&`, `|`, `!`, `~`, parentheses and spaces arrive intact, because
  `wsl.exe -e` runs `dotnet` directly with no shell.
- `ext/*/.git` (the submodule gitlink files) are excluded. The build doesn't need them: the YARA rules are
  embedded straight from `ext/reversinglabs-yara-rules/yara/**`, and analysis-net builds from its sources.
- If a project directory is deleted on Windows, its mirror copy keeps its (excluded, so protected) `bin/` and
  `obj/`, and rsync warns that it cannot delete a non-empty directory. This is harmless. To start clean,
  delete `~/silvergun-wsl` by hand.
- Never build at `/mnt/c/...` from WSL. The mirror's `bin/` and `obj/` never touch the Windows ones, so
  this is safe to run alongside a Windows `dotnet test`.
