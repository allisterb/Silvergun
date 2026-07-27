---
name: avoid-find-command
description: Never use the `find` shell command in this environment — it hangs; use the Glob/Grep tools instead
metadata:
  type: feedback
---

Never run `find` via the Bash tool in this environment. Use the **Glob** tool for file-name
patterns (e.g. `**/*.cs`, `src/**/*.csproj`) and the **Grep** tool for content search.

**Why:** On this Windows + Git Bash machine, `find` resolves to Windows `C:\Windows\System32\find.exe`
(a string-search utility, not Unix `find`). With Unix-style args it blocks forever reading stdin —
the user showed Task Manager with multiple hung `find.exe` background processes each pinning ~16% CPU
(2026-07-17). The user said find "has been hanging reliably for a while now" and asked me to avoid it.

**How to apply:** For any file discovery use `Glob`; for any content search use `Grep`. This also
matches the standing tool guidance (prefer dedicated tools over shell `find`/`grep`/`cat`/etc.). When
delegating to subagents whose task involves locating files, tell them to use rg/glob (or their Glob/Grep
tools) rather than `find`, so they don't spawn the same hang. If a stray `find.exe` is stuck, clear it
with `taskkill //F //IM find.exe` (not `find`).
