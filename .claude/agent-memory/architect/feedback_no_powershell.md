---
name: prefer-powershell-scripts
description: PowerShell is ALLOWED and preferred for non-trivial shell work on this machine (Bash is finicky) — the old deny rule was removed 2026-07-26; confirm invocation style
metadata:
  type: feedback
---

**Prefer PowerShell scripts over long/complex Bash on this machine.** Bash here is finicky
and has bitten us repeatedly; the user asked for this preference on 2026-07-26 and is
adding it to `CLAUDE.md`.

**⚠️ This REVERSES earlier guidance — do not act on the old rule.** Until 2026-07-26 there
was a project deny rule on PowerShell, and a `dotnet-implementer` subagent that invoked
`powershell.exe -NoProfile -Command` *through Bash* triggered a security-policy warning
(2026-07-17). **That deny rule has been removed** — verified directly in
`.claude/settings.json`, whose `deny` list now holds only `Bash(git push:*)`,
`Bash(rm -rf:*)`, and `Edit`/`Write` on `reference/**`.

**Why:** the user's judgement is that the Bash-only constraint was costing more than it
protected on a Windows machine where the shell is Git Bash over MSYS. Concrete Bash
failures observed in this project: `find` resolves to Windows `find.exe` and **hangs**;
chained `sleep` is blocked by the harness; MSYS mangles `/`-prefixed argv (needed a `.bat`
wrapper to call `ildasm`); heredocs and quoting around Windows paths are fragile.

**Residual caution worth keeping:** the 2026-07-17 incident was an *auto-mode classifier*
warning about routing around a deny rule via Bash — a different mechanism from the project
deny list. With the deny rule gone the intent objection disappears, but if a PowerShell
call is ever refused or flagged, **stop and ask** rather than trying to slip it through
another way. Prefer a `.ps1` script file over `powershell.exe -Command "<one-liner>"`.

**How to apply:** for multi-step file/process work, write a `.ps1` in a scratch dir and run
it, rather than an increasingly baroque Bash pipeline. Simple one-shot `git`/`dotnet`/`ls`
/`grep` calls are still fine in Bash. **Tell subagents PowerShell is available** — their
agent definitions and older specs may still say otherwise. Related:
[[avoid-find-command]], [[email-literal-redaction]].

**Also learned 2026-07-26:** never run two `dotnet test` invocations in parallel when their
projects share a referenced project's output — they collide on the same `obj/`/`bin/` DLL
and fail with `CS2012` (file in use). Run test suites sequentially.
