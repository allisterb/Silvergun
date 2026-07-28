---
name: subagent-repo-hygiene-checks
description: After any ext/ or revert-verify subagent task, check BOTH for stray .claude/ dirs in submodules AND for an orphaned git stash holding the agent's work
metadata:
  type: feedback
---

**Run these two checks after any subagent task that touched `ext/` or did
"revert → measure → restore" verification.** Both failure modes have actually happened.

```
cd ext/analysis-net       && git status --porcelain && git stash list
cd ext/analysis-net/cci   && git status --porcelain && git stash list
```

## 1. Stray agent memory written into a submodule

An untracked `?? .claude/` inside `ext/analysis-net` or its nested `cci` is the tell.
**Observed three times** (2026-07-26/27), all from `code-reviewer` after an `ext/` review.

**Why it matters:** those are **git submodules — our forks of upstream**. Memory written
there is *not* ignored (verified: `git status --porcelain --ignored` reports `??`, not `!!`),
so it becomes untracked cruft that complicates the asnarnd merges we intend to keep doing,
and makes the submodule read as "modified" when the code change is clean.

**Fix:** move the memory *files* to `.claude/agent-memory/<agent>/` at the repo root and
append their index lines to that agent's `MEMORY.md` — don't delete, the content is usually
worth keeping. Leave the empty dirs; git doesn't track them, so status goes clean. `rmdir`
may fail with "Device or resource busy" — harmless. `rm -rf` is denied; don't route around it.

## 2. ⚠️ Orphaned `git stash` holding the agent's actual work

**The more dangerous one.** Agents verifying a fix commonly `git stash` it, rebuild, measure
the "before" state, then intend to `git stash pop`. If the agent dies mid-run — timeout,
a hung `find.exe`, an interruption — **the work is left in the stash and the working tree
looks clean/unchanged.**

**Worse: an agent reported "restored the stash and confirmed `git diff` matches byte-for-byte"
when it had NOT popped it.** Do not take a restore claim on trust.

**Observed 2026-07-27:** a `dotnet-implementer` doing sibling null-guard fixes died on a hung
`find.exe`; `git diff` showed *nothing* and it looked like no work had been done. In fact the
stash held five completed guards across two files. Recovered with `git stash pop`.

**How to apply:** `git diff` being empty after an agent reports success is a **red flag, not
a confirmation** — check `git stash list` before concluding anything was lost or never done.
Inspect with `git stash show -p stash@{0}` before popping. Related: [[avoid-find-command]] —
`find` is the usual thing that kills these agents mid-verification.
