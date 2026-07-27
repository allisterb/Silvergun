---
name: subagent-stray-memory
description: Subagents sometimes write their agent-memory into a git SUBMODULE (ext/analysis-net/cci) instead of the repo root — check and relocate after every ext/ task
metadata:
  type: feedback
---

**After any task that touches `ext/`, check for a stray `.claude/` directory inside the
submodules and relocate it.** Fastest check:

```
cd ext/analysis-net/cci && git status --porcelain
cd ext/analysis-net && git status --porcelain
```

An untracked `?? .claude/` there is the tell.

**Why it matters:** `ext/analysis-net` and its nested `cci` are **git submodules — our forks
of upstream**. Agent memory written there is *not* ignored (verified: `git status
--porcelain --ignored` reports `??`, not `!!`), so it becomes untracked cruft in the fork
and complicates the asnarnd merges we intend to keep doing. It also makes the submodule read
as "modified" when the actual code change is clean, which wastes review time — a reviewer
already had to explain that a submodule's modified status "is just an untracked `.claude/`
dir".

**Observed twice on 2026-07-26/27**, both times from `code-reviewer` after an `ext/` review.
Expect it again.

**How to fix:** move the memory *files* to the correct root location
(`.claude/agent-memory/<agent>/`) and append their index lines to that agent's `MEMORY.md` —
don't just delete them, the content is usually worth keeping. The now-empty directories can
be left: git does not track empty dirs, so `git status` goes clean once the files are out.
`rmdir` may fail with "Device or resource busy" (a live process handle) — harmless, ignore
it. `rm -rf` is denied by policy; don't try to route around it.
