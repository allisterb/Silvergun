---
name: research-journal
description: Prior-art/technique research is logged in a running journal at docs/agent/research/RESEARCH-JOURNAL.md — append new projects there, keep it the index
metadata:
  type: project
---

The user asked (2026-07-16) for a **running research journal** of prior-art/technique findings.
It lives at `docs/agent/research/RESEARCH-JOURNAL.md` and is the canonical index + backlog;
detailed per-topic write-ups are sibling files in `docs/agent/research/`.

**Why:** research spans many projects (Capslock, GuardDog, OSSGadget so far, more to come) and
findings were at risk of getting buried across separate docs; the user wants one navigable log.

**How to apply:** whenever we survey a new tool/paper or extract a reusable technique, **append a
project entry to the journal** (what it is, key techniques with [V]/[K] confidence tags, a
reuse-for-Silvergun table with status tags, further-research notes) and update the consolidated
backlog — don't just write a standalone doc and leave the journal stale. Status tags in use:
Done/In-progress/Queued/Decision-needed/Proposed/Idea. Confidence tags: [V] verified from a fetched
source, [K] established-but-unverified.

Note: web research runs **in-thread via curl** (the `researcher` subagent can't register — its
env lacks WebSearch/WebFetch; see that doc's provenance notes).

**Resuming multi-session work:** check for `docs/agent/SESSION-HANDOFF.md` — the architect writes a
dated resume brief there (what shipped, queued next-up tasks with package needs, open decisions)
when the user checkpoints before clearing context. It's the fastest way to pick up cold.
