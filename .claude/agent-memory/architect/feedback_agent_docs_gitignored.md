---
name: agent-docs-gitignored
description: docs/agent/ stays gitignored by design; user backs it up manually — stop raising it as an open issue in handoffs
metadata:
  type: feedback
---

`docs/agent/*` is gitignored (`.gitignore:431`) and **that is the user's deliberate repo policy**,
not an oversight. The user backs the directory up manually (confirmed 2026-08-03). Stop listing it
as an unresolved item.

**Why:** it was flagged in four consecutive session handoffs as "raised repeatedly; still open",
which read as nagging about a decision that had already been made. A `.gitignore` edit is repo
policy and the user's call; `reference/*` is ignored on the same deliberate grounds (bulk
third-party material).

**How to apply:** do not add "docs/agent/ is not in version control" to handoff checkpoints or
status reports. It is still worth remembering that ADRs, specs and measurements have **no git
history** — so treat those files as append-mostly, never rewrite one destructively assuming
`git checkout` can recover it, and prefer adding a new dated section over replacing prose.

Related: [[research-journal]]
