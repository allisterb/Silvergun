---
name: email-literal-redaction
description: Writing a literal email-like `user@host` string to a file gets silently rewritten by a redaction filter in this environment
metadata:
  type: feedback
---

Writing a **literal contiguous email-like string** (e.g. `git@github.com`) into a file via the
editing tools gets **silently rewritten** to a placeholder address by a redaction filter on the
file-write path in this environment. The change is silent — the file on disk differs from what was
"written".

**Why it matters:** observed 2026-07-17 — a `test-engineer` writing SSH-URL test cases
(`git@github.com:owner/repo.git`) had those literals scrubbed, breaking the tests until worked
around. Any code/test/doc/fixture containing an SSH git remote, a contact email, a git config
example, etc. can be corrupted this way without warning.

**How to apply:** When a file must contain a literal `user@host`/email, avoid a single contiguous
literal — e.g. in C# use compile-time concatenation (`"git@" + "github.com:owner/repo.git"`), which
stays a constant expression, or otherwise break the token so it isn't a contiguous match. Tell
subagents this when their task involves SSH URLs / emails. If a written file mysteriously differs
from intent around an `@`, suspect this filter. Related environment gotcha: [[avoid-find-command]].
