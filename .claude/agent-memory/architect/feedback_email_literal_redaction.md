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

## Also silently transformed: the `\u0000` escape (2026-08-20)

The `Write` tool **silently replaced the literal escape sequence `\u0000` in file content with a
plain space**. But a second agent, writing C# source, saw the same escape become a **raw `0x00` byte
embedded in the `.cs` file** — enough that `grep` then classified the source as binary. A bare
backslash-zero char literal survived untouched, so the trigger is the four-hex-digit backslash-u
*pattern*, not the codepoint. **The result of the transformation VARIES; do not rely on it being
benign.**

⚠️ **This also applies to MY OWN tool calls.** An `Edit` whose `old_string` contained that escape
arrived with it already replaced by a space, so the match failed against a file that genuinely
contained the escape. If an edit inexplicably cannot find text you just read, suspect this.

⇒ Safe rule: **never embed a four-hex-digit backslash-u escape in written file content.** Construct
the value at runtime instead (`new string((char)0, 1)`), and anchor edits on surrounding text that
does not contain the pattern.

**Why it matters beyond the one case:** this project authors adversarial test fixtures on purpose —
markup-injection payloads, hostile paths, unusual codepoints. **A fixture whose payload is silently
neutralised on write produces a test that passes while testing nothing**, which is the
[[inert-guard-defect-class]] arriving through the tooling rather than the code.

**How to apply:** when a fixture's whole point is an unusual codepoint or escape sequence, author it
via a Bash heredoc or construct it in code (`"\u0000"`, `'\0'`), and then **verify the bytes are
actually there** rather than trusting the write. Generalise the suspicion: assume file-write may
transform content, and check any payload whose exact bytes are the thing under test.
