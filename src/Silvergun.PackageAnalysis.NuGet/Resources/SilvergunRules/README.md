# Silvergun-owned ruleset — provenance

The Application Inspector rule JSON files in this directory (`callback_domains.json`,
`msbuild_exec.json`) are **authored by this project**. They are not copied or derived from
`Resources/BackdoorRules/` (the OSSGadget MIT ruleset) or from any other third-party ruleset — the
OSSGadget files were consulted only to learn the Application Inspector rule JSON *schema* (field
names and shape), never for rule content or text.

- Task spec: `docs/agent/tasks/silvergun-script-ruleset.md`.
- Domain lists in `callback_domains.json` are re-expressed from public, general knowledge of
  out-of-band (OOB) interaction / request-catcher services (`pipedream`, `ceye.io`, Burp
  Collaborator, `interact.sh`, `webhook.site`, `dnslog.cn`, `canarytokens.com`, etc.) and of
  paste/anonymous-file/chat-webhook exfiltration sinks (Pastebin raw, `transfer.sh`, `file.io`,
  Discord/Slack/Telegram webhook endpoints, etc.) — not copied from any single source.
- `msbuild_exec.json` encodes MSBuild `<Exec>` task detection and a set of well-known
  download/execute command-line primitives (PowerShell `-enc`/`DownloadString`/`iex`, `curl | sh`,
  `certutil -urlcache`/`-decode`, `bitsadmin /transfer`, `mshta http`, `rundll32 ...url.dll`),
  general LOLBAS-class knowledge, not sourced from `Resources/BackdoorRules/`.

## Rule ids

Rule ids use the `SG` prefix (`SG0001`…) reserved for this project's own rules, distinct from the
embedded OSSGadget `BD*` ids and any Application Inspector built-in id.

| Id | Severity | Tag | Summary |
| --- | --- | --- | --- |
| `SG0001` | important | `Silvergun.Backdoor.CallbackDomain` | OOB interaction / request-catcher domain (pipedream, ceye.io, Burp Collaborator, interact.sh, webhook.site, dnslog.cn, canarytokens.com, requestcatcher.com, beeceptor.com, hookbin.com, requestbin). |
| `SG0002` | moderate | `Silvergun.Backdoor.ExfilSink` | Paste / anonymous-file / chat-webhook exfiltration sink (pastebin raw, hastebin, transfer.sh, file.io, anonfiles, Discord/Slack/Telegram webhooks). |
| `SG0010` | moderate | `Silvergun.Execution.MsBuildExec` | An `<Exec>` MSBuild task — a supply-chain execution primitive in a package-shipped `.targets`/`.props`. |
| `SG0011` | critical | `Silvergun.Execution.MsBuildDownloadExec` | An `<Exec>` `Command` carrying a download/execute or encoded-execution primitive. |

## Why these rules are ungated (no `applies_to`)

`.targets`, `.props` and `.nuspec` are detected by Application Inspector as **no language at all**
(`LanguageInfo.Name == ""`), so any `applies_to` language gate — including `["xml"]` — makes a rule
permanently unreachable on exactly the files this ruleset targets. See
`docs/agent/tasks/silvergun-script-ruleset.md` for the measurement. These rules are therefore left
ungated, matching how the embedded `BD000600`/`BD000610` (LOLBAS) rules already reach these files.

## Authoring gotchas

Two traps have already been hit once in this ruleset. Read this before adding a rule here.

1. **`"type": "string"` compiles with implicit `\b` word-boundary anchors.** A literal that starts
   with a non-word character (e.g. `<Exec `, which begins with `<`) can therefore **never** match —
   `\b` requires a word/non-word transition, and there is none at a `<`. This made `SG0010` dead on
   arrival the first time it was authored. Use `"type": "substring"` (or `"type": "regex"` with your
   own explicit anchors) for any literal that doesn't start with `[A-Za-z0-9_]`.
2. **Domain alternations need explicit boundary anchors, or they match inside longer hostnames.**
   An unanchored `interact\.sh` matches `interact.shop`; an unanchored `file\.io` matches
   `file.iogames.com`. Wrap the alternation in a trailing `(?![A-Za-z0-9-])` so a longer label/TLD
   can't follow, and (for bare-host alternatives with no path segment) a leading
   `(?<![A-Za-z0-9-])` so a longer preceding label can't precede (e.g. `notpipedream.net` must not
   match `pipedream\.net`). Deliberately **exclude `.` from the leading exclusion class** — a real
   subdomain match like `x.pipedream.net` must still fire, and `.` is exactly the separator that
   makes it a subdomain rather than an unrelated label. For alternatives that already carry a path
   segment (e.g. `pastebin\.com/raw`, `discord\.com/api/webhooks`), check what legitimately follows
   the literal in real URLs before adding a trailing anchor: most are followed by `/` and are safe to
   anchor, but `api\.telegram\.org/bot` is directly followed by a token/digits with no separator
   (`.../bot123456/sendMessage`), so a trailing anchor there would reject every real bot webhook URL.
   When one anchor style doesn't fit every alternative in a family, split into multiple `patterns[]`
   entries on the same rule rather than forcing one regex to cover cases with different boundary
   needs — a near-miss test corpus for this class of bug must include **longer** hostnames, not just
   shorter/truncated ones.
3. **`applies_to` must be absent.** `.targets`/`.props`/`.nuspec` are detected as no language at all
   (`LanguageInfo.Name == ""`), so any language gate — including `["xml"]` — makes the rule
   permanently unreachable on exactly the files this ruleset targets.

## License

All content in this directory is original to the Silvergun project and carries the same license as
the rest of `src/`. No third-party license or attribution applies.
