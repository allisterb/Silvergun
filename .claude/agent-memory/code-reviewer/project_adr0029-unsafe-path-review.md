---
name: project_adr0029-unsafe-path-review
description: ADR-0029 (control-character entry names hiding a YARA hit) review rounds 1-5, 2026-08-22 — the closed fail-open sites, the Ordinal-vs-OrdinalIgnoreCase comparer mismatch, the round-4 "truncate-at-first-C0 vs split-at-CR/LF" mismatch in decision 17a, and the round-5 clean landing.
metadata:
  type: project
---

Review of the ADR-0029 fix (`YaraPathSafety`, `YaraScanIncompleteException`, `YaraCliScanner`
partition + recovery pass), rounds 1-4, 2026-08-22.

## Round 1 (all addressed)

**Residual fail-open routes in `YaraCliScanner.ScanDirectory`** — enumeration failure, ruleset
preparation, batch start failure/timeout, nonzero exit each returned an empty list ⇒ `Completed`.
Closed: all throw `YaraScanIncompleteException` (timeout carries a `TimeoutException` inner).

**`IYaraScanner.Available` does not cover any of that.** One-time `File.Exists`, so it stays `true` for
an unlaunchable, hung or failing engine. Any "already covered by `Available`" rationale is wrong.

**Escaping audit lesson:** `ex.Message` embeds the *source path* on Unix IO failures, so escaping only
the explicit path argument is half a fix. Trace `ex.Message`, not just explicit arguments.

## Round 2 — the comparer mismatch (fixed in round 3)

The echo-key partition compared `StringComparer.Ordinal` while `forged`/attribution compared
`OrdinalIgnoreCase`, so anything ignore-case-equal but ordinal-distinct escaped the partition and was
still conflated. Full evasion cost one empty file (`content/mal.dll` + `content/MAL.dll\nx`).
Now one comparer (OrdinalIgnoreCase) everywhere; `exact` stays Ordinal and is checked first.

**Proof that one comparer suffices** (reusable): for any batch target `T` echoed for enumerated file
`F`, `TryNormalize(T)` is either `EchoKey(F)` or contains a C0 char. So once the partition and
attribution compare keys the same way, `deferred ∩ attributable-keys = ∅`, `forged ⊆ deferred`, and the
`forged` veto is provably vacuous (defence in depth only — the ADR records this honestly).

## Round 4 (2026-08-22) — decision 17a's exclusion is keyed on the wrong string

**The live defect.** `ScanBatch`'s dropped-hit filter is
`!deferred.Contains(key)` where `key = TryNormalize(r.Target)` (the *whole* echoed target), but
`deferred` holds `EchoKey(f) = TryNormalize(TruncateAtFirstControl(f))`. Those coincide **only when the
echoed line is cut where `TruncateAtFirstControl` cuts** — i.e. the file's first C0 is LF or CR
(`ParseAll` splits on `\n`; .NET's `AsyncStreamReader` also breaks a lone `\r` — the "`\r` - Mac"
branch), or is a trailing whitespace char removed by `raw.TrimEnd()`.

For a deferred file whose first C0 is TAB or any of 0x01–0x08/0x0B/0x0C/0x0E–0x1F, the echoed target
keeps the control char ⇒ not in `deferred` ⇒ counted as dropped ⇒ `ScanBatch` throws **before**
`ScanIndividually` runs. A matching payload named `content/pay\tload.bin` therefore reports
`Unavailable` / zero findings instead of the finding the recovery pass would have produced — the exact
outcome 17a exists to prevent. Fails closed, so not a false clean, but under
`--strict --allow-incomplete` exit 2 becomes exit 0.

Fix: compare the *truncated* form — `!deferred.Contains(EchoKey(x.Target))`. Safe because the filter
only sees `File is null` records and no attributable file's echo can have an EchoKey in `deferred`.

**How it was proved without running anything:** `YaraCliDroppedHitTests`'s escaping test already stages
target `<root>/content/gh\tost.bin` for a file that is deliberately *not created* and asserts the
throw. Creating that file only adds `<root>/content/gh` to `deferred`, which the predicate never
compares against. Reuse this trick: find the test that stages the hostile shape as a ghost, then ask
what changes if the file exists.

**Coverage gap that hid it:** every test with a *matching* deferred file uses `\n`
(`YaraCliAttributionTests` ×6, `YaraCliScannerUnsafePathTests`, `YaraCliDroppedHitTests`); the only
non-LF control-char file with real content is deliberately non-matching. Any future change here needs a
`\t`-named matching file.

**Nit worth remembering:** `IsUnderRoot`'s `key[root.Length] is '/' or '\\'` — after `TryNormalize` the
backslash arm is dead on Windows (folded to `/`) and wrong on Linux (`\` is a legal filename char, so a
*sibling* `<root>\evil` reads as under the root). Unreachable today (needs the random temp root).

## Round 5 (2026-08-22) — fix landed clean, no Critical

`IsDeferredEcho(target) => EchoKey(target) is { } echo && deferred.Contains(echo)` is the specified
fix and matches ADR 17a's wording ("targets whose echo key belongs to a file in the deferred set").
Re-derived both directions: every deferred file's echo truncates to its own echo key regardless of
*where* the line was cut (the cut is always at a C0 char, so at or after the first one), and
attributable ∩ deferred = ∅ because `ambiguous` is grouped over **all** keyed entries, unsafe ones
included. The `is { } echo` null arm is also what keeps a `string?` out of `IReadOnlySet<string>.Contains`.

Residual, all sub-nit: the widened exclusion also swallows a *non-enumerated* target whose pre-C0
prefix collides with a deferred key (forged extra line, or a TOCTOU file) — unreachable, we execute
no package code and pass `NoFollowSymlinks`.

**The one thing worth re-checking every time here: "ParseAll splits stdout on LF" is not the whole
truth.** `RunProcess` reads via `OutputDataReceived` (AsyncStreamReader), which breaks at CR, LF and
CRLF and re-joins with `'\n'`, so the effective cut set is {LF, CR}. Several src comments still say
"only at an LF" while correctly omitting 0x0D from their character lists.

## YARA test-suite facts (verified, still current)

- The env race needs **both** `[Collection("yara-env")]` on every env-mutating class *and*
  `YaraEnvScope`'s ctor touching `YaraScannerFactory.Shared` before poisoning. `YaraCliProbe`'s statics
  are safe because they initialize at xunit *discovery*, before any test poisons the env, and prefer
  distro paths over `SILVERGUN_YARA_PATH`.
- `FakeYaraProbe` (Exe under `tests/`) stages *stdout* as well as exit code/hang/argv — `_STDOUT` for
  the recursive pass, `_ECHO_RULE` for single-file scans (the recovery pass's temp-copy name is not
  knowable in advance). Sound for attribution tests; rule matching is still real-engine, Linux-only.
- Re-derived pins that are correct: 33 colliding pairs ⇒ "could not scan 2 of 66"; 3 invocations for a
  case-only pair + one ordinary file (1 batch + 2 individual); `elapsed < 7.5 s` for 3 files × 4 s
  against a 5.25 s aggregate budget; `HermeticWiperSample` = 623 hex tokens + `MZ` = **625 bytes**, so
  the `> 400` pin has margin.
- The two round-2 stale pins were rewritten correctly: the cost pin's old (1 process) and new (3
  processes) assertions are mutually exclusive, and the echo-key test now asserts OrdinalIgnoreCase
  collision alongside the retained ordinal-distinctness.

**How to apply:** on any further ADR-0016/0027/0029/0030 change, re-check (a) which `ScanDirectory`
exits still return empty-and-`Completed` (including the interface default), (b) that every
normalisation used to *partition* uses the same comparer **and the same truncation** as the one used to
*attribute* or *exclude*, (c) that no hit is discarded without being counted, and (d) that no
`ex.Message` reaches a log unescaped. Related: [[project_yara-compiler-poisoning-review]],
[[feedback-reverify-empirical-code-comments]], [[feedback_verify-structural-commutativity-claims]].
