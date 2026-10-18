---
name: project_adr0030-0031-containment-and-anomalies-review
description: ADR-0030/0031 (lexical containment, claim-once, packaging anomalies, rune-aware escaper) review, 2026-08-22 — the C1 claim-once trace, the two residual shadowing shapes (trailing space/dot, exact duplicate names), and the reusable measurements.
metadata:
  type: project
---

Review of the packaging-anomaly + lexical-containment work (`PackageEntryNameAnalyzer`,
`PackagingAnomaly`, `NuGetPackage.UninventoriedEntryNames`, rune-aware `YaraPathSafety.Escape`),
round 3, 2026-08-22, on top of `HEAD = df94310`. **No Critical.**

## Claim-once (`NuGetPackage.UninventoriedEntries`) — re-derived, sound

`unclaimed = set(files that passed IsContained)`; walk `ContainedEntries(declared)` in archive
(central-directory) order; `seen` skips a repeated RAW name; `unclaimed.Remove(key)` is destructive, so
no file can be claimed twice. Deterministic (zip central-directory order; `Directory.EnumerateFiles`
order is irrelevant because both sides are sets). Every "claim a file a later entry should have owned"
case requires colliding keys, i.e. one extracted path — so "should have owned" is not well defined and
over-reporting is fail-closed.

## The two shadowing shapes it still cannot see (both Warnings, both pre-existing)

1. **Trailing space / dot.** MEASURED on this machine: `File.Create("X.dll ")` and `File.Create("Y.dll.")`
   silently produce `X.dll` / `Y.dll` on Windows — no exception. So declared `lib/net8.0/evil.dll `
   lands on disk as `evil.dll`, fails `IsContained` (warn + skipped), and the unclaimed branch tests
   `IsAssembly(key)` on the *untrimmed* key, which does not end in `.dll` ⇒ **not** reported lost ⇒
   package reads complete, exit 0 under `--strict`. Only the (non-gating) `TrailingSpaceOrDot` anomaly
   fires. Fix: test the kind on `key.TrimEnd(' ', '.')`; safe because on Linux the entry claims its own
   file before reaching that branch.
2. **Exact duplicate entry names with DIFFERENT bytes.** The `seen` carve-out and
   `CollisionGroups`'s `.Distinct(Ordinal)` both rule these out with the justification "one entry
   declared twice" — which is a claim about the *name*, not the content. MEASURED: `ZipArchive.GetEntry`
   returns the **first** duplicate (checked on .NET Framework via PS 5.1) while sequential extract-all
   leaves the **last** on disk, so "the file scanned is not the file shipped" is live and unreported.
   Natural sibling of the already-recorded `PathFoldingCollision` follow-up.

## Verified derivations (do not re-trust, re-derive if they change)

- ADR-0031 corrected decision 4's "**12 BMP misses**" is exactly right: 0x00AD(1) + 0x200B–D(3) +
  0x200E/F(2) + 0x2060–2064(5) + 0xFEFF(1) = 12; Tag block = 128.
- `Escape`'s output can contain no `NeedsEscape` code point: all escape sequences are ASCII, pass-through
  runes are by definition not `NeedsEscape`, and a lone surrogate becomes U+FFFD (not forbidden).
  Idempotence therefore holds even for astral pass-through.
- The escaper is a strict superset of the `InvisibleCharacter` category (U+200E/F, U+2060–2064,
  U+2028/9 are escaped but not categorised). Deliberate — do not "fix" by widening the category.
- The random multi-rune property does not assert well-formedness directly, but an emitted lone surrogate
  would break its `Escape(escaped) == escaped` assertion, so it IS covered transitively.

## Watch-outs

- `src/Silvergun.CLI/bin/Debug/net10.0/Silvergun-CLI*.log` holds warnings from *intermediate* builds
  (e.g. `content/../Folded.dll was NOT inventoried`) that the current code contradicts. Build output is
  not evidence; check against `UninventoriedEntryTests` instead.
- `PackageScanner.NotInventoried` calls `RoleOf`/`TargetFrameworkOf` on the ALREADY-ESCAPED name, so a
  hostile first segment yields `Unknown`/null. Cosmetic only.

Related: [[project_adr0029-unsafe-path-review]], [[feedback-reverify-empirical-code-comments]],
[[project_exit-code-footer-predicate]].
