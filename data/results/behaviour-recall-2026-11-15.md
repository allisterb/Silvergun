# Behaviour-fixture recall, 2026-11-15

**Provenance:**
- **Spec:** `docs/agent/tasks/behaviour-fixtures-recall.md`.
- **Code:** in-house synthetic fixtures under `tests/BehaviourFixtures/` and the harness under
  `tests/Silvergun.CLI.Tests/Behaviour/`, on HEAD `c1802df` plus the uncommitted fixture work. They are original code,
  not third-party data, and contain no real samples.
- **Run:** the Silvergun CLI from the same tree, Debug, invoked by the test harness.
- **Command:** `scan-package <nupkg> --json --strict --reachability --ssa --no-vulns --allow-incomplete`, one package at
  a time.
- **Per-run JSON:** `%TEMP%\silvergun-behaviour-recall` (48 files; overwritten by each run).
- **YARA:** `Unavailable` on every row (`SILVERGUN_YARA_PATH` unset in the test environment). **These numbers are
  recall without YARA.**
- **Vulnerabilities:** not checked (`--no-vulns`; the fixtures have no dependencies).

**Caveat: these are in-house fixtures, written by us, for behaviours we chose.** They give a floor and a map of misses, not
an estimate of recall on real malware. The predictions were written before any fixture existed (spec §5), and the
catalogue follows the ReversingLabs TTP inventory, not our detector list. Even so, the authors know the detectors.

## 1. Headline numbers against the predictions

| Measure | Predicted | Measured |
|---|---|---|
| **Gate recall** (`--strict` exit 2), malicious | 6 of 29 | **7 of 29 (24%)**. The same rows as predicted; §5 counted BF19 once, but it is two packages |
| **Twins failing the gate** | 0 of 19 | **0 of 19** |
| **Attention** ("Findings present"), malicious / twins | not predicted | **29 of 29 / 17 of 19**: the headline does not discriminate |
| **Signal recall, strict:** a finding that names the behaviour | not predicted separately | **18 of 29** |
| **Signal recall, loose:** any signal the twin lacks, including composition and SSA values | about 26 of 29 | **26 of 29** |

Signal recall by strength:
- **Named (18).** A finding that names the behaviour:
  - a gating or non-gating indicator;
  - a specific script rule;
  - an encoded-executable obfuscation finding;
  - a reachability trigger;
  - an SSA-resolved reflection target.
  - Rows: BF01a, BF01b, BF02, BF03, BF07a–c, BF08a–d, BF09, BF11, BF12a, BF13, BF16, BF19a, BF19b.
- **Composition only (6).** The malicious side differs from its twin only by an extra capability or reach statement,
  usually Network: BF04, BF05, BF06, BF15, BF17, BF18. Nothing says "harvests and sends". It is visible only by
  comparing against the twin, which a user never has.
- **Values only (2).** The difference shows only in SSA constants or import names: BF10 (`powershell -NoP -W Hidden
  -Enc …` against `git --version`) and BF14 (`VirtualAlloc(_, _, 12288, 64)` against `GetTickCount64`).
- **None (3).** BF12b–d, the three hidden-payload evasions. This was predicted.

**What gates, and what doesn't.** Only three indicator categories caught anything at the gate: CredentialPath
(BF07a–c, BF19a–b), CallbackDomain (BF08c) and DynamicDns (BF08d). Every behaviour without a distinctive string passes
`--strict`. That includes:
- build-time `<Exec>` download cradles;
- MSBuild tasks, analyzers and module initializers that harvest and post;
- encoded PowerShell;
- Run-key persistence;
- a loader shape;
- CI-secret harvesting.

## 2. Where the predictions missed

| Row | Predicted | Measured | Why |
|---|---|---|---|
| BF15 | ReachTrigger NativeEntry → EnvironmentProbe | Informational | By design: R3 makes a trigger only for the five signal capabilities (`reachability-r3.md`), and EnvironmentProbe is not one. The prediction was wrong, not the analyzer |
| BF12 twin | no obfuscation | `HighEntropyBlob` on the base64 PNG | Benign base64 blobs fire obfuscation. The known 29% benign prevalence (ADR 0027 decision 2) |
| BF10 | Obfuscation `?` | none | The `-Enc` base64 sits inside a longer, space-separated constant, which the decoder does not tokenise |
| BF19a/b | Anomaly `?` | none | A managed DLL at the package root or under `content/` is analysed (and caught by its indicator), but raises no packaging anomaly |

Not a miss, but worth noting: BF18 measured as predicted ("as BF17"), plus RuntimeControl on both sides. The
anti-analysis checks are visible only as a generic capability that the twin shares.

`?` cells resolved:
- BF01 cradle → `SG0011` (twin: `SG0010` only);
- BF02 → `BD000702`;
- BF03 → `BD000101` (both twins: no finding and no attention);
- YARA → unavailable.

## 3. The detector matrix

M = the malicious side hit; T = the twin hit; B = both; blank = neither. Detectors that never fired on any row (Anomaly,
YARA) are left out.

| Row | Capability | Indicator | Obfuscation | Script | Reach (statement) | SSA site | Gate |
|---|---|---|---|---|---|---|---|
| BF01a/b | | | | B (SG0011 M only) | | | |
| BF02 | | | | M | | | |
| BF03 | | | | M | | | |
| BF04 | B (+Network M) | M (GenericUrl) | | | B HostContract (+Network M) | B | |
| BF05 | B (+Network M) | M (GenericUrl) | | | B HostContract (+Network M) | B (values differ) | |
| BF06 | B (+Env, Network M) | M (GenericUrl) | | | B LoadTime | M | |
| BF07a–c | B | **M CredentialPath** | | | | M | **M** |
| BF08a/b | B | M ExfilSink (twin GenericUrl) | | | | B | |
| BF08c | B | **M CallbackDomain** | | | | B | **M** |
| BF08d | B | **M DynamicDns** | | | | B | **M** |
| BF09 | B (+Network M) | M RawCodeHost | | | | B | |
| BF10 | B | | | | | B (values differ) | |
| BF11 | B | M AutorunRegistry | | | | B (values differ) | |
| BF12a | B (+Process M) | | B (EncodedExecutable M, HighEntropyBlob T) | | | | |
| BF12b–d | B (+Process M) | | T only | | | | |
| BF13 | B (+Network M) | M ReflectionTypeName | | | | B (M resolves `System.IO.File::ReadAllBytes`) | |
| BF14 | B | | | | | B (values differ) | |
| BF15 | B | | | | M Informational | | |
| BF16 | B | | | | M **Trigger** Finalizer/Direct → ProcessExecution (twin Informational → UnsafeMemory) | M | |
| BF17, BF18 | B (+Network M) | M (GenericUrl) | | | | B (values differ) | |
| BF19a/b | B | **M CredentialPath** | | | | M | **M** |

`GenericUrl` fires on every `example.test` URL, so its M/T difference reflects the twins' URL choices, not detection.

## 4. SSA pairs: input for argument-aware triggers

Same callee, malicious constant against twin constant:

| Callee | Malicious | Twin | Value class that separates them here |
|---|---|---|---|
| `Process.Start(string, string)` | `"powershell", "-NoP -W Hidden -Enc VwByAGkA…"`; BF16 `"cmd.exe", "/c whoami"` | `"git", "--version"` | a shell interpreter as the file, with hidden-window or encoded-command flags |
| `kernel32!VirtualAlloc` | `(_, _, 12288, 64)`: MEM_COMMIT\|MEM_RESERVE, PAGE_EXECUTE_READWRITE | (twin calls `GetTickCount64`) | an executable page protection (0x10/0x20/0x40/0x80) |
| `Environment.GetEnvironmentVariable` | `"GITHUB_TOKEN"`, `"NUGET_API_KEY"`, `"AWS_SECRET_ACCESS_KEY"` | `"ASPNETCORE_ENVIRONMENT"`, `"DOTNET_CLI_TELEMETRY_OPTOUT"` | a secret-shaped name (`*TOKEN*`, `*KEY*`, `*SECRET*`, known CI secret names) |
| `RegistryKey.OpenSubKey` / `SetValue` | `…\CurrentVersion\Run`, writable | `Software\<Vendor>\Settings` | already caught by the `AutorunRegistry` indicator; SSA adds that it is opened writable and written |
| `Environment.GetFolderPath` | `28` (LocalApplicationData), `40` (UserProfile) | BF05 twin: `26` (ApplicationData) | weak: both are common in benign code |

**Three candidates for argument-aware triggers:**
1. A shell interpreter with stealth flags.
2. An executable `VirtualAlloc` protection.
3. A secret-shaped environment-variable name.

None may be proposed from this table alone. Each must first be checked against the benign prevalence of the same
(callee, value class) in S4.5's facts over C100 and C-build (ADR 0037 decision 11; `ssa-facts-s5.md`). Constant
`GetEnvironmentVariable` already appears in 16–18 benign packages per corpus, but how many of those use secret-shaped
names is unmeasured.

## 5. Reflection edges

- **BF13:** SSA resolves both reflected calls: `System.IO.File::ReadAllBytes`, and the own private `Behaviour.Hidden::Post`.
  - As edges, they would add FileSystem reach from the caller and provenance to `Post`.
  - No verdict would move. The row is already flagged (`ReflectionTypeName`, Network), and reach statements gate
    nothing. This is reasoned, not measured: BF13 has no reach statements at all, so whether `Post` is a presented
    root was not observed.
- **BF09:** the target is unresolved (`Member _ :: _`): the type comes from the downloaded bytes.
- **Verdict on this evidence: reflection edges change no verdict here.** Revisit only if a trigger is ever defined
  over reach from a host-invoked root, where an edge could complete a path that today ends unseen.

## 6. Levers for the misses, ranked

| Miss | Lever | Ties to |
|---|---|---|
| Harvest-and-send (BF04–06, BF15, BF17, BF18) is composition only | a co-reach statement: one root reaching both a collection capability (EnvironmentProbe or FileSystem enumeration) and Network, worded as such; measure benign prevalence first, as R2b did | seam-mapping §4.10; ADR 0037 "Composition" |
| BF10, BF14, the BF17 values | argument-aware triggers on the three value classes in §4, after benign prevalence | ADR 0037 decision 11 |
| BF12b split base64 | constant folding of string concatenation in SSA, then feed folded constants to the obfuscation decoder | the precision item ("constant folding") |
| BF12c RVA data, BF12d managed resource | the resource and RVA blob scanner | seam-mapping §4.6 |
| BF10 `-Enc` inside a longer constant | tokenise `ldstr` text on whitespace before base64 detection | `ObfuscationAnalysis` |
| BF19 no anomaly for DLLs outside the standard folders | a packaging anomaly for managed assemblies at the package root or under `content/` | ADR 0031 |
| Script-only build vectors gate nothing (BF01–03) | the per-rule breakdown ADR 0027 decision 3 asked for: `SG0011`, `BD000702` and `BD000101` fired here and not on their twins, while `SG0010` fired on both | ADR 0027 decision 3 follow-up |
| No YARA in this measurement | re-run with the YARA worker deployed | ADR 0033 |

## 7. Changes after review (2026-11-15)

- The BF05 twin was made faithful: it now enumerates `ApplicationData\SilvergunBehaviourVendor\Analyzers`, which
  gives it EnvironmentProbe and two SSA sites. No other row changed, and no headline number moved: BF05 stays
  composition-only, through Network.
- Every `SILVERGUN_*` variable is removed from the CLI child, so these numbers are pinned as recall with YARA off.

## 8. Update, 2026-11-16: recall levers 1

Spec: `docs/agent/tasks/recall-levers-1.md`. The same fixtures, command and environment as above, on the uncommitted
levers tree. Three changes are informational only: nothing gates, and exit codes are unchanged.
- **Co-reach statements:** one presented root reaches both a collection capability and Network.
- **Value signals at SSA sites:** a shell interpreter, stealth arguments, executable memory, a secret-shaped environment
  name.
- **Folding** of `string.Concat` of constants.

| Measure | 2026-11-15 | 2026-11-16 |
|---|---|---|
| Gate recall, malicious | 7 of 29 | 7 of 29 (unchanged) |
| Twins failing the gate | 0 of 19 | 0 of 19 |
| Signal recall, strict (named) | 18 of 29 | **25 of 29** |
| Signal recall, loose | 26 of 29 | 26 of 29 |
| Twins showing any new statement or signal | | 0 of 19 |

**Newly named:**

| Rows | What names them |
|---|---|
| BF04 | HostContract co-reach of EnvironmentProbe and Network |
| BF05 | HostContract co-reach of EnvironmentProbe or FileSystem, and Network |
| BF06 | LoadTime co-reach of both pairs |
| BF10 | ShellInterpreter, StealthArguments |
| BF14 | ExecutableMemory |
| BF17, BF18 | SecretEnvironmentName |

BF16 also gains ShellInterpreter; it was already named. BF15 stays composition-only: its native entry point does not
reach Network. BF12b–d stay missed: folding does not follow static fields, and the decode call is not a sink.

**Nothing became a trigger.** Measured on the benign corpora (C100, C-build) by a rule written before the run:
- Shell, secret-environment, HostContract and TypeInitializer/Finalizer co-reach fire in benign build tools and SDKs.
- StealthArguments, ExecutableMemory and LoadTime co-reach fired on no benign package. They fail only the floor clause:
  any SSA-incomplete folder counts as a possible hit.

Folding moved no benign constant-sink count. Pins are updated in `BehaviourMeasured.cs` (8 rows, additions only).

## 9. Pinned

Every observation in this document is pinned row by row in `tests/Silvergun.CLI.Tests/Behaviour/BehaviourMeasured.cs`.
Any detection change, including an improvement, turns that suite red until the pin and this file are updated together.
