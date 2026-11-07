# Reachability R2b - the combine step (2026-11-07)

**A measurement, not a feature** (`docs/agent/tasks/reachability-r2b.md`, S4). HostContract and LoadTime, at ChaOnly
and Direct, judged on P-all only over C100 and C-build as one population with one denominator, by the rules R2
pre-registered (E1, E2, the judged gate, the symmetric floor rule). The runtime classes are judged by `--reachability`
on C100 alone. Read offline from the cached results of both runs and their repeats: nothing was measured or fetched.

## 1. Parameters

| Parameter | C100 | C-build |
| --- | --- | --- |
| Manifest | `benign-top.manifest` | `c-build.manifest` |
| Manifest hash | `9e5635c320485af7b86e5656860465e4c1bc5ba753e7771336e7d677ac8838a6` | `cd9ade3633e1e3eb87e51a887afd08550769a7043e12b8e10ce148e4b74a6af0` |
| Manifest entries | 100 | 50 |
| Names cut at 1024 chars (amendment a5; distinct per folder, summed over every folder) | 0 | **22** (some reported names are bounded, not whole) |
| Status: scanned / graph-failed / no-assemblies / crashed / timeout / incomplete / not-cached | 81 / 0 / 19 / 0 / 0 / 0 / 0 | 50 / 0 / 0 / 0 / 0 / 0 / 0 |
| In P-all (the union's denominator, by run) | 81 | 50 |

| Parameter | Value |
| --- | --- |
| Harness build | `3c5da420eb59653311f8138d3e39baf7057d57e8` |
| Harness assemblies sha256 | `8d6e3f9e66e8421a31817632f43d6a77bac70cdcd4fe63522348056ca6ccb613` |
| Date (`--date`) | 2026-11-07 |
| Presence oracle (`--oracle`, C100's side) | `presence-oracle-2026-11-06.tsv` |
| **P-all denominator** (C100 and C-build, one population) | **131** |
| Floor packages in P-all (both runs) | 0, of which unmeasured 0 |
| Classes judged | LoadTime, HostContract |
| Labels | ChaOnly, Direct |

## 2. Gates

| Gate | Result |
| --- | --- |
| C-build manifest is the pinned `c-build.manifest` (hash `cd9ade3633e1e3eb87e51a887afd08550769a7043e12b8e10ce148e4b74a6af0`) | yes |
| C100 oracle, recomputed from the cached results (a full MATCH) | MATCH (78 packages compared) |
| C100 not-cached (0) | 0 |
| C-build not-cached (0; crashed, timeout and incomplete are unmeasured P-all floors) | 0 |
| C100 run and repeat identical per package (results without cost, temp paths masked) | yes |
| C-build run and repeat identical per package | yes |
| Ids in both manifests (none) | none |

**Every gate holds:** the verdicts below stand.

## 3. E1 - P-all over C100 and C-build

As in `--reachability`, section 3: a cell fails only in its best case and passes only in its worst case, every floor
package of either run (Partial reachability, an assembly only one side read, a partial presence scan, or a crashed,
timed-out or incomplete child) counted against the expectation; otherwise it is Floor, not a pass.

### P-all (denominator 131; floor packages 0)

#### P-all - ChaOnly

| Signal capability | Presence | LoadTime reach | LoadTime Bound | LoadTime E1 | HostContract reach | HostContract Bound | HostContract E1 |
| --- | ---: | ---: | ---: | --- | ---: | ---: | --- |
| FileSystem | 61/131 (46.6%) | 0/131 (0.0%) | 0/131 (0.0%) | pass | 20/131 (15.3%) | 20/131 (15.3%) | pass |
| Network | 29/131 (22.1%) | 0/131 (0.0%) | 0/131 (0.0%) | pass | 6/131 (4.6%) | 3/131 (2.3%) | pass |
| ProcessExecution | 35/131 (26.7%) | 0/131 (0.0%) | 0/131 (0.0%) | pass | 9/131 (6.9%) | 7/131 (5.3%) | pass |
| Registry | 11/131 (8.4%) | 0/131 (0.0%) | 0/131 (0.0%) | pass | 2/131 (1.5%) | 2/131 (1.5%) | pass |
| NativeInterop | 43/131 (32.8%) | 0/131 (0.0%) | 0/131 (0.0%) | pass | 12/131 (9.2%) | 6/131 (4.6%) | pass |

| Class | Roots | E1 |
| --- | ---: | --- |
| LoadTime | 5 | pass |
| HostContract | 47711 | pass |

#### P-all - Direct

| Signal capability | Presence | LoadTime Direct reach | LoadTime E1 | HostContract Direct reach | HostContract E1 |
| --- | ---: | ---: | --- | ---: | --- |
| FileSystem | 61/131 (46.6%) | 0/131 (0.0%) | pass | 20/131 (15.3%) | pass |
| Network | 29/131 (22.1%) | 0/131 (0.0%) | pass | 6/131 (4.6%) | pass |
| ProcessExecution | 35/131 (26.7%) | 0/131 (0.0%) | pass | 9/131 (6.9%) | pass |
| Registry | 11/131 (8.4%) | 0/131 (0.0%) | pass | 2/131 (1.5%) | pass |
| NativeInterop | 43/131 (32.8%) | 0/131 (0.0%) | pass | 12/131 (9.2%) | pass |

| Class | Roots | E1 |
| --- | ---: | --- |
| LoadTime | 5 | pass |
| HostContract | 47711 | pass |

## 4. E2 - P-all over C100 and C-build

### P-all (denominator 131)

| Class | Label | Roots | >= 2 signals (Unseen-inclusive, judged) | Without Unseen | With Unseen | Class profiles cut at 64 (packages) | Floor packages | E2 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| LoadTime | ChaOnly | 5 | 0/131 (0.0%) | 0/131 (0.0%) | 0/131 (0.0%) | 0 | 0 | pass |
| LoadTime | Direct | 5 | 0/131 (0.0%) | 0/131 (0.0%) | 0/131 (0.0%) | 0 | 0 | pass |
| HostContract | ChaOnly | 47711 | 14/131 (10.7%) | 13/131 (9.9%) | 4/131 (3.1%) | 0 | 0 | **FAIL** |
| HostContract | Direct | 47711 | 14/131 (10.7%) | 13/131 (9.9%) | 4/131 (3.1%) | 0 | 0 | **FAIL** |

## 5. Verdicts (P-all only: a fail of E1 or E2 = does not discriminate; any Floor = undecided)

| Class | Label | P-all E1 | P-all E2 | Verdict |
| --- | --- | --- | --- | --- |
| LoadTime | ChaOnly | pass | pass | E1 and E2 hold in P-all |
| LoadTime | Direct | pass | pass | E1 and E2 hold in P-all |
| HostContract | ChaOnly | pass | **FAIL** | does not discriminate on the benign corpus |
| HostContract | Direct | pass | **FAIL** | does not discriminate on the benign corpus |

## 6. Floor packages (both runs)

*None.*

