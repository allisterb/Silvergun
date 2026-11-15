# SSA facts, S4.5, benign-top.manifest, Debug, 2026-11-15

Measured by the benign-corpus harness `--ssa` (docs/agent/tasks/ssa-facts-s4.md, S4.5). Per cached package: the `ssa-join`
child (every folder's graph, every method lifted and joined to the graph's call-site edges by node id and IL offset, then
the product path's facts in a fresh session), and `PackageReachability.Analyze` through the real `Silvergun.CLI` worker
with default options: SSA off, on (`SsaFactBounds.Default`), and on again over a second extraction.

- manifest: `benign-top.manifest`, hash `9e5635c320485af7b86e5656860465e4c1bc5ba753e7771336e7d677ac8838a6`, 100 entr(ies)
- cache: `%LOCALAPPDATA%\Silvergun\benign-corpus` (read only; nothing downloaded); results: `%LOCALAPPDATA%\Silvergun\ssa-s5b\c100`
- build: Debug, identity `commit 644bd70428cc0f5313af3d6627079f5fd93ff0f4-dirty, assemblies 37233b5474375a16871fba676427fa14090bf21ef7b16b39eaa50aa106544e35`
- packages: 100; folders: 523; join-child folders: 523
- **problems: 0**

## Additivity (AC1)

- folders compared: 523; identical with SSA off and on (outcome, serialized report, assemblies, load failures, reason, SameAs, size): 523
- graph outcomes with SSA on: Analyzed 517, NothingLoaded 6
- SSA outcomes: Analyzed 517, NotRun 6

## The per-site join (AC4), every method lifted

| Measure | Count | Rate |
|---|---:|---:|
| Method definitions with a body | 764,846 | |
| Lifted | 745,196 | 97.431% |
| Lifted, node id an own graph node (node-id join) | 745,196 | 100.000% |
| Unknown | 19,650 | |
| Unknown, node id an own graph node | 19,650 | 100.000% |
| Own graph nodes with a body | 761,290 | |
| ... with an SSA outcome under their node id | 761,290 | 100.000% |
| SSA call sites (call, newobj, ldftn, ldvirtftn) of lifted methods in the graph | 2,722,351 | |
| ... joined to an edge of the same kind group and callee key | 2,722,292 | 99.998% |
| ... and of the same exact kind (call vs callvirt) | 2,722,292 | 100.000% |
| Edge sites (node, offset, kind group) of own nodes | 2,970,207 | |
| ... of nodes with a lifted definition (checked) | 2,710,265 | 91.248% |
| ... ... joined to an SSA site | 2,709,312 | 99.965% |
| ... ... with more than one callee (Ambiguous) | 3,178 | |
| ... of nodes with only Unknown definitions (not checked) | 259,942 | 8.752% |
| ... of nodes with no SSA outcome (a miss class) | 0 | |
| Graph-truncated folders | 0 | |
| Folders where SSA lost an assembly | 0 | |

Misses by class (examples in the `-join-examples.tsv`):

| Class | Count | Folders | Explained |
|---|---:|---:|---|
| `edge:initialize-array-intrinsic` | 953 | 134 | yes |
| `site:no-edge(md-array-accessor)` | 59 | 9 | yes |
- folders whose graph is not the join child's: 0; product facts misaligned with their raw sites: 0

## Sink coverage (worker, SSA on)

- sink sites: 55,188; kept: 55,188; truncated folders: 0
- by status: Analyzed 54,200, MethodUnknown 988
- Analyzed with at least one Constant or OneOf argument: 6,631 (12.234% of Analyzed)
- MethodUnknown by failure kind (methods lifted for sinks): UnresolvedFact 383
- NotJoined by reason: 

Top constant-bearing sinks (Analyzed sites with a Constant or OneOf argument; counts only; all 314 in the `-constant-sinks.tsv`):

| Capability | Callee | Sites | Packages |
|---|---|---:|---:|
| EnvironmentProbe | `System.Environment.GetEnvironmentVariable` | 696 | 16 |
| NativeInterop | `System.Runtime.InteropServices.Marshal.SetLastSystemError` | 570 | 7 |
| ReflectionInvocation | `System.Reflection.MethodBase.Invoke` | 236 | 22 |
| FileSystem | `System.IO.FileStream..ctor` | 200 | 17 |
| ReflectionInvocation | `System.Reflection.MethodInfo.CreateDelegate` | 196 | 18 |
| ReflectionInvocation | `System.Type.GetType` | 194 | 17 |
| Cryptography | `System.Security.Cryptography.Oid..ctor` | 183 | 3 |
| ReflectionInvocation | `System.Reflection.PropertyInfo.GetValue` | 170 | 16 |
| DynamicCodeLoading | `System.Reflection.Emit.ILGenerator.EmitCall` | 162 | 3 |
| Cryptography | `System.Security.Cryptography.SymmetricAlgorithm.set_KeySize` | 157 | 5 |
| DynamicCodeLoading | `System.Reflection.Emit.DynamicMethod..ctor` | 122 | 11 |
| NativeInterop | `System.Runtime.InteropServices.Marshal.Copy` | 106 | 10 |
| DynamicCodeLoading | `System.Reflection.Emit.ILGenerator.DeclareLocal` | 90 | 10 |
| ReflectionInvocation | `System.Reflection.FieldInfo.GetValue` | 81 | 13 |
| DynamicCodeLoading | `System.Reflection.Emit.ILGenerator.Emit` | 77 | 10 |
| EnvironmentProbe | `System.Environment.GetFolderPath` | 73 | 4 |
| Registry | `Microsoft.Win32.RegistryKey.GetValue` | 67 | 6 |
| Registry | `Microsoft.Win32.RegistryKey.OpenSubKey` | 65 | 6 |
| DynamicCodeLoading | `System.Activator.CreateInstance` | 64 | 7 |
| Registry | `Microsoft.Win32.RegistryKey.SetValue` | 60 | 2 |
| Cryptography | `System.Security.Cryptography.CryptoStream..ctor` | 55 | 9 |
| NativeInterop | `System.Runtime.InteropServices.SafeHandle..ctor` | 55 | 7 |
| ReflectionInvocation | `System.Reflection.PropertyInfo.SetValue` | 55 | 7 |
| Cryptography | `System.Security.Cryptography.Oid.FromOidValue` | 54 | 2 |
| Cryptography | `System.Security.Cryptography.X509Certificates.X509Store.Open` | 54 | 4 |

## Reflection targets

- Analyzed reflection sites with a target: 2,624
- type resolved (Constant or OneOf): 209 (7.965%)
- member resolved: 236 (8.994%)
- with own ByName candidates: 9 (0.343%); with a candidates gap: 0

## Cost and the defaults (AC5)

| Wall time, sum over packages | ms |
|---|---:|
| worker pass, SSA off (first) | 310,379 |
| worker pass, SSA off (last) | 314,355 |
| worker pass, SSA on | 504,372 |
| worker pass, SSA on, repeat | 502,571 |
| worker pass, the faster off against the faster on, per package | 301,019 against 489,931 |
| join child, whole process | 1,032,295 |
| join child, graphs | 269,258 |
| join child, every method lifted and joined | 535,021 |
| join child, product facts (sink methods only; SSA's own cost) | 157,044 |

- slowest packages with SSA on (budget 600 s): StackExchange.Redis 3.1.13 26,389 ms (off 18,582); coverlet.collector 10.0.1 22,024 ms (off 12,270); Microsoft.Extensions.ApiDescription.Server 10.0.11 21,057 ms (off 17,063); Microsoft.Data.SqlClient 7.0.2 19,065 ms (off 11,447); Microsoft.Identity.Client 4.87.0 17,455 ms (off 10,524)
- slowest folders' product facts in the child (worker backstop 60 s, folder timeout 120 s): coverlet.collector 10.0.1 build/net8.0 2,212 ms; System.Drawing.Common 10.0.11 lib/net10.0 2,121 ms; coverlet.collector 10.0.1 build/net9.0 2,103 ms; coverlet.collector 10.0.1 build/net10.0 1,918 ms; System.Drawing.Common 10.0.11 lib/net9.0 1,722 ms
- peak worker working set with SSA on: 700 MB (Microsoft.Extensions.ApiDescription.Server 10.0.11); peak private 785 MB; with SSA off 723 MB (limit 4,096 MB)
- peak join child working set (graph data held while every method lifts): 881 MB (Microsoft.Extensions.ApiDescription.Server 10.0.11)
- largest folder facts: 2,008,017 chars of JSON (System.Drawing.Common 10.0.11 lib/net10.0); per package at most 6,663,907 (SSA record budget 134,217,728 bytes, record line limit 16,777,216 bytes)
- most sites in a folder: 3,098 (MaxSites 8,192); most methods lifted for sinks: 2,144 (MaxLiftedMethods 50,000)
- folders cut: truncated 0, method budget 0, time budget 0, text budget 0
- largest observed: arguments 8 (MaxArguments 8), OneOf 4 (MaxAlternatives 4), constant text 160 chars (MaxTextChars 256, plus the cut suffix), candidates 4 (MaxCandidates 64), site name 502 chars (MaxNameChars 1024, plus the cut suffix); ill-formed strings 0

## Determinism (AC6)

- SSA on, twice, over separate extractions: equal 517, n/a 6
- worker facts against the join child's in-process facts: equal 517, n/a 6

## S5 presentation

`ReachabilitySummary.From` of the off, on and repeat passes above, serialized with the report's own JSON options (indented,
enums by name), as scan-package `--json` writes its `Reachability` member (there nested one level deeper, so a few
bytes of indentation more). Section lines are the terminal section's logical lines, estimated from the summary as
`SsaSectionRenderer` writes them (title rule, count line; per listed folder its header, the copy line, its first 10
sites each with its `acts on` line, one `N more site(s) ... in --json` line past them, the summary caps' dropped line,
each gap); a terminal narrower than a line wraps it. Sites listed below are the summary's (`--json`), not the terminal's.

- packages with a presentation: 100 of 100; not measured or failed: 
- additive (the on summary without its `Ssa` objects is byte for byte the off summary): 100; mismatches: 0; `Complete` differs: 0
- determinism, the on and repeat summaries' `Ssa` parts: equal 100

| Summary bytes per package | Max | p95 | Total |
|---|---:|---:|---:|
| without SSA | 188,525 | 74,227 | 1,838,353 |
| with SSA | 441,824 | 280,051 | 5,597,387 |
| of which the `Ssa` objects | 338,886 | 167,983 | 3,759,034 |
| terminal section lines | 140 | 104 | 3,117 |

- sites listed: 6,316 in all, at most 585 in a package (coverlet.collector 10.0.1); not listed (caps): 377
- largest summary with SSA: coverlet.collector 10.0.1; longest section: System.Text.Json 10.0.11
- packages with a folder past the per-folder cap (100): 3 (7 folder(s)); past the per-package cap (1,000): 0
- folders: 523; with SSA 523; analysed copies (listed under their primary) 27
- SSA-incomplete folders: 96, in 29 package(s); folders by gap kind (a folder may have several): method-unknown 90, not-analysed:NotRun 6

