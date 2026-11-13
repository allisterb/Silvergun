# SSA facts, S4.5, benign-top.manifest, Release, 2026-11-13

Measured by the benign-corpus harness `--ssa` (docs/agent/tasks/ssa-facts-s4.md, S4.5). Per cached package: the `ssa-join`
child (every folder's graph, every method lifted and joined to the graph's call-site edges by node id and IL offset, then
the product path's facts in a fresh session), and `PackageReachability.Analyze` through the real `Silvergun.CLI` worker
with default options: SSA off, on (`SsaFactBounds.Default`), and on again over a second extraction.

- manifest: `benign-top.manifest`, hash `9e5635c320485af7b86e5656860465e4c1bc5ba753e7771336e7d677ac8838a6`, 100 entr(ies)
- cache: `%LOCALAPPDATA%\Silvergun\benign-corpus` (read only; nothing downloaded); results: `%LOCALAPPDATA%\Silvergun\ssa-s45\c100-release`
- build: Release, identity `commit b2645476ce703cc7b93006aa8fcbc155a986b869-dirty, assemblies 5df85c23ae653447b351b3def38f3fbe6ad345927343d8f55f4f015a1856c7cb`
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

- sink sites: 55,180; kept: 55,180; truncated folders: 0
- by status: Analyzed 54,192, MethodUnknown 988
- Analyzed with at least one Constant or OneOf argument: 6,631 (12.236% of Analyzed)
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
| worker pass, SSA off (first) | 273,620 |
| worker pass, SSA off (last) | 280,822 |
| worker pass, SSA on | 423,806 |
| worker pass, SSA on, repeat | 424,782 |
| worker pass, the faster off against the faster on, per package | 263,174 against 415,448 |
| join child, whole process | 818,913 |
| join child, graphs | 231,103 |
| join child, every method lifted and joined | 412,649 |
| join child, product facts (sink methods only; SSA's own cost) | 108,917 |

- slowest packages with SSA on (budget 600 s): coverlet.collector 10.0.1 22,803 ms (off 14,675); StackExchange.Redis 3.1.13 22,418 ms (off 16,135); Newtonsoft.Json 13.0.4 15,502 ms (off 10,252); System.Security.Cryptography.Pkcs 10.0.11 14,299 ms (off 8,517); Microsoft.Extensions.ApiDescription.Server 10.0.11 13,876 ms (off 10,509)
- slowest folders' product facts in the child (worker backstop 60 s, folder timeout 120 s): System.Drawing.Common 10.0.11 lib/net10.0 2,265 ms; coverlet.collector 10.0.1 build/net10.0 1,654 ms; coverlet.collector 10.0.1 build/net8.0 1,595 ms; coverlet.collector 10.0.1 build/net9.0 1,480 ms; System.Drawing.Common 10.0.11 lib/net8.0 1,372 ms
- peak worker working set with SSA on: 726 MB (Microsoft.Extensions.ApiDescription.Server 10.0.11); peak private 805 MB; with SSA off 641 MB (limit 4,096 MB)
- peak join child working set (graph data held while every method lifts): 1,007 MB (Microsoft.Extensions.ApiDescription.Server 10.0.11)
- largest folder facts: 2,008,017 chars of JSON (System.Drawing.Common 10.0.11 lib/net10.0); per package at most 6,663,907 (SSA record budget 134,217,728 bytes, record line limit 16,777,216 bytes)
- most sites in a folder: 3,098 (MaxSites 8,192); most methods lifted for sinks: 2,144 (MaxLiftedMethods 50,000)
- folders cut: truncated 0, method budget 0, time budget 0, text budget 0
- largest observed: arguments 8 (MaxArguments 8), OneOf 4 (MaxAlternatives 4), constant text 160 chars (MaxTextChars 256, plus the cut suffix), candidates 4 (MaxCandidates 64), site name 502 chars (MaxNameChars 1024, plus the cut suffix); ill-formed strings 0

## Determinism (AC6)

- SSA on, twice, over separate extractions: equal 517, n/a 6
- worker facts against the join child's in-process facts: equal 517, n/a 6

