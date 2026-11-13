# SSA facts, S4.5, c-build.manifest, Release, 2026-11-13

Measured by the benign-corpus harness `--ssa` (docs/agent/tasks/ssa-facts-s4.md, S4.5). Per cached package: the `ssa-join`
child (every folder's graph, every method lifted and joined to the graph's call-site edges by node id and IL offset, then
the product path's facts in a fresh session), and `PackageReachability.Analyze` through the real `Silvergun.CLI` worker
with default options: SSA off, on (`SsaFactBounds.Default`), and on again over a second extraction.

- manifest: `c-build.manifest`, hash `cd9ade3633e1e3eb87e51a887afd08550769a7043e12b8e10ce148e4b74a6af0`, 50 entr(ies)
- cache: `%LOCALAPPDATA%\Silvergun\benign-corpus` (read only; nothing downloaded); results: `%LOCALAPPDATA%\Silvergun\ssa-s45\cbuild-release`
- build: Release, identity `commit b2645476ce703cc7b93006aa8fcbc155a986b869-dirty, assemblies 5df85c23ae653447b351b3def38f3fbe6ad345927343d8f55f4f015a1856c7cb`
- packages: 50; folders: 505; join-child folders: 505
- **problems: 0**

## Additivity (AC1)

- folders compared: 505; identical with SSA off and on (outcome, serialized report, assemblies, load failures, reason, SameAs, size): 505
- graph outcomes with SSA on: Analyzed 503, NothingLoaded 2
- SSA outcomes: Analyzed 503, NotRun 2

## The per-site join (AC4), every method lifted

| Measure | Count | Rate |
|---|---:|---:|
| Method definitions with a body | 936,133 | |
| Lifted | 852,089 | 91.022% |
| Lifted, node id an own graph node (node-id join) | 852,068 | 99.998% |
| Unknown | 84,044 | |
| Unknown, node id an own graph node | 84,044 | 100.000% |
| Own graph nodes with a body | 901,241 | |
| ... with an SSA outcome under their node id | 901,227 | 99.998% |
| SSA call sites (call, newobj, ldftn, ldvirtftn) of lifted methods in the graph | 3,154,289 | |
| ... joined to an edge of the same kind group and callee key | 3,153,814 | 99.985% |
| ... and of the same exact kind (call vs callvirt) | 3,153,814 | 100.000% |
| Edge sites (node, offset, kind group) of own nodes | 3,802,452 | |
| ... of nodes with a lifted definition (checked) | 3,075,054 | 80.870% |
| ... ... joined to an SSA site | 3,073,146 | 99.938% |
| ... ... with more than one callee (Ambiguous) | 3,465 | |
| ... of nodes with only Unknown definitions (not checked) | 727,376 | 19.129% |
| ... of nodes with no SSA outcome (a miss class) | 22 | |
| Graph-truncated folders | 0 | |
| Folders where SSA lost an assembly | 0 | |

Misses by class (examples in the `-join-examples.tsv`):

| Class | Count | Folders | Explained |
|---|---:|---:|---|
| `edge:initialize-array-intrinsic` | 1,858 | 84 | yes |
| `edge:node-not-in-ssa(pointer-as-byref)` | 22 | 2 | yes |
| `edge:node-partly-lifted` | 50 | 1 | yes |
| `method:lifted-node-not-in-graph(module-type)` | 7 | 6 | yes |
| `method:lifted-node-not-in-graph(pointer-as-byref)` | 14 | 2 | yes |
| `site:no-edge(md-array-accessor)` | 475 | 22 | yes |
- folders whose graph is not the join child's: 0; product facts misaligned with their raw sites: 0

## Sink coverage (worker, SSA on)

- sink sites: 39,811; kept: 39,811; truncated folders: 0
- by status: Analyzed 38,962, MethodUnknown 849
- Analyzed with at least one Constant or OneOf argument: 10,285 (26.398% of Analyzed)
- MethodUnknown by failure kind (methods lifted for sinks): UnresolvedFact 289
- NotJoined by reason: 

Top constant-bearing sinks (Analyzed sites with a Constant or OneOf argument; counts only; all 332 in the `-constant-sinks.tsv`):

| Capability | Callee | Sites | Packages |
|---|---|---:|---:|
| DynamicCodeLoading | `Microsoft.CSharp.RuntimeBinder.CSharpArgumentInfo.Create` | 2,877 | 3 |
| EnvironmentProbe | `System.Environment.GetEnvironmentVariable` | 725 | 18 |
| DynamicCodeLoading | `Microsoft.CSharp.RuntimeBinder.Binder.GetMember` | 708 | 2 |
| DynamicCodeLoading | `Microsoft.CSharp.RuntimeBinder.Binder.BinaryOperation` | 456 | 1 |
| FileSystem | `System.IO.FileStream..ctor` | 453 | 17 |
| DynamicCodeLoading | `Microsoft.CSharp.RuntimeBinder.Binder.UnaryOperation` | 428 | 1 |
| DynamicCodeLoading | `Microsoft.CSharp.RuntimeBinder.Binder.Convert` | 412 | 1 |
| DynamicCodeLoading | `Microsoft.CSharp.RuntimeBinder.Binder.InvokeMember` | 303 | 2 |
| ReflectionInvocation | `System.Reflection.MethodBase.Invoke` | 221 | 18 |
| ReflectionInvocation | `System.Type.GetType` | 209 | 22 |
| ReflectionInvocation | `System.Reflection.MethodInfo.CreateDelegate` | 130 | 13 |
| NativeInterop | `System.Runtime.InteropServices.Marshal.SetLastSystemError` | 129 | 1 |
| DynamicCodeLoading | `System.Reflection.Emit.DynamicMethod..ctor` | 114 | 8 |
| ReflectionInvocation | `System.Reflection.PropertyInfo.GetValue` | 114 | 10 |
| EnvironmentProbe | `System.Environment.GetFolderPath` | 109 | 13 |
| FileSystem | `System.IO.File.Copy` | 109 | 8 |
| Cryptography | `System.Security.Cryptography.Oid..ctor` | 86 | 1 |
| ReflectionInvocation | `System.Reflection.PropertyInfo.SetValue` | 84 | 9 |
| UnsafeMemory | `System.Runtime.InteropServices.GCHandle.Alloc` | 82 | 15 |
| Cryptography | `System.Security.Cryptography.SymmetricAlgorithm.set_KeySize` | 77 | 1 |
| FileSystem | `System.IO.File.Open` | 74 | 13 |
| Cryptography | `System.Security.Cryptography.CryptographicException..ctor` | 68 | 10 |
| DynamicCodeLoading | `System.Activator.CreateInstance` | 67 | 8 |
| FileSystem | `System.IO.Directory.GetFiles` | 66 | 10 |
| ProcessExecution | `System.Diagnostics.ProcessStartInfo.set_RedirectStandardOutput` | 59 | 12 |

## Reflection targets

- Analyzed reflection sites with a target: 2,688
- type resolved (Constant or OneOf): 233 (8.668%)
- member resolved: 259 (9.635%)
- with own ByName candidates: 9 (0.335%); with a candidates gap: 0

## Cost and the defaults (AC5)

| Wall time, sum over packages | ms |
|---|---:|
| worker pass, SSA off (first) | 377,907 |
| worker pass, SSA off (last) | 385,954 |
| worker pass, SSA on | 497,097 |
| worker pass, SSA on, repeat | 504,902 |
| worker pass, the faster off against the faster on, per package | 356,933 against 484,504 |
| join child, whole process | 870,760 |
| join child, graphs | 333,714 |
| join child, every method lifted and joined | 391,199 |
| join child, product facts (sink methods only; SSA's own cost) | 76,042 |

- slowest packages with SSA on (budget 600 s): SpecFlow.Tools.MsBuild.Generation 3.9.74 49,276 ms (off 39,273); Microsoft.Net.Compilers 4.2.0 47,312 ms (off 36,566); NSwag.MSBuild 14.7.1 37,073 ms (off 37,281); Microsoft.Maui.Controls.Build.Tasks 10.0.120 30,018 ms (off 20,408); coverlet.msbuild 10.1.0 25,902 ms (off 15,268)
- slowest folders' product facts in the child (worker backstop 60 s, folder timeout 120 s): Microsoft.Net.Compilers 4.2.0 tools 2,928 ms; Microsoft.Maui.Controls.Build.Tasks 10.0.120 buildTransitive/netstandard2.0 2,891 ms; NSwag.MSBuild 14.7.1 tools/Win 2,646 ms; dotnet-reportgenerator-globaltool 5.5.12 tools/net10.0/any 2,624 ms; SpecFlow.Tools.MsBuild.Generation 3.9.74 tasks/net461 2,242 ms
- peak worker working set with SSA on: 2,779 MB (Microsoft.Net.Compilers 4.2.0); peak private 2,858 MB; with SSA off 2,369 MB (limit 4,096 MB)
- peak join child working set (graph data held while every method lifts): 3,107 MB (Microsoft.Net.Compilers 4.2.0)
- largest folder facts: 2,177,787 chars of JSON (NSwag.MSBuild 14.7.1 tools/Win); per package at most 7,183,413 (SSA record budget 134,217,728 bytes, record line limit 16,777,216 bytes)
- most sites in a folder: 2,832 (MaxSites 8,192); most methods lifted for sinks: 1,137 (MaxLiftedMethods 50,000)
- folders cut: truncated 0, method budget 0, time budget 0, text budget 0
- largest observed: arguments 8 (MaxArguments 8), OneOf 2 (MaxAlternatives 4), constant text 287 chars (MaxTextChars 256, plus the cut suffix), candidates 2 (MaxCandidates 64), site name 806 chars (MaxNameChars 1024, plus the cut suffix); ill-formed strings 0

## Determinism (AC6)

- SSA on, twice, over separate extractions: equal 503, n/a 2
- worker facts against the join child's in-process facts: equal 503, n/a 2

