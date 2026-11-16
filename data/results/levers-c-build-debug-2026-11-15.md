# Recall levers 1, c-build.manifest, Debug, 2026-11-15

Measured by the benign-corpus harness `--levers` (docs/agent/tasks/recall-levers-1.md, L2). Per cached package: one
`PackageReachability.Analyze` pass through the real `Silvergun.CLI` worker with SSA on (`SsaFactBounds.Default`), then
`ReachabilitySummary.From`. Counts and names only: the verdict by §4's rule is not made here.

- manifest: `c-build.manifest`, hash `cd9ade3633e1e3eb87e51a887afd08550769a7043e12b8e10ce148e4b74a6af0`, 50 entr(ies)
- cache: `%LOCALAPPDATA%\Silvergun\benign-corpus` (read only; nothing downloaded); results: `%LOCALAPPDATA%\Silvergun\levers\cbuild`
- build: Debug, identity `commit c1802dfed8825ef81762f696f0903cc68a64a3f6-dirty, assemblies 74db7551731eb6850e8eca2f880c30e6e61d7d16f09d431a74becab9b6b4f11e`
- packages: 50; with a report: 50; folders: 505; packages whose summary dropped statements: 0
- **problems: 0**

A **floor** package is one where the cell or signal did not fire but could have: a folder was not analysed, a class was
Unknown, the profiles were cut, the summary dropped statements, or SSA was incomplete or absent in a folder. A package with no
report is a floor for everything. *Worst case* is fired plus floor.

## Co-reach cells (class x collection + Network x label)

| Cell | Measured | Fired | Floor | Worst case | Fired in |
|---|---:|---:|---:|---:|---|
| TypeInitializer EnvironmentProbe+Network Direct | 50 | 7 | 4 | 11 | NSwag.MSBuild 14.7.1, OpenCover 4.7.1221, ReportGenerator 5.5.12, Reqnroll.Tools.MsBuild.Generation 3.3.4, SpecFlow.Tools.MsBuild.Generation 3.9.74, Xamarin.AndroidX.Migration 1.0.10, dotnet-sonarscanner 12.1.0 |
| TypeInitializer EnvironmentProbe+Network Deferred | 50 | 7 | 4 | 11 | NSwag.MSBuild 14.7.1, OpenCover 4.7.1221, ReportGenerator 5.5.12, Reqnroll.Tools.MsBuild.Generation 3.3.4, SpecFlow.Tools.MsBuild.Generation 3.9.74, Xamarin.AndroidX.Migration 1.0.10, dotnet-sonarscanner 12.1.0 |
| TypeInitializer FileSystem+Network Direct | 50 | 7 | 4 | 11 | NSwag.MSBuild 14.7.1, OpenCover 4.7.1221, ReportGenerator 5.5.12, Reqnroll.Tools.MsBuild.Generation 3.3.4, SpecFlow.Tools.MsBuild.Generation 3.9.74, Xamarin.AndroidX.Migration 1.0.10, dotnet-sonarscanner 12.1.0 |
| TypeInitializer FileSystem+Network Deferred | 50 | 7 | 4 | 11 | NSwag.MSBuild 14.7.1, OpenCover 4.7.1221, ReportGenerator 5.5.12, Reqnroll.Tools.MsBuild.Generation 3.3.4, SpecFlow.Tools.MsBuild.Generation 3.9.74, Xamarin.AndroidX.Migration 1.0.10, dotnet-sonarscanner 12.1.0 |
| Finalizer EnvironmentProbe+Network Direct | 50 | 5 | 3 | 8 | NSwag.MSBuild 14.7.1, OpenCover 4.7.1221, Reqnroll.Tools.MsBuild.Generation 3.3.4, SpecFlow.Tools.MsBuild.Generation 3.9.74, dotnet-sonarscanner 12.1.0 |
| Finalizer EnvironmentProbe+Network Deferred | 50 | 2 | 5 | 7 | SpecFlow.Tools.MsBuild.Generation 3.9.74, Xamarin.AndroidX.Migration 1.0.10 |
| Finalizer FileSystem+Network Direct | 50 | 6 | 3 | 9 | NSwag.MSBuild 14.7.1, OpenCover 4.7.1221, Reqnroll.Tools.MsBuild.Generation 3.3.4, SpecFlow.Tools.MsBuild.Generation 3.9.74, Xamarin.AndroidX.Migration 1.0.10, dotnet-sonarscanner 12.1.0 |
| Finalizer FileSystem+Network Deferred | 50 | 2 | 5 | 7 | SpecFlow.Tools.MsBuild.Generation 3.9.74, Xamarin.AndroidX.Migration 1.0.10 |
| NativeEntry EnvironmentProbe+Network Direct | 50 | 0 | 6 | 6 | - |
| NativeEntry EnvironmentProbe+Network Deferred | 50 | 0 | 6 | 6 | - |
| NativeEntry FileSystem+Network Direct | 50 | 0 | 6 | 6 | - |
| NativeEntry FileSystem+Network Deferred | 50 | 0 | 6 | 6 | - |
| HostContract EnvironmentProbe+Network Direct | 50 | 6 | 6 | 12 | ReportGenerator 5.5.12, Reqnroll.Tools.MsBuild.Generation 3.3.4, SpecFlow.Tools.MsBuild.Generation 3.9.74, Xamarin.AndroidX.Migration 1.0.10, Xamarin.Build.Download 0.11.6, dotnet-sonarscanner 12.1.0 |
| HostContract EnvironmentProbe+Network Deferred | 50 | 4 | 7 | 11 | SpecFlow.Tools.MsBuild.Generation 3.9.74, Xamarin.AndroidX.Migration 1.0.10, Xamarin.Build.Download 0.11.6, dotnet-sonarscanner 12.1.0 |
| HostContract FileSystem+Network Direct | 50 | 6 | 6 | 12 | ReportGenerator 5.5.12, Reqnroll.Tools.MsBuild.Generation 3.3.4, SpecFlow.Tools.MsBuild.Generation 3.9.74, Xamarin.AndroidX.Migration 1.0.10, Xamarin.Build.Download 0.11.6, dotnet-sonarscanner 12.1.0 |
| HostContract FileSystem+Network Deferred | 50 | 4 | 7 | 11 | SpecFlow.Tools.MsBuild.Generation 3.9.74, Xamarin.AndroidX.Migration 1.0.10, Xamarin.Build.Download 0.11.6, dotnet-sonarscanner 12.1.0 |
| LoadTime EnvironmentProbe+Network Direct | 50 | 0 | 8 | 8 | - |
| LoadTime EnvironmentProbe+Network Deferred | 50 | 0 | 8 | 8 | - |
| LoadTime FileSystem+Network Direct | 50 | 0 | 8 | 8 | - |
| LoadTime FileSystem+Network Deferred | 50 | 0 | 8 | 8 | - |

Floor packages per cell are in `-cells.tsv` (`floor` yes, `fired` no).

## Value signals

| Signal | Measured | Packages fired | Sites | Floor | Worst case | Fired in |
|---|---:|---:|---:|---:|---:|---|
| ShellInterpreter | 50 | 0 | 0 | 31 | 31 | - |
| StealthArguments | 50 | 0 | 0 | 31 | 31 | - |
| ExecutableMemory | 50 | 0 | 0 | 31 | 31 | - |
| SecretEnvironmentName | 50 | 1 | 1 | 30 | 31 | NSwag.MSBuild 14.7.1 |

## Signal sites (the summary's listed sites; all in `-examples.tsv`)

1 listed site(s) with a signal in 1 package(s). The sites past the summary's caps are counted above, not listed.

| Package | Signal | Folder | Callee | Call |
|---|---|---|---|---|
| NSwag.MSBuild 14.7.1 | SecretEnvironmentName | tools/Win | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("DOTNET_USER_SECRETS_FALLBACK_DIR")` |

## Constant-bearing sinks (Analyzed sites with a Constant or OneOf argument; all 332 in `-constant-sinks.tsv`)

The same rule and format as `--ssa`'s: diff the TSV against a committed `ssa-facts-<manifest>-<configuration>-<date>-constant-sinks.tsv` to see what folding moved.

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

