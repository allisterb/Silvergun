# Recall levers 1, benign-top.manifest, Debug, 2026-11-15

Measured by the benign-corpus harness `--levers` (docs/agent/tasks/recall-levers-1.md, L2). Per cached package: one
`PackageReachability.Analyze` pass through the real `Silvergun.CLI` worker with SSA on (`SsaFactBounds.Default`), then
`ReachabilitySummary.From`. Counts and names only: the verdict by §4's rule is not made here.

- manifest: `benign-top.manifest`, hash `9e5635c320485af7b86e5656860465e4c1bc5ba753e7771336e7d677ac8838a6`, 100 entr(ies)
- cache: `%LOCALAPPDATA%\Silvergun\benign-corpus` (read only; nothing downloaded); results: `%LOCALAPPDATA%\Silvergun\levers\c100`
- build: Debug, identity `commit c1802dfed8825ef81762f696f0903cc68a64a3f6-dirty, assemblies 74db7551731eb6850e8eca2f880c30e6e61d7d16f09d431a74becab9b6b4f11e`
- packages: 100; with a report: 100; folders: 523; packages whose summary dropped statements: 0
- **problems: 0**

A **floor** package is one where the cell or signal did not fire but could have: a folder was not analysed, a class was
Unknown, the profiles were cut, the summary dropped statements, or SSA was incomplete or absent in a folder. A package with no
report is a floor for everything. *Worst case* is fired plus floor.

## Co-reach cells (class x collection + Network x label)

| Cell | Measured | Fired | Floor | Worst case | Fired in |
|---|---:|---:|---:|---:|---|
| TypeInitializer EnvironmentProbe+Network Direct | 100 | 9 | 5 | 14 | AWSSDK.Core 4.0.101.1, Azure.Core 1.61.0, Grpc.Net.Client 2.83.0, Microsoft.Azure.Amqp 2.7.4, Microsoft.Data.SqlClient 7.0.2, Microsoft.Extensions.ApiDescription.Server 10.0.11, Npgsql 10.0.3, StackExchange.Redis 3.1.13, System.ClientModel 1.15.0 |
| TypeInitializer EnvironmentProbe+Network Deferred | 100 | 8 | 5 | 13 | AWSSDK.Core 4.0.101.1, Azure.Core 1.61.0, Grpc.Net.Client 2.83.0, Microsoft.Azure.Amqp 2.7.4, Microsoft.Data.SqlClient 7.0.2, Microsoft.Extensions.ApiDescription.Server 10.0.11, Npgsql 10.0.3, StackExchange.Redis 3.1.13 |
| TypeInitializer FileSystem+Network Direct | 100 | 4 | 6 | 10 | AWSSDK.Core 4.0.101.1, Microsoft.Data.SqlClient 7.0.2, Npgsql 10.0.3, StackExchange.Redis 3.1.13 |
| TypeInitializer FileSystem+Network Deferred | 100 | 5 | 6 | 11 | AWSSDK.Core 4.0.101.1, Microsoft.Data.SqlClient 7.0.2, Npgsql 10.0.3, Pipelines.Sockets.Unofficial 2.3.1, StackExchange.Redis 3.1.13 |
| Finalizer EnvironmentProbe+Network Direct | 100 | 3 | 6 | 9 | AWSSDK.Core 4.0.101.1, Microsoft.Data.SqlClient 7.0.2, StackExchange.Redis 3.1.13 |
| Finalizer EnvironmentProbe+Network Deferred | 100 | 1 | 7 | 8 | StackExchange.Redis 3.1.13 |
| Finalizer FileSystem+Network Direct | 100 | 3 | 6 | 9 | AWSSDK.Core 4.0.101.1, Microsoft.Data.SqlClient 7.0.2, StackExchange.Redis 3.1.13 |
| Finalizer FileSystem+Network Deferred | 100 | 1 | 7 | 8 | StackExchange.Redis 3.1.13 |
| NativeEntry EnvironmentProbe+Network Direct | 100 | 0 | 6 | 6 | - |
| NativeEntry EnvironmentProbe+Network Deferred | 100 | 0 | 6 | 6 | - |
| NativeEntry FileSystem+Network Direct | 100 | 0 | 6 | 6 | - |
| NativeEntry FileSystem+Network Deferred | 100 | 0 | 6 | 6 | - |
| HostContract EnvironmentProbe+Network Direct | 100 | 0 | 5 | 5 | - |
| HostContract EnvironmentProbe+Network Deferred | 100 | 0 | 5 | 5 | - |
| HostContract FileSystem+Network Direct | 100 | 0 | 5 | 5 | - |
| HostContract FileSystem+Network Deferred | 100 | 0 | 5 | 5 | - |
| LoadTime EnvironmentProbe+Network Direct | 100 | 0 | 5 | 5 | - |
| LoadTime EnvironmentProbe+Network Deferred | 100 | 0 | 5 | 5 | - |
| LoadTime FileSystem+Network Direct | 100 | 0 | 5 | 5 | - |
| LoadTime FileSystem+Network Deferred | 100 | 0 | 5 | 5 | - |

Floor packages per cell are in `-cells.tsv` (`floor` yes, `fired` no).

## Value signals

| Signal | Measured | Packages fired | Sites | Floor | Worst case | Fired in |
|---|---:|---:|---:|---:|---:|---|
| ShellInterpreter | 100 | 2 | 16 | 27 | 29 | AWSSDK.Core 4.0.101.1, Microsoft.Identity.Client 4.87.0 |
| StealthArguments | 100 | 0 | 0 | 29 | 29 | - |
| ExecutableMemory | 100 | 0 | 0 | 29 | 29 | - |
| SecretEnvironmentName | 100 | 5 | 148 | 25 | 30 | AWSSDK.Core 4.0.101.1, Azure.Core 1.61.0, Microsoft.Identity.Client 4.87.0, Npgsql 10.0.3, StackExchange.Redis 3.1.13 |

## Signal sites (the summary's listed sites; all in `-examples.tsv`)

164 listed site(s) with a signal in 5 package(s). The sites past the summary's caps are counted above, not listed.

| Package | Signal | Folder | Callee | Call |
|---|---|---|---|---|
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_WEB_IDENTITY_TOKEN_FILE")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_FULL_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SHARED_CREDENTIALS_FILE")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_FULL_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SECRET_KEY")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SESSION_TOKEN")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SECRET_KEY")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SESSION_TOKEN")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SECRET_KEY")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SESSION_TOKEN")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_FULL_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_AUTHORIZATION_TOKEN")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net472 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_FULL_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_WEB_IDENTITY_TOKEN_FILE")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_FULL_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SHARED_CREDENTIALS_FILE")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_FULL_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SECRET_KEY")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SESSION_TOKEN")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SECRET_KEY")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SESSION_TOKEN")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SECRET_KEY")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SESSION_TOKEN")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_FULL_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_AUTHORIZATION_TOKEN")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/net8.0 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_FULL_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/netcoreapp3.1 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_WEB_IDENTITY_TOKEN_FILE")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/netcoreapp3.1 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/netcoreapp3.1 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_FULL_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/netcoreapp3.1 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SHARED_CREDENTIALS_FILE")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/netcoreapp3.1 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/netcoreapp3.1 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_CONTAINER_CREDENTIALS_FULL_URI")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/netcoreapp3.1 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/netcoreapp3.1 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SECRET_KEY")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/netcoreapp3.1 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/netcoreapp3.1 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SESSION_TOKEN")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/netcoreapp3.1 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID")` |
| AWSSDK.Core 4.0.101.1 | SecretEnvironmentName | lib/netcoreapp3.1 | `System.Environment.GetEnvironmentVariable(System.String)` | `System.Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY")` |
| ... 104 more | | | | |

## Constant-bearing sinks (Analyzed sites with a Constant or OneOf argument; all 314 in `-constant-sinks.tsv`)

The same rule and format as `--ssa`'s: diff the TSV against a committed `ssa-facts-<manifest>-<configuration>-<date>-constant-sinks.tsv` to see what folding moved.

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

