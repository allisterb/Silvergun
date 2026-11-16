# Hidden payloads 1: benign base rates, benign-top.manifest (C100), Debug, 2026-11-16

Provenance: `data/corpus/benign-top.manifest` (100 entries), each scanned from the local benign-corpus package cache
(`%LOCALAPPDATA%\Silvergun\benign-corpus\packages`, fetched earlier from nuget.org; nothing was downloaded for this run)
with `scan-package <nupkg> --json --no-yara --no-vulns --allow-incomplete` (offline), one guarded run per package, on the
working tree after `docs/agent/tasks/hidden-payloads-1.md` review round 4. All 100 exited 0. Package names and file paths
below are third-party data, tab/newline-cleaned and cut; per-finding rows are in the `-findings.tsv` beside this file.
Informational base rates: obfuscation findings never gate.

- reports read: 100; unreadable: 0
- packages with any obfuscation finding: 30 (30%)
- packages with any non-image finding (the attention headline): 30 (30%)

| Kind | Source | Packages | % | Findings | DetectedAs |
|---|---|---:|---:|---:|---|
| EncodedArchive | Resource | 2 | 2% | 43 | gzip (42), zip (1) |
| EncodedImage | Resource | 1 | 1% | 3 | ICO (3) |
| EncodedText | Constant | 1 | 1% | 200 | UTF-8 text (200) |
| HighEntropyBlob | Constant | 29 | 29% | 1769 | high-entropy base64 (1769) |

## Packages per cell

- EncodedArchive/Resource: Microsoft.Azure.Amqp.2.7.4, Swashbuckle.AspNetCore.SwaggerUI.10.2.3
- EncodedImage/Resource: System.Drawing.Common.10.0.11
- EncodedText/Constant: Google.Protobuf.3.35.1
- HighEntropyBlob/Constant: AWSSDK.Core.4.0.101.1, AWSSDK.S3.4.0.102.2, AutoMapper.16.2.0, Azure.Storage.Blobs.12.29.1, Azure.Storage.Common.12.28.0, Castle.Core.5.2.1, FluentValidation.12.1.1, Google.Protobuf.3.35.1, Grpc.Net.Client.2.83.0, Microsoft.Azure.Amqp.2.7.4, Microsoft.Azure.WebJobs.3.0.47, Microsoft.Data.SqlClient.7.0.2, Microsoft.EntityFrameworkCore.10.0.11, Microsoft.Extensions.ApiDescription.Server.10.0.11, Microsoft.Extensions.Diagnostics.HealthChecks.10.0.11, Microsoft.Identity.Client.4.87.0, Microsoft.IdentityModel.Clients.ActiveDirectory.5.3.0, Microsoft.OpenApi.3.10.0, Moq.4.20.72, NUnit.4.6.1, Npgsql.10.0.3, Serilog.4.4.0, StackExchange.Redis.3.1.13, System.CodeDom.10.0.11, System.Diagnostics.EventLog.10.0.11, System.Drawing.Common.10.0.11, System.Text.Json.10.0.11, System.Windows.Extensions.10.0.11, coverlet.collector.10.0.1
