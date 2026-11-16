# Hidden payloads 1: benign base rates, benign-top-ext.manifest (C100+), Debug, 2026-11-16

Provenance: `data/corpus/benign-top-ext.manifest` (100 entries, download ranks 98-223). All 100 exited 0. The one embedded PE is EO.WebBrowser's `GetAssVersion.exe` helper (a commercial browser control). each entry scanned from the local benign-corpus package cache (`%LOCALAPPDATA%\Silvergun\benign-corpus\packages`), downloaded 2026-11-16 from `https://api.nuget.org/v3-flatcontainer/` at 1 request/s with a zip-magic check (163 downloads, 1.67 GB, no refusals; 5 already cached), with `scan-package <nupkg> --json --no-yara --no-vulns --allow-incomplete` (offline), one guarded run per package, on the working tree after `docs/agent/tasks/hidden-payloads-1.md` review round 4. Manifest selection and request counts: `data/corpus/PROVENANCE.md`, "Expansion, 2026-11-16". Each package keeps its own licence; only ids, versions and finding rows are recorded here. Package names, resource names and paths below are third-party data, tab/newline-cleaned and cut; per-finding rows are in the `-findings.tsv` beside this file. Informational base rates: obfuscation findings never gate.

- reports read: 100; unreadable: 0
- packages with any obfuscation finding: 34 (34%)
- packages with any non-image finding (the attention headline): 34 (34%)

| Kind | Source | Packages | % | Findings | DetectedAs |
|---|---|---:|---:|---:|---|
| EncodedArchive | FieldData | 2 | 2% | 4 | gzip (4) |
| EncodedArchive | Resource | 1 | 1% | 5 | zip (5) |
| EncodedExecutable | Resource | 1 | 1% | 2 | Windows PE (2) |
| EncodedImage | FieldData | 1 | 1% | 2 | PNG (1), GIF (1) |
| EncodedImage | Resource | 1 | 1% | 4 | ICO (3), GIF (1) |
| EncodedText | Constant | 3 | 3% | 12 | UTF-8 text (12) |
| HighEntropyBlob | Constant | 30 | 30% | 685 | high-entropy base64 (685) |

## Packages per cell

- EncodedArchive/FieldData: EO.WebBrowser.26.3.58, SharpZipLib.1.4.2
- EncodedArchive/Resource: TimeZoneConverter.8.0.1
- EncodedExecutable/Resource: EO.WebBrowser.26.3.58
- EncodedImage/FieldData: SixLabors.ImageSharp.4.1.3
- EncodedImage/Resource: EO.WebBrowser.26.3.58
- EncodedText/Constant: BouncyCastle.Cryptography.2.7.0, EO.WebBrowser.26.3.58, Portable.BouncyCastle.1.9.0
- HighEntropyBlob/Constant: AWSSDK.Polly.4.1.0, AWSSDK.SQS.4.1.0, AWSSDK.SecurityToken.4.1.0, Autofac.9.3.4, Azure.Messaging.ServiceBus.7.21.0, Bogus.35.6.5, DocumentFormat.OpenXml.3.5.1, EO.WebBrowser.26.3.58, EntityFramework.6.5.2, FluentValidation.AspNetCore.11.3.1, Hangfire.Core.1.8.25, MediatR.15.0.0, Microsoft.AspNet.Mvc.5.3.0, Microsoft.AspNetCore.Mvc.Testing.11.0.0, Microsoft.CodeAnalysis.Workspaces.MSBuild.5.12.0, Microsoft.Testing.Platform.2.5.3, Microsoft.Testing.Platform.MSBuild.2.5.3, Microsoft.VisualStudio.Azure.Containers.Tools.Targets.1.23.0, MongoDB.Driver.3.14.0, MongoDB.Driver.Core.2.30.0, NUnit3TestAdapter.6.3.1, NodaTime.3.3.7, Npgsql.EntityFrameworkCore.PostgreSQL.10.0.3, RabbitMQ.Client.7.2.2, RestSharp.114.1.0, SixLabors.Fonts.3.2.0, SixLabors.ImageSharp.4.1.3, System.IO.Packaging.11.0.0, System.Management.11.0.0, System.Reactive.7.0.0
