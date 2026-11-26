using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("Silvergun.PackageAnalysis.NuGet.Tests")]
// The MCP server reuses the worker containment (Job Object, parent watch, line reader, launch resolution): ADR 0039 D2.
[assembly: InternalsVisibleTo("Silvergun.MCPServer")]
