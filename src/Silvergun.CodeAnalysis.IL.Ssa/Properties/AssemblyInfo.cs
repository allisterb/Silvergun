using System.Runtime.CompilerServices;

// The adapter's tests live in the IL test project (a project reference there; no new test project, so no new packages).
[assembly: InternalsVisibleTo("Silvergun.CodeAnalysis.IL.Tests")]
