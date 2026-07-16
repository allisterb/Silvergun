namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.IO;
using System.Linq;

using Silvergun;
using Silvergun.CodeAnalysis.IL;

using Xunit;

/// <summary>
/// Behavioural tests for <see cref="AssemblyMetadata.Read(string, bool)"/> and the serializable
/// <see cref="AssemblyMetadataInfo"/>/<see cref="AssemblyReferenceInfo"/> records. Reuses
/// <see cref="AnalyzerFixture"/> only to initialize the Silvergun runtime once; metadata is read
/// directly from deterministic assemblies present in the test output directory
/// (<c>Silvergun.Runtime.dll</c> and the fixture dll). Covers the seven cases in the
/// assembly-metadata-reader spec.
/// </summary>
public sealed class AssemblyMetadataTests : IClassFixture<AnalyzerFixture>
{
    #region Constructors
    // The fixture is injected only to guarantee Runtime.Initialize has run once for this class.
    public AssemblyMetadataTests(AnalyzerFixture fixture) => _ = fixture;
    #endregion

    #region Methods
    // Case 1 — happy path over a real IL-only library dll.
    [Fact]
    public void Read_OnRuntimeAssembly_ReturnsCoreModuleMetadata()
    {
        var info = ReadRuntime();

        Assert.Equal("Silvergun.Runtime", info.Name);
        Assert.True(info.IsILOnly, "Silvergun.Runtime is a managed IL-only assembly.");
        Assert.Contains("Library", info.ModuleKind, StringComparison.Ordinal);
        Assert.False(info.HasEntryPoint, "A library dll has no module entry point.");
        Assert.False(string.IsNullOrWhiteSpace(info.TargetRuntimeVersion));
    }

    // Case 2 — referenced-assembly identities are surfaced with versions.
    [Fact]
    public void Read_OnRuntimeAssembly_ListsReferencesWithVersions()
    {
        var info = ReadRuntime();

        Assert.NotEmpty(info.References);

        // Silvergun.Runtime references Serilog / Microsoft.Extensions.Logging.Abstractions and the
        // BCL facades — at least one known identity must be present with a non-null version.
        string[] expected =
        [
            "Serilog", "Microsoft.Extensions.Logging", "netstandard", "System."
        ];

        Assert.Contains(
            info.References,
            r => expected.Any(e => r.Name.StartsWith(e, StringComparison.Ordinal) ||
                                   r.Name.Contains(e, StringComparison.Ordinal))
                 && r.Version is not null);
    }

    // Case 3 — our assemblies are unsigned; PKT extraction still works for signed BCL references.
    [Fact]
    public void Read_OnUnsignedAssembly_ReportsNoStrongNameButExtractsReferencePkt()
    {
        var info = ReadRuntime();

        Assert.False(info.IsStrongNameSigned, "Silvergun.Runtime is not strong-name signed.");
        Assert.Null(info.PublicKeyToken);

        // Proof that PKT extraction works: signed BCL/facade references carry a lowercase-hex token.
        Assert.Contains(info.References, r => r.PublicKeyToken is not null);
        Assert.All(
            info.References.Where(r => r.PublicKeyToken is not null),
            r => Assert.Equal(r.PublicKeyToken, r.PublicKeyToken!.ToLowerInvariant()));
    }

    // Case 4 — custom-attribute intel captures attribute type full names.
    [Fact]
    public void Read_OnRuntimeAssembly_CustomAttributesContainTargetFramework()
    {
        var info = ReadRuntime();

        Assert.Contains(
            "System.Runtime.Versioning.TargetFrameworkAttribute",
            info.CustomAttributes);
    }

    // Case 5a — resolution is best-effort: any reference marked resolved must point at a real file.
    [Fact]
    public void Read_WithResolution_ResolvedReferencesPointAtExistingFiles()
    {
        var info = ReadRuntime(resolveReferences: true);

        Assert.All(
            info.References.Where(r => r.Resolved),
            r =>
            {
                Assert.NotNull(r.ResolvedPath);
                Assert.True(File.Exists(r.ResolvedPath), $"Resolved path does not exist: {r.ResolvedPath}");
            });
    }

    // Case 5b — resolution can be skipped; then nothing is resolved but references are still listed.
    [Fact]
    public void Read_WithoutResolution_ListsReferencesUnresolved()
    {
        var info = ReadRuntime(resolveReferences: false);

        Assert.NotEmpty(info.References);
        Assert.All(info.References, r =>
        {
            Assert.False(r.Resolved);
            Assert.Null(r.ResolvedPath);
        });
    }

    // Case 6a — a nonexistent path is a failure Result, never a throw.
    [Fact]
    public void Read_OnNonexistentPath_ReturnsFailureWithoutThrowing()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"silvergun-missing-{Guid.NewGuid():N}.dll");

        // The "never throws" contract: Read must surface the failure as a Result, not an exception.
        var ex = Record.Exception(() =>
        {
            var result = AssemblyMetadata.Read(missing);
            Assert.False(result.IsSuccess);
        });

        Assert.Null(ex);
    }

    // Case 6b — a non-PE file (plain text) is a failure Result, never a throw.
    [Fact]
    public void Read_OnNonPeFile_ReturnsFailureWithoutThrowing()
    {
        var textPath = Path.Combine(Path.GetTempPath(), $"silvergun-notpe-{Guid.NewGuid():N}.txt");
        File.WriteAllText(textPath, "this is not a portable executable");

        try
        {
            // The "never throws" contract: a non-PE file yields a failure Result, not an exception.
            var ex = Record.Exception(() =>
            {
                var result = AssemblyMetadata.Read(textPath);
                Assert.False(result.IsSuccess);
            });

            Assert.Null(ex);
        }
        finally
        {
            File.Delete(textPath);
        }
    }

    // Case 6c — the reference-resolution path itself never throws for a valid managed dll.
    [Fact]
    public void Read_WithResolution_OnValidAssembly_DoesNotThrowAndSucceeds()
    {
        var ex = Record.Exception(() =>
        {
            var result = AssemblyMetadata.Read(RuntimePath, resolveReferences: true);
            Assert.True(result.IsSuccess, result.Message);
        });

        Assert.Null(ex);
    }

    // Case 7 — JSON round-trip preserves scalar fields, custom attributes, and references element-wise.
    [Fact]
    public void AssemblyMetadataInfo_JsonRoundTrip_PreservesFieldsAndUsesEnumNames()
    {
        var info = ReadRuntime();

        var json = info.ToJson();
        var restored = AssemblyMetadataInfo.FromJson(json);

        Assert.NotNull(restored);

        // ModuleKind (enum-derived) is serialized as a string, not a bare number.
        Assert.Contains($"\"{info.ModuleKind}\"", json);

        // Scalar fields.
        Assert.Equal(info.Name, restored!.Name);
        Assert.Equal(info.Version, restored.Version);
        Assert.Equal(info.Culture, restored.Culture);
        Assert.Equal(info.PublicKeyToken, restored.PublicKeyToken);
        Assert.Equal(info.IsStrongNameSigned, restored.IsStrongNameSigned);
        Assert.Equal(info.ModuleKind, restored.ModuleKind);
        Assert.Equal(info.IsILOnly, restored.IsILOnly);
        Assert.Equal(info.Requires32Bit, restored.Requires32Bit);
        Assert.Equal(info.Requires64Bit, restored.Requires64Bit);
        Assert.Equal(info.RequiresAmdInstructionSet, restored.RequiresAmdInstructionSet);
        Assert.Equal(info.ContainsForeignTypes, restored.ContainsForeignTypes);
        Assert.Equal(info.HasEntryPoint, restored.HasEntryPoint);
        Assert.Equal(info.TargetRuntimeVersion, restored.TargetRuntimeVersion);
        Assert.Equal(info.DebugInformationLocation, restored.DebugInformationLocation);

        // Collections, element-wise (record equality over scalar members).
        Assert.Equal(info.CustomAttributes, restored.CustomAttributes);
        Assert.Equal(info.References, restored.References);
    }

    private AssemblyMetadataInfo ReadRuntime(bool resolveReferences = true)
    {
        var result = AssemblyMetadata.Read(RuntimePath, resolveReferences);
        Assert.True(result.IsSuccess, result.Message);
        return result.Value;
    }
    #endregion

    #region Fields
    private static readonly string RuntimePath = typeof(Silvergun.Runtime).Assembly.Location;
    #endregion
}
