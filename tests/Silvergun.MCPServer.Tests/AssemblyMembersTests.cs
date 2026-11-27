namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Microsoft.Cci;

using Silvergun.CodeAnalysis.IL;

/// <summary>
/// <see cref="AssemblyMembers.Read"/> over the emitted S3 fixture (task S3, <c>list_members</c> and <c>search_strings</c>):
/// MethodDef tokens, unique and sorted; the <c>special</c> flags and their near misses; the three body kinds; distinct
/// strings with first offset and occurrences; call sites named exactly as capability findings name them; and a corrupted
/// body that costs that one method only.
/// </summary>
public sealed class AssemblyMembersTests : IDisposable
{
    #region Methods
    [Fact]
    public void Read_TokensAreMethodDefs_UniqueAndSorted_OneRowPerMethodDefinition()
    {
        var (members, unreadable, problem) = AssemblyMembers.Read(clean);

        Assert.Null(problem);
        Assert.Equal(0, unreadable);
        Assert.All(members, m => Assert.Equal(0x06u, m.Token >> 24));
        Assert.Equal(members.Select(m => m.Token).Order(), members.Select(m => m.Token));
        Assert.Equal(members.Count, members.Select(m => m.Token).Distinct().Count());
        // Every MethodDef row, 1..n, and nothing else (the module's <Module> type has no methods here).
        Assert.Equal(Enumerable.Range(1, members.Count).Select(i => 0x06000000u | (uint)i), members.Select(m => m.Token));
        var defs = clean.Module.GetAllTypes().SelectMany(t => t.Methods).Count();
        Assert.Equal(defs, members.Count);
    }

    [Fact]
    public void Token_IsTheMethodDefToken_AndNullForAMethodWithNone()
    {
        var method = clean.Module.GetAllTypes().SelectMany(t => t.Methods).First(m => m.Name.Value == "Sample");

        Assert.Equal(InspectFixtures.Token(clean, InspectFixtures.ListingType, "Sample"), AssemblyMembers.Token(method));
        Assert.Null(AssemblyMembers.Token(Dummy.MethodDefinition));
    }

    public static TheoryData<string, string, string?, MemberSpecial> Specials() => new()
    {
        { InspectFixtures.SpecialType, ".ctor", null, MemberSpecial.Constructor },
        { InspectFixtures.ShapeType, ".ctor", null, MemberSpecial.Constructor },
        { InspectFixtures.SpecialType, ".cctor", null, MemberSpecial.TypeInitializer },
        { InspectFixtures.SpecialType, "Finalize", "Finalize()", MemberSpecial.Finalizer },
        { InspectFixtures.SpecialType, "Finalize", "Finalize(System.Int32)", MemberSpecial.None },
        { InspectFixtures.SpecialType, "Beep", null, MemberSpecial.PInvoke },
        { InspectFixtures.SpecialType, "Exported", null, MemberSpecial.NativeExport },
        { InspectFixtures.SpecialType, "Plain", null, MemberSpecial.None },
        { InspectFixtures.SpecialType, "Virtual", null, MemberSpecial.None },
        { InspectFixtures.ShapeType, "Area", null, MemberSpecial.None },
        { InspectFixtures.ListingType, "Sample", null, MemberSpecial.None },
    };

    [Theory]
    [MemberData(nameof(Specials))]
    public void Read_TheSpecialFlag_IsTheMethodsMetadataFact(string type, string name, string? idEnd, MemberSpecial special)
    {
        var member = Member(clean, type, name, idEnd);

        Assert.Equal(special, member.Special);
    }

    [Fact]
    public void Read_FlagsAndVisibility_AreTheMetadatas()
    {
        var area = Member(clean, InspectFixtures.ShapeType, "Area");
        Assert.True(area.IsAbstract && area.IsVirtual && !area.IsStatic);
        Assert.Equal(TypeMemberVisibility.Public, area.Visibility);

        var hidden = Member(clean, InspectFixtures.SpecialType, "Hidden");
        Assert.True(hidden.IsStatic && !hidden.IsVirtual && !hidden.IsAbstract);
        Assert.Equal(TypeMemberVisibility.Private, hidden.Visibility);

        Assert.Equal(TypeMemberVisibility.Family, Member(clean, InspectFixtures.ShapeType, ".ctor").Visibility);
        Assert.True(Member(clean, InspectFixtures.SpecialType, "Virtual").IsVirtual);
        Assert.False(Member(clean, InspectFixtures.SpecialType, "Plain").IsStatic);
    }

    [Fact]
    public void Read_BodyKinds_AreIlNoneAndUnreadable_WithIlBytes()
    {
        var (members, unreadable, problem) = AssemblyMembers.Read(patched);

        Assert.Null(problem);
        Assert.Equal(1, unreadable);
        var sample = Member(patched, InspectFixtures.ListingType, "Sample");
        Assert.Equal((MemberBody.Il, 31u), (sample.Body, sample.IlBytes));
        Assert.Equal((MemberBody.None, 0u), (Member(patched, InspectFixtures.ShapeType, "Area").Body, Member(patched, InspectFixtures.ShapeType, "Area").IlBytes));
        Assert.Equal(MemberBody.None, Member(patched, InspectFixtures.SpecialType, "Beep").Body);
        var broken = Member(patched, InspectFixtures.BodiesType, "Broken");
        Assert.Equal((MemberBody.Unreadable, 0u), (broken.Body, broken.IlBytes));
        Assert.Empty(broken.CalledApis);
        Assert.Empty(broken.Strings);
        Assert.Single(members, m => m.Body == MemberBody.Unreadable);
    }

    /// <summary>A corrupted body costs that method's facts only: every other member reads exactly as from the clean file.</summary>
    [Fact]
    public void Read_AnUnreadableBody_CostsOneMethod_TheRestAreUnchanged()
    {
        var before = AssemblyMembers.Read(clean).Members;
        var after = AssemblyMembers.Read(patched).Members;

        Assert.Equal(before.Count, after.Count);
        var brokenToken = Member(clean, InspectFixtures.BodiesType, "Broken").Token;
        foreach (var (b, a) in before.Zip(after))
        {
            Assert.Equal(b.Token, a.Token);
            if (b.Token == brokenToken)
            {
                Assert.Equal((MemberBody.Il, MemberBody.Unreadable), (b.Body, a.Body));
                Assert.Equal((b.Type, b.Name, b.Id, b.Visibility, b.IsStatic, b.Special), (a.Type, a.Name, a.Id, a.Visibility, a.IsStatic, a.Special));
                continue;
            }
            Assert.Equal((b.Type, b.Name, b.Id, b.Visibility, b.IsStatic, b.IsVirtual, b.IsAbstract, b.Special, b.Body, b.IlBytes),
                (a.Type, a.Name, a.Id, a.Visibility, a.IsStatic, a.IsVirtual, a.IsAbstract, a.Special, a.Body, a.IlBytes));
            Assert.Equal(b.CalledApis.Order(), a.CalledApis.Order());
            Assert.Equal(b.Strings, a.Strings);
        }
    }

    [Fact]
    public void Read_Strings_AreDistinct_WithTheirFirstOffsetAndOccurrences_InOffsetOrder()
    {
        var strings = Member(clean, InspectFixtures.ListingType, "Strings").Strings;

        Assert.Equal([new MethodString("a", 0x00, 3), new MethodString("b", 0x06, 1)], strings);
    }

    [Fact]
    public void Read_Strings_OfALongMethod_AreEveryDistinctConstantOnce()
    {
        var strings = Member(clean, InspectFixtures.ListingType, "Long").Strings;

        Assert.Equal(InspectFixtures.LongPairs, strings.Count);
        Assert.All(strings, s => Assert.Equal(1, s.Occurrences));
        // Each ldstr/pop pair is six bytes.
        Assert.Equal(Enumerable.Range(0, InspectFixtures.LongPairs).Select(i => (uint)(i * 6)), strings.Select(s => s.Offset));
        Assert.Equal($"line 0007 " + new string('x', 40), strings[7].Text);
    }

    [Fact]
    public void Read_HostileNamesAndConstants_AreKeptRaw_TheyAreEscapedWhereServed()
    {
        using var hostile = InspectFixtures.Load(InspectFixtures.WriteHostile(dirs.Base));

        var evil = Member(hostile, Hostile3.TypeName, Hostile3.MethodName);

        Assert.Equal(["cmd.exe /c " + Hostile3.Mix, "https://evil.example/" + Hostile3.Mix], evil.Strings.Select(s => s.Text));
        Assert.Contains(Hostile3.TypeName + "." + Hostile3.CalleeName, evil.CalledApis);
        Assert.Equal(Hostile3.TypeName + "." + Hostile3.MethodName + "()", evil.Id);
    }

    /// <summary>
    /// The join a finding's caller tokens rest on: every capability finding of a call site names a CalledApi that its
    /// caller's members (by type and name) carry. P/Invoke and native-export findings are matched by their special flag.
    /// </summary>
    [Fact]
    public void Read_CalledApis_NameCallSitesAsCapabilityFindingsDo()
    {
        var members = AssemblyMembers.Read(clean).Members;
        var report = new CapabilityAnalysis(clean).Analyze();
        Assert.True(report.IsSuccess, report.Message);
        var findings = report.Value.Findings;
        Assert.True(findings.Count >= 8, $"{findings.Count} findings");

        foreach (var f in findings)
        {
            var callers = members.Where(m => m.Type == f.CallerType && m.Name == f.CallerMethod).ToList();
            Assert.True(callers.Count > 0, $"no member is the caller {f.CallerType}::{f.CallerMethod}");
            if (f.Kind == ApiCallKind.NativeImport)
                Assert.Contains(callers, m => m.Special == MemberSpecial.PInvoke);
            else if (f.Kind == ApiCallKind.NativeExport)
                Assert.Contains(callers, m => m.Special == MemberSpecial.NativeExport);
            else
                Assert.True(callers.Any(m => m.CalledApis.Contains(f.CalledApi)), $"{f.CallerMethod}: no overload calls {f.CalledApi}");
        }
        // The narrowing evidence is per overload: Go(int) starts a process, Go(string) reads a file.
        Assert.Equal(["System.Diagnostics.Process.Start"], Member(clean, InspectFixtures.OverloadsType, "Go", "(System.Int32)").CalledApis);
        Assert.Equal(["System.IO.File.ReadAllText"], Member(clean, InspectFixtures.OverloadsType, "Go", "(System.String)").CalledApis);
        Assert.Contains(findings, f => f.CallerMethod == "Go" && f.CalledApi == "System.IO.File.ReadAllText");
    }

    [Fact]
    public void Read_TheCap_StopsTheList_AndSaysSo()
    {
        var (members, _, problem) = AssemblyMembers.Read(clean, maxMembers: 5);

        Assert.Equal(5, members.Count);
        Assert.Contains("more than 5", problem);
        Assert.Equal(members.Select(m => m.Token).Order(), members.Select(m => m.Token));
    }

    public void Dispose()
    {
        clean.Dispose();
        patched.Dispose();
        dirs.Dispose();
    }
    #endregion

    #region Methods: helpers
    private static MemberFacts Member(AssemblyAnalyzer assembly, string type, string name, string? idEnd = null) =>
        Assert.Single(AssemblyMembers.Read(assembly).Members, m => m.Type == type && m.Name == name && (idEnd is null || m.Id.EndsWith(idEnd, StringComparison.Ordinal)));
    #endregion

    #region Fields
    private readonly TestDirs dirs = new();
    private readonly AssemblyAnalyzer clean;
    private readonly AssemblyAnalyzer patched;
    #endregion

    #region Constructors
    public AssemblyMembersTests()
    {
        clean = InspectFixtures.Load(InspectFixtures.Write(dirs.Base));
        patched = InspectFixtures.Load(InspectFixtures.Write(dirs.Base, unreadable: true, name: "Inspect.Patched.dll"));
    }
    #endregion
}
