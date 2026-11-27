namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Silvergun.CodeAnalysis.IL;
using Silvergun.MCPServer.Jobs;

/// <summary>
/// <see cref="MethodListing.Render"/> over the emitted S3 fixture, in-process, with the inspect worker's display function
/// (task S3, <c>disassemble</c>): a known method's listing exactly (Accept); paging by IL offset that shows every instruction
/// once and always advances; handlers on their own page when they do not fit; a bounded switch and locals; array
/// pseudo-ops as calls; not found; no body; an unreadable body; hostile names and constants escaped.
/// </summary>
public sealed class MethodListingTests : IDisposable
{
    #region Methods
    /// <summary>
    /// Accept: "A known fixture method's IL comes out exactly". <c>Inspect.Listing.Sample</c> is emitted by
    /// <see cref="InspectFixtures"/> as: ldarg.0; ldc.i4.0; ble.s skip; ldstr "positive"; call Console.WriteLine(string);
    /// skip: ldarg.0; stloc.0 inside a try, whose catch (Exception) pops and stores -1; then ldloc.0; ret. ILGenerator adds the
    /// two <c>leave</c>s (5 bytes each) to the end label. Offsets: 0 ldarg.0 (1), 1 ldc.i4.0 (1), 2 ble.s (2), 4 ldstr (5),
    /// 9 call (5), 0xe ldarg.0, 0xf stloc.0, 0x10 leave (5), 0x15 pop, 0x16 ldc.i4.m1, 0x17 stloc.0, 0x18 leave (5), 0x1d
    /// ldloc.0, 0x1e ret: 31 bytes. The tokens are the emitted module's: Console.WriteLine is its second MemberRef, Exception
    /// its fifth TypeRef. CCI gives the short forms their implied operand (<c>ldc.i4.0 0</c>, <c>stloc.0 V_0</c>).
    /// </summary>
    [Fact]
    public void Render_TheSampleMethod_IsExactlyItsIl()
    {
        var page = Render(Token("Sample"));

        Assert.Equal(
            """
            .method Inspect.Listing.Sample(System.Int32)  // token 0x06000002
            .size 31  .maxstack 2  .locals 1 init
              V_0: System.Int32
            IL_0000: ldarg.0 x
            IL_0001: ldc.i4.0 0
            IL_0002: ble.s IL_000e
            IL_0004: ldstr "positive"
            IL_0009: call [0x0a000002] System.Console.WriteLine(System.String)
            IL_000e: ldarg.0 x
            IL_000f: stloc.0 V_0
            IL_0010: leave IL_001d
            IL_0015: pop
            IL_0016: ldc.i4.m1 -1
            IL_0017: stloc.0 V_0
            IL_0018: leave IL_001d
            IL_001d: ldloc.0 V_0
            IL_001e: ret
            .try IL_0000 to IL_0015 catch [0x01000005] System.Exception handler IL_0015 to IL_001d
            """.ReplaceLineEndings("\n"), page.Text);
        Assert.True(page.Found);
        Assert.Equal((MemberBody.Il, 31u, 2, 1, 14, 14), (page.Body, page.IlBytes, page.MaxStack, page.Locals, page.Instructions, page.Shown));
        Assert.Null(page.Next);
        Assert.Equal(("Inspect.Listing", "Sample", "Inspect.Listing.Sample(System.Int32)"), (page.Type, page.Name, page.Id));
    }

    /// <summary>The tokens in a listing are the operands' own: the call's MemberRef and the catch's TypeRef resolve to those members.</summary>
    [Fact]
    public void Render_OperandTokens_AreTheReferencedMembersOwnTokens()
    {
        var page = Render(Token("Sample"));
        var module = (Microsoft.Cci.ITokenDecoder)clean.Module;

        var call = Assert.IsAssignableFrom<Microsoft.Cci.IMethodReference>(module.GetObjectForToken(0x0a000002));
        Assert.Equal("WriteLine", call.Name.Value);
        var type = Assert.IsAssignableFrom<Microsoft.Cci.ITypeReference>(module.GetObjectForToken(0x01000005));
        Assert.Equal("System.Exception", AssemblyAnalyzer.TypeName(type));
        Assert.Contains("[0x0a000002]", page.Text);
    }

    /// <summary>A call into the package carries a MethodDef token that names the callee, so it can be disassembled in turn.</summary>
    [Fact]
    public void Render_ACallIntoThePackage_CarriesTheCalleesMethodDefToken()
    {
        var page = Render(InspectFixtures.Token(hostile, Hostile3.TypeName, Hostile3.MethodName), on: hostile);
        var callee = InspectFixtures.Token(hostile, Hostile3.TypeName, Hostile3.CalleeName);

        var line = Assert.Single(page.Text.Split('\n'), l => l.Contains("call [0x06", StringComparison.Ordinal));
        Assert.Contains($"[0x{callee:x8}]", line);
        Assert.True(Render(callee, on: hostile).Found);
    }

    [Theory]
    [InlineData("Long", 8_000)]
    [InlineData("Long", 9_600)]
    [InlineData("Switch", 1_500)]
    [InlineData("Handlers", 3_200)]
    [InlineData("Sample", 400)]
    public void Render_PagingByNext_ShowsEveryInstructionExactlyOnce_AndAlwaysAdvances(string method, int maxChars)
    {
        var token = Token(method);
        var whole = Render(token, maxChars: int.MaxValue);
        Assert.Null(whole.Next);
        var expected = Instructions(whole.Text);
        Assert.Equal(whole.Instructions, expected.Count);

        var (pages, shown) = Pages(token, maxChars);

        Assert.Equal(expected, shown);
        Assert.All(pages, p => Assert.Equal(whole.Instructions, p.Instructions));
        Assert.Equal(expected.Count, pages.Sum(p => p.Shown));
        if (method == "Long")
            Assert.True(pages.Count >= 5, $"{pages.Count} pages");
        Assert.All(pages, p => Assert.True(p.Text.Length <= maxChars, $"a page of {p.Text.Length} chars, over {maxChars}"));
        // The handlers, once, after the last instruction.
        Assert.Equal(Handlers(whole.Text), pages.SelectMany(p => Handlers(p.Text)).ToList());
    }

    /// <summary>
    /// When the handlers do not fit after the last instruction, the page ends there and <c>next</c> is the IL size: the
    /// handlers come on a page of their own, with the header and no instruction. Swept over budgets so some page ends exactly
    /// so, whatever the line lengths are.
    /// </summary>
    [Fact]
    public void Render_HandlersThatDoNotFit_ComeOnAPageOfTheirOwn()
    {
        var token = Token("Handlers");
        var whole = Render(token, maxChars: int.MaxValue);
        var handlers = Handlers(whole.Text);
        Assert.Equal(InspectFixtures.HandlerCount, handlers.Count);
        var seen = 0;

        // From the least budget whose own page holds all 30 handlers (about 88 chars each, after the header and the note room).
        for (var maxChars = 3_000; maxChars < 9_000; maxChars += 37)
        {
            var (pages, shown) = Pages(token, maxChars);
            Assert.Equal(Instructions(whole.Text), shown);
            Assert.Equal(handlers, pages.SelectMany(p => Handlers(p.Text)).ToList());
            var own = pages.Where(p => Handlers(p.Text).Count > 0).ToList();
            Assert.Single(own);
            if (own[0].Shown == 0)
            {
                seen++;
                var before = pages[pages.IndexOf(own[0]) - 1];
                Assert.Equal(whole.IlBytes, before.Next);
                Assert.Equal(Header(whole.Text), Header(own[0].Text));
            }
        }
        Assert.True(seen > 0, "no budget put the handlers on a page of their own");
    }

    /// <summary>Handlers beyond what their own page holds are counted, never silently dropped (they are not paged further).</summary>
    [Fact]
    public void Render_HandlersBeyondTheirOwnPage_AreCounted()
    {
        var token = Token("Handlers");
        var whole = Render(token, maxChars: int.MaxValue);

        var page = Render(token, from: whole.IlBytes, maxChars: 1_000);

        var shown = Handlers(page.Text);
        Assert.InRange(shown.Count, 1, InspectFixtures.HandlerCount - 1);
        Assert.Equal(Handlers(whole.Text).Take(shown.Count), shown);
        Assert.EndsWith($"// {InspectFixtures.HandlerCount - shown.Count} more exception handlers not shown", page.Text);
        Assert.Equal(InspectFixtures.HandlerCount - shown.Count, page.HandlersNotShown);
        Assert.Equal(0, whole.HandlersNotShown);
        Assert.Null(page.Next);
        Assert.True(page.Text.Length <= 1_000);
    }

    /// <summary>
    /// S3 review W4: handlers past the listing's cap of 64 are counted too. With room for every line, 80 handlers show 64
    /// and count exactly 16; paged at the least budget, only the closing page counts them, and it counts the same 16.
    /// </summary>
    [Fact]
    public void Render_MoreThan64Handlers_CountsTheOnesPastTheCap()
    {
        var token = InspectFixtures.Token(clean, InspectFixtures.GuardedType, "Guarded");
        var notShown = InspectFixtures.ManyHandlerCount - 64;

        var whole = Render(token, maxChars: int.MaxValue);

        Assert.Equal(64, Handlers(whole.Text).Count);
        Assert.Equal(notShown, whole.HandlersNotShown);
        Assert.EndsWith($"\n// {notShown} more exception handlers not shown", whole.Text);
        Assert.Equal(4 * InspectFixtures.ManyHandlerCount + 1, whole.Instructions);

        var (pages, _) = Pages(token, InspectProtocol.MinChars);
        Assert.All(pages.SkipLast(1), p => Assert.Equal(0, p.HandlersNotShown));
        Assert.Equal(notShown, pages[^1].HandlersNotShown);
        Assert.Equal(Handlers(whole.Text), pages.SelectMany(p => Handlers(p.Text)).ToList());
    }

    [Fact]
    public void Render_AtTheIlSize_IsTheHandlersAlone()
    {
        var token = Token("Sample");

        var page = Render(token, from: 31);

        Assert.Equal(0, page.Shown);
        Assert.Null(page.Next);
        Assert.Empty(Instructions(page.Text));
        Assert.Single(Handlers(page.Text));
    }

    [Fact]
    public void Render_FromAnOffsetInsideAnInstruction_StartsAtTheNextInstruction()
    {
        var page = Render(Token("Sample"), from: 5);

        Assert.StartsWith("IL_0009: call", Instructions(page.Text)[0]);
        Assert.Equal(10, page.Shown);
    }

    [Fact]
    public void Render_ASwitch_ShowsAtMost32Targets_AndCountsTheRest()
    {
        var text = Render(Token("Switch")).Text;

        var line = Assert.Single(text.Split('\n'), l => l.Contains(": switch ", StringComparison.Ordinal));
        Assert.Equal(32, Regex.Matches(line, "IL_[0-9a-f]{4}").Count - 1);
        Assert.EndsWith($", ... {InspectFixtures.SwitchTargets - 32} more)", line);
        Assert.StartsWith("IL_0001: switch (IL_00a8, IL_00aa,", line);
    }

    [Fact]
    public void Render_Locals_AreAtMost16_EachTypeCut_WithTheTotal()
    {
        var page = Render(Token("Locals"));
        var lines = page.Text.Split('\n');

        Assert.Equal(InspectFixtures.LocalCount, page.Locals);
        Assert.Contains($".locals {InspectFixtures.LocalCount} init", lines[1]);
        var locals = lines.Where(l => l.StartsWith("  V_", StringComparison.Ordinal)).ToList();
        Assert.Equal(16, locals.Count);
        Assert.Contains($"  // {InspectFixtures.LocalCount - 16} more locals", lines);
        Assert.StartsWith("  V_0: Inspect.LongLLL", locals[0]);
        Assert.Contains("sha256:", locals[0]);
        Assert.True(locals[0].Length < "  V_0: ".Length + 128 + 40, $"the long local type is {locals[0].Length} chars");
        Assert.Equal("  V_15: System.String", locals[15]);
    }

    [Fact]
    public void Render_ArrayPseudoOps_AreShownAsTheCallsTheyReplace()
    {
        var instructions = Instructions(Render(Token("Arrays")).Text);

        Assert.Contains("IL_0002: newobj System.Int32[,]::.ctor", instructions);
        Assert.Contains("IL_000c: call System.Int32[,]::Set", instructions);
        Assert.Contains("IL_0014: call System.Int32[,]::Get", instructions);
        Assert.Contains("IL_001d: call System.Int32[,]::Address", instructions);
    }

    [Theory]
    [InlineData(0x06FFFFFFu)]
    [InlineData(0x06000000u)]
    [InlineData(0x02000002u)]
    [InlineData(0x0a000002u)]
    public void Render_ATokenThatIsNoMethodOfTheAssembly_IsNotFound(uint token)
    {
        var page = Render(token);

        Assert.False(page.Found);
        Assert.Equal("", page.Text);
        Assert.Null(page.Next);
        Assert.Null(page.Type);
    }

    [Theory]
    [InlineData(InspectFixtures.ShapeType, "Area", ".method Inspect.Shape.Area()  // token 0x06000013")]
    [InlineData(InspectFixtures.SpecialType, "Beep", ".method Inspect.Special.Beep(System.UInt32,System.UInt32)  // token 0x0600000d")]
    public void Render_AMethodWithNoBody_IsItsHeaderAndANote(string type, string name, string header)
    {
        var page = Render(InspectFixtures.Token(clean, type, name));

        Assert.True(page.Found);
        Assert.Equal(MemberBody.None, page.Body);
        Assert.Equal(header + "\n// no IL body (abstract, extern, a P/Invoke or a runtime method)", page.Text);
        Assert.Equal((0u, 0, 0), (page.IlBytes, page.Instructions, page.Shown));
        Assert.Null(page.Next);
    }

    [Fact]
    public void Render_AnUnreadableBody_IsItsHeaderAndANote()
    {
        var page = MethodListing.Render(patched, InspectFixtures.Token(patched, InspectFixtures.BodiesType, "Broken"), 0, InspectProtocol.MinChars, InspectFixtures.Display);

        Assert.True(page.Found);
        Assert.Equal(MemberBody.Unreadable, page.Body);
        Assert.Equal(".method Inspect.Bodies.Broken()  // token 0x06000026\n// the body could not be read", page.Text);
    }

    /// <summary>Names and constants come out escaped by the display function: no raw hostile code point, and the server's own bulk check holds.</summary>
    [Fact]
    public void Render_HostileNamesAndConstants_AreEscaped_AndTheServersCheckHolds()
    {
        foreach (var name in new[] { Hostile3.MethodName, Hostile3.CalleeName })
        {
            var page = Render(InspectFixtures.Token(hostile, Hostile3.TypeName, name), on: hostile);

            Hostile3.AssertDisplayable(page.Text, name);
            foreach (var s in new[] { page.Type!, page.Name!, page.Id! })
            {
                Hostile3.AssertDisplayable(s, "a name");
                Assert.DoesNotContain('\n', s);
            }
            Assert.Contains(Backslash + "u202e", page.Text);
            Assert.Contains(Backslash + "u061c", page.Text);
            Assert.Contains(Backslash + "ufe0f", page.Text);
            Assert.Contains(Backslash + "U000E0100", page.Text);
            Assert.Contains(Backslash + "U000E0041", page.Text);
            // A package newline is an escape; the listing's own lines are the only real ones.
            Assert.All(page.Text.Split('\n'), l => Assert.Matches(@"^(\.method |\.size |  V_|  // |IL_[0-9a-f]{4}: |\.try |// )", l));
        }
    }

    public void Dispose()
    {
        clean.Dispose();
        patched.Dispose();
        hostile.Dispose();
        dirs.Dispose();
    }
    #endregion

    #region Methods: helpers
    private uint Token(string method) => InspectFixtures.Token(clean, InspectFixtures.ListingType, method);

    private MethodListingPage Render(uint token, uint from = 0, int maxChars = InspectProtocol.MaxChars, AssemblyAnalyzer? on = null) =>
        MethodListing.Render(on ?? clean, token, from, maxChars, InspectFixtures.Display);

    // Every page from offset 0, following next; asserts next always moves on.
    private (List<MethodListingPage> Pages, List<string> Shown) Pages(uint token, int maxChars)
    {
        var pages = new List<MethodListingPage>();
        var shown = new List<string>();
        uint? from = 0;
        while (from is { } at)
        {
            var page = Render(token, at, maxChars);
            Assert.True(page.Found);
            pages.Add(page);
            var lines = Instructions(page.Text);
            Assert.Equal(page.Shown, lines.Count);
            shown.AddRange(lines);
            if (page.Next is { } next)
            {
                Assert.True(next > at, $"next {next} does not move on from {at}");
                Assert.True(next <= page.IlBytes, $"next {next} is past the IL size {page.IlBytes}");
            }
            from = page.Next;
            Assert.True(pages.Count < 1_000, "paging does not end");
        }
        return (pages, shown);
    }

    private static List<string> Instructions(string text) => [.. text.Split('\n').Where(l => Regex.IsMatch(l, "^IL_[0-9a-f]{4}: "))];

    private static List<string> Handlers(string text) => [.. text.Split('\n').Where(l => l.StartsWith(".try ", StringComparison.Ordinal))];

    private static string Header(string text) => string.Join("\n", text.Split('\n').TakeWhile(l => !l.StartsWith("IL_", StringComparison.Ordinal) && !l.StartsWith(".try", StringComparison.Ordinal)));
    #endregion

    #region Fields
    private const string Backslash = @"\";

    private readonly TestDirs dirs = new();
    private readonly AssemblyAnalyzer clean;
    private readonly AssemblyAnalyzer patched;
    private readonly AssemblyAnalyzer hostile;
    #endregion

    #region Constructors
    public MethodListingTests()
    {
        clean = InspectFixtures.Load(InspectFixtures.Write(dirs.Base));
        patched = InspectFixtures.Load(InspectFixtures.Write(dirs.Base, unreadable: true, name: "Inspect.Patched.dll"));
        hostile = InspectFixtures.Load(InspectFixtures.WriteHostile(dirs.Base));
    }
    #endregion
}
