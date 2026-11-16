namespace Silvergun.CLI.Tests.Behaviour;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// The 48 rows of the behaviour recall measurement (<c>docs/agent/tasks/behaviour-fixtures-recall.md</c> sections 3 and 5):
/// 29 malicious packages and 19 benign twins.
/// <para>
/// <see cref="BehaviourRow.Predicted"/> is the architect's section 5 table, copied and NEVER edited (its <c>Text</c> is the
/// cell verbatim, hashed against a pinned constant and checked against the spec when the spec is on disk).
/// <see cref="BehaviourRow.Measured"/> is pinned from the first run (<see cref="BehaviourMeasured"/>): a change in what the
/// CLI says, an improvement included, turns the theory red, and is recorded there. A twin's predicted gate is
/// <see cref="Verdict.Passes"/>, from section 5's "Twin gate rate: 0 of 19".
/// </para>
/// </summary>
public static class BehaviourGroundTruth
{
    #region Properties
    public static IReadOnlyList<BehaviourRow> Rows { get; } = Build();

    /// <summary>Malicious and twin package counts per family, so no row can disappear silently.</summary>
    public static IReadOnlyDictionary<string, (int Malicious, int Twins)> FamilyCounts { get; } = new Dictionary<string, (int, int)>
    {
        ["BF01"] = (2, 1), ["BF02"] = (1, 1), ["BF03"] = (1, 1), ["BF04"] = (1, 1), ["BF05"] = (1, 1), ["BF06"] = (1, 1),
        ["BF07"] = (3, 1), ["BF08"] = (4, 1), ["BF09"] = (1, 1), ["BF10"] = (1, 1), ["BF11"] = (1, 1), ["BF12"] = (4, 1),
        ["BF13"] = (1, 1), ["BF14"] = (1, 1), ["BF15"] = (1, 1), ["BF16"] = (1, 1), ["BF17"] = (1, 1), ["BF18"] = (1, 1),
        ["BF19"] = (2, 1),
    };
    #endregion

    #region Methods
    public static BehaviourRow Row(string key) => Rows.Single(r => r.Key == key);

    private static List<BehaviourRow> Build()
    {
        const string TargetsVector = "build-time, build/<id>.targets";
        const string Runtime = "runtime, lib/";
        var rows = new List<BehaviourRow>();

        // Malicious: id, vector, TTP, predicted gate, section 5 primary-signal cell verbatim, note.
        void Mal(string id, string vector, string ttp, Verdict gate, string cell, string note = "") =>
            rows.Add(Make(id, Side.Malicious, vector, ttp, gate, cell, note));
        // Twin: the family id, the section 5 twin cell verbatim.
        void Twin(string id, string vector, string ttp, string cell, string note = "") =>
            rows.Add(Make(id, Side.Twin, vector, ttp, Verdict.Passes, cell, note));

        const string Bf01Cell = "ScriptRule `SG0010` (any `<Exec>`); a cradle-specific rule `?`; Yara `?`";
        Mal("BF01a", TargetsVector, "TH16503-family script execution", Verdict.Passes, Bf01Cell);
        Mal("BF01b", TargetsVector, "TH16503-family script execution", Verdict.Passes, Bf01Cell);
        Twin("BF01", TargetsVector, "TH16503-family script execution", "yes (`SG0010` fires on any `<Exec>`)");

        Mal("BF02", TargetsVector, "inline MSBuild code (ROADMAP \"parse <UsingTask>... as XML\")", Verdict.Passes, "ScriptRule `?` (text rules over `<Code>`)");
        Twin("BF02", TargetsVector, "inline MSBuild code (ROADMAP \"parse <UsingTask>... as XML\")", "`?`");

        Mal("BF03", "install-time (legacy VS), tools/init.ps1", "TH16602-family", Verdict.Passes, "ScriptRule (an AppInspector download/execute rule on `.ps1`) `?`");
        Twin("BF03", "install-time (legacy VS), tools/init.ps1", "TH16602-family", "no");

        Mal("BF04", "build-time, an MSBuild task DLL in build/", "TH15104 search + network", Verdict.Passes, "ReachInfo HostContract → EnvironmentProbe and Network; Capability");
        Twin("BF04", "build-time, an MSBuild task DLL in build/", "TH15104 search + network", "yes (HostContract and Capability), not Network");

        Mal("BF05", "compile-time, an analyzer DLL in analyzers/dotnet/cs/", "TH15104 search + network", Verdict.Passes, "ReachInfo HostContract → FileSystem and Network");
        Twin("BF05", "compile-time, an analyzer DLL in analyzers/dotnet/cs/", "TH15104 search + network", "yes (HostContract), not Network");

        Mal("BF06", "load-time, [ModuleInitializer] in lib/", "TH15104 search", Verdict.Passes, "ReachInfo LoadTime → FileSystem and Network");
        Twin("BF06", "load-time, [ModuleInitializer] in lib/", "TH15104 search", "yes (LoadTime), not Network");

        const string CredentialCell = "Indicator `CredentialPath`";
        foreach (var id in new[] { "BF07a", "BF07b", "BF07c" })
            Mal(id, Runtime, "TH16122-TH16126", Verdict.Fails, CredentialCell);
        Twin("BF07", Runtime, "TH16122-TH16126", "no");

        const string ExfilCell = "Indicator `ExfilSink` (headline only)";
        Mal("BF08a", Runtime, "TH17xx URL IOCs, TH17126", Verdict.Passes, ExfilCell);
        Mal("BF08b", Runtime, "TH17xx URL IOCs, TH17126", Verdict.Passes, ExfilCell);
        Mal("BF08c", Runtime, "TH17xx URL IOCs, TH17126", Verdict.Fails, "Indicator `CallbackDomain`");
        Mal("BF08d", Runtime, "TH17xx URL IOCs, TH17126", Verdict.Fails, "Indicator `DynamicDns`, if the host is a tunnel-fronting domain the rule lists (`?` otherwise)");
        Twin("BF08", Runtime, "TH17xx URL IOCs, TH17126", "no");

        Mal("BF09", Runtime, "TH15104 execution", Verdict.Passes, "Indicator `RawCodeHost`; Capability DynamicCodeLoading");
        Twin("BF09", Runtime, "TH15104 execution", "twin: DynamicCodeLoading yes, RawCodeHost no");

        Mal("BF10", Runtime, "TH16111-TH16121 (constant-argument seam)", Verdict.Passes, "SsaSite `Process.Start(\"powershell\", \"-NoP -W Hidden -Enc …\")`; Obfuscation `?` on the `-Enc` base64",
            "The `?` resolved by hidden-payloads-1: Obfuscation EncodedText `UTF-16LE text` (Substring) on the `-Enc` base64.");
        Twin("BF10", Runtime, "TH16111-TH16121 (constant-argument seam)", "twin: SsaSite `Process.Start(\"git\", \"--version\")`");

        Mal("BF11", Runtime, "autostart", Verdict.Passes, "Indicator `AutorunRegistry`; SsaSite with the Run-key path");
        Twin("BF11", Runtime, "autostart", "twin: Registry capability and SsaSite, no `AutorunRegistry`");

        const string Bf12Ttp = "TH16107 and its three evasions (seam-mapping 5.2)";
        Mal("BF12a", Runtime, Bf12Ttp, Verdict.Passes, "Obfuscation (hidden PE)");
        foreach (var id in new[] { "BF12b", "BF12c", "BF12d" })
            Mal(id, Runtime, Bf12Ttp, Verdict.Passes, "**none** (the three known evasions)",
                "Predicted miss (the payload is not one ldstr), closed by hidden-payloads-1: Obfuscation EncodedExecutable from folded constants (BF12b), RVA field data (BF12c) and a managed resource (BF12d).");
        Twin("BF12", Runtime, Bf12Ttp, "no (the PNG decodes as an image)");

        Mal("BF13", Runtime, "reflection-hidden capability", Verdict.Passes, "Capability ReflectionInvocation; SsaSite reflection target `System.IO.File::ReadAllBytes`; Indicator `ReflectionTypeName`");
        Twin("BF13", Runtime, "reflection-hidden capability", "twin: ReflectionInvocation yes");

        Mal("BF14", Runtime, "TH15104 memory / execution", Verdict.Passes, "Capability NativeInterop (`kernel32!VirtualAlloc`, `CreateThread`)");
        Twin("BF14", Runtime, "TH15104 memory / execution", "twin: NativeInterop yes");

        Mal("BF15", "native-entry, lib/", "native entry point", Verdict.Passes, "ReachTrigger NativeEntry → EnvironmentProbe");
        Twin("BF15", "native-entry, lib/", "native entry point", "twin: a NativeEntry root, no sink, so no trigger");

        Mal("BF16", Runtime, "finalizer payload", Verdict.Passes, "ReachTrigger Finalizer/Direct → ProcessExecution");
        Twin("BF16", Runtime, "finalizer payload", "twin: no trigger");

        Mal("BF17", Runtime, "TH15104 steal", Verdict.Passes, "Capability EnvironmentProbe and Network; SsaSite with the constant names");
        Twin("BF17", Runtime, "TH15104 steal", "twin: EnvironmentProbe and SsaSite, different names");

        Mal("BF18", Runtime, "TH15104 evasion", Verdict.Passes, "as BF17 (the evasion is not seen)");
        Twin("BF18", Runtime, "TH15104 evasion", "as BF17's twin");

        const string ConcealCell = "Indicator `CredentialPath` (still scanned), plus an Anomaly for the placement `?`";
        Mal("BF19a", "concealment", "packaging concealment (ADR 0031)", Verdict.Fails, ConcealCell);
        Mal("BF19b", "concealment", "packaging concealment (ADR 0031)", Verdict.Fails, ConcealCell);
        Twin("BF19", "concealment", "packaging concealment (ADR 0031)", "no");

        return rows;
    }

    private static BehaviourRow Make(string id, Side side, string vector, string ttp, Verdict gate, string cell, string note) =>
        new(id, side, vector, ttp,
            new Prediction(gate, Attention: null, cell),
            BehaviourMeasured.Table.GetValueOrDefault($"{id}/{side}") ?? Observation.Unpinned,
            note);
    #endregion
}
