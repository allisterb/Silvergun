namespace Silvergun.CodeAnalysis.IL.Tests;

using System.Collections.Generic;

using Silvergun.CodeAnalysis.IL;

/// <summary>
/// One root-class ground-truth row (reachability R1, S3): the single own method <paramref name="RootRegex"/> names, as a
/// root of <paramref name="Class"/>, reaches <paramref name="Capability"/> and the strongest evidence tier it does so in
/// is <paramref name="Strongest"/>. An <see cref="Expectation.Absent"/> row has no <paramref name="Strongest"/>: the root
/// reaches <paramref name="Capability"/> (null = any capability) in no tier. Asserted against
/// <see cref="Reachability.Analyze"/> over <see cref="MechanismGraphSource.Graph"/>.
/// </summary>
public sealed record RootPath(
    string Id,
    string RootRegex,
    RootClass Class,
    Capability? Capability,
    ReachEvidence? Strongest,
    Expectation Expect,
    string Note);

/// <summary>
/// The root-class and evidence-tier ground truth for the mechanism fixture (docs/agent/tasks/reachability-r1.md, S3;
/// ADR 0037 decisions 4 and 7), beside <see cref="MechanismGroundTruth"/>'s path table. The new cases live in the
/// fixture's <c>MechanismFixture.Roots</c> namespaces (<c>Roots.cs</c>); the LoadTime, type-initializer, Direct,
/// P/Invoke and Interface cases are the existing ones, reused.
/// <para>
/// <b>Expectations are design decisions</b>, written from the spec and the ADR before the rows were first run. Do not
/// edit one to make a test pass; changing one is recorded in the spec. Every row carries a Note, and every row that is
/// not Absent has an Absent twin of the same class, whose Id is its own plus <see cref="TwinSuffix"/>.
/// </para>
/// </summary>
public static class RootGroundTruth
{
    #region Properties
    /// <summary>Every row, in catalogue order: one pair per root class, then the evidence tiers.</summary>
    public static IReadOnlyList<RootPath> Rows { get; } =
    [
        // ---- LoadTime ----------------------------------------------------------------------------------------
        new("LoadTime.ModuleInitializer", Own("ModuleInit.Startup.Init()"), RootClass.LoadTime, Env, ReachEvidence.Bound, Expectation.Present,
            "[ModuleInitializer] Init calls the sink itself: the install-time vector, Bound. (LoadTime's verdict stays Unknown for the opaque <Module>..cctor gap.)"),
        new("LoadTime.ModuleInitializerSafe", Own("ModuleInit.SafeStartup.InitSafe()"), RootClass.LoadTime, null, null, Expectation.Absent,
            "Twin module initializer with a benign body."),

        // ---- HostContract ------------------------------------------------------------------------------------
        new("HostContract.TaskExecute", Own("Roots.Host.EnvTask.Execute()"), RootClass.HostContract, Env, ReachEvidence.Bound, Expectation.Present,
            "An ITask's Execute (the stub's Microsoft.Build.Framework.ITask, never indexed, so external): MSBuild calls it on the developer's or CI's machine."),
        new("HostContract.TaskExecuteSafe", Own("Roots.Host.SafeTask.Execute()"), RootClass.HostContract, null, null, Expectation.Absent,
            "Twin task with a benign Execute."),
        new("HostContract.AnalyzerConstructor", Own("Roots.Host.EnvAnalyzer..ctor()"), RootClass.HostContract, Env, ReachEvidence.Bound, Expectation.Present,
            "Every method of a type below a host contract is HostContract, constructors included: the compiler host constructs a DiagnosticAnalyzer before anything else."),
        new("HostContract.AnalyzerConstructorSafe", Own("Roots.Host.SafeAnalyzer..ctor()"), RootClass.HostContract, null, null, Expectation.Absent,
            "Twin analyzer with a benign constructor."),

        // ---- TypeInitializer, Finalizer, NativeEntry (R1's RuntimeInvoked, split by ADR 0037 amendment a1) -----
        new("TypeInitializer.FieldInitializer", Own("StaticInit.FieldInit..cctor()"), RootClass.TypeInitializer, Env, ReachEvidence.Bound, Expectation.Present,
            "A static field initializer's .cctor (the existing StaticInit case): the runtime runs it on first access."),
        new("TypeInitializer.FieldInitializerSafe", Own("StaticInit.SafeFieldInit..cctor()"), RootClass.TypeInitializer, null, null, Expectation.Absent,
            "Twin .cctor (the existing StaticInit twin)."),
        new("Finalizer.Finalize", Own("Roots.Runtime.EnvFinalized.Finalize()"), RootClass.Finalizer, Env, ReachEvidence.Bound, Expectation.Present,
            "~EnvFinalized() overrides Object.Finalize: the finalizer thread runs it, nothing in IL calls it."),
        new("Finalizer.FinalizeSafe", Own("Roots.Runtime.SafeFinalized.Finalize()"), RootClass.Finalizer, null, null, Expectation.Absent,
            "Twin finalizer with a benign body."),
        new("NativeEntry.UnmanagedCallersOnly", Own("Roots.Runtime.Exports.ExportsEnv()"), RootClass.NativeEntry, Env, ReachEvidence.Bound, Expectation.Present,
            "An [UnmanagedCallersOnly] export (a root-attribute ... NativeEntry entry): native code calls in."),
        new("NativeEntry.UnmanagedCallersOnlySafe", Own("Roots.Runtime.Exports.ExportsSafe()"), RootClass.NativeEntry, null, null, Expectation.Absent,
            "Twin export with a benign body. The scanner still reports a NativeExport for it (the export itself); reachability's sinks are what it calls."),

        // ---- PublicApi ---------------------------------------------------------------------------------------
        new("PublicApi.Direct", Own("Direct.Probes.ReadsEnv()"), RootClass.PublicApi, Env, ReachEvidence.Bound, Expectation.Present,
            "A public static method calling the sink: the consumer can call it, with no Dispatch edge on the way (the Bound tier)."),
        new("PublicApi.DirectSafe", Own("Direct.Probes.ReadsEnvSafe()"), RootClass.PublicApi, null, null, Expectation.Absent,
            "Twin (the existing Direct twin)."),
        new("PublicApi.ExplicitImplementation", Own("Roots.Visibility.NetResolver.MechanismFixture.Roots.Visibility.IResolver.Resolve()"),
            RootClass.PublicApi, Capability.Network, ReachEvidence.Bound, Expectation.Present,
            "A private explicit implementation of a public interface on a public type: a consumer calls it through IResolver, so it is PublicApi though private."),
        new("PublicApi.ExplicitImplementationSafe", Own("Roots.Visibility.SafeResolver.MechanismFixture.Roots.Visibility.ISafeResolver.Resolve()"),
            RootClass.PublicApi, null, null, Expectation.Absent,
            "Twin explicit implementation (of its own interface) with a benign body."),
        new("PublicApi.TypeInitializerTrigger", Own("StaticInit.Triggers.TriggersInit()"), RootClass.PublicApi, Env, ReachEvidence.Bound, Expectation.Present,
            "Reading a static field reaches the .cctor by a TypeInitializer edge: an implicit edge, but no Dispatch, so Bound."),
        new("PublicApi.TypeInitializerTriggerSafe", Own("StaticInit.Triggers.TriggersSafeInit()"), RootClass.PublicApi, null, null, Expectation.Absent,
            "Twin trigger, whose .cctor is benign."),
        new("PublicApi.PInvoke", Own("Opacity.Native.CallsNative()"), RootClass.PublicApi, Capability.NativeInterop, ReachEvidence.Bound, Expectation.Present,
            "A call to an own [DllImport]: the extern is a NativeInterop sink (ADR 0037 decision 2), the same rule Opacity.PInvokeCapability ratchets."),
        new("PublicApi.PInvokeSafe", Own("Opacity.Native.CallsManaged()"), RootClass.PublicApi, null, null, Expectation.Absent,
            "Twin: a managed computation in place of the native call."),

        // ---- PublicContract ----------------------------------------------------------------------------------
        new("PublicContract.InternalImplementation", Own("Roots.Visibility.EnvGauge.Read()"), RootClass.PublicContract, Env, ReachEvidence.Bound, Expectation.Present,
            "Rule (a): an internal implementation of the public IGauge, handed out by a public factory; CHA from the visible IGauge.Read reaches it."),
        new("PublicContract.InternalImplementationSafe", Own("Roots.Visibility.SafeGauge.Read()"), RootClass.PublicContract, null, null, Expectation.Absent,
            "Twin: the same shape (public ISafeGauge, public factory) with a benign Read."),
        new("PublicContract.PlatformSlotOverride", Own("Roots.Visibility.EnvLabel.ToString()"), RootClass.PublicContract, Env, ReachEvidence.Bound, Expectation.Present,
            "Rule (b): an internal class's ToString overrides Object.ToString, a slot declared outside the package, so any escaped instance runs it."),
        new("PublicContract.PlatformSlotOverrideSafe", Own("Roots.Visibility.SafeLabel.ToString()"), RootClass.PublicContract, null, null, Expectation.Absent,
            "Twin ToString override with a benign body."),

        // ---- Hidden ------------------------------------------------------------------------------------------
        new("Hidden.Unreferenced", Own("Roots.Visibility.Unreached.ReadsEnv()"), RootClass.Hidden, Env, ReachEvidence.Bound, Expectation.Present,
            "An internal method of an internal class nothing calls: reachable only by reflection, or dead. Still a root (ADR 0020 d6), only Hidden."),
        new("Hidden.UnreferencedSafe", Own("Roots.Visibility.UnreachedSafe.ReadsSafe()"), RootClass.Hidden, null, null, Expectation.Absent,
            "Twin unreferenced method with a benign body."),

        // ---- Evidence tiers (ADR 0037 decision 7) ------------------------------------------------------------
        new("Tier.Instantiated", Own("Interface.Dispatch.CallsThroughInterface()"), RootClass.PublicApi, Env, ReachEvidence.Instantiated, Expectation.Present,
            "callvirt IProbe.Run needs the Dispatch edge to EnvProbe.Run, and EnvProbe is live (newobj'd here, and publicly constructible): Instantiated, not Bound."),
        new("Tier.InstantiatedSafe", Own("Interface.Dispatch.CallsThroughSafeInterface()"), RootClass.PublicApi, null, null, Expectation.Absent,
            "Twin (the existing Interface twin): ISafeProbe's only implementor is benign."),
        new("Tier.InstantiatedInternal", Own("Roots.Tiers.Callers.CallsMade()"), RootClass.PublicApi, Env, ReachEvidence.Instantiated, Expectation.Present,
            "The Dispatch edge's target type is internal, so live only because the package newobj's it: the case where the RTA tier's liveness comes from instantiation alone."),
        new("Tier.InstantiatedInternalSafe", Own("Roots.Tiers.Callers.CallsMadeSafe()"), RootClass.PublicApi, null, null, Expectation.Absent,
            "Twin: the same shape, with a benign implementor."),
        new("Tier.ChaOnly", Own("Roots.Tiers.Callers.CallsUnmade(System.Object)"), RootClass.PublicApi, Env, ReachEvidence.ChaOnly, Expectation.Present,
            "The only path is a Dispatch edge to an internal sealed implementor of an internal interface that nothing instantiates: ChaOnly, not Instantiated. " +
            "Reported, labelled, never pruned: a deserializer or Activator could create one."),
        new("Tier.ChaOnlySafe", Own("Roots.Tiers.Callers.CallsUnmadeSafe(System.Object)"), RootClass.PublicApi, null, null, Expectation.Absent,
            "Twin: the same never-instantiated shape, with a benign implementor."),
    ];
    #endregion

    #region Methods
    /// <summary>An anchored, escaped root regex for an own fixture method (<see cref="MechanismGroundTruth.Own"/>).</summary>
    private static string Own(string nodeIdWithoutRoot) => MechanismGroundTruth.Own(nodeIdWithoutRoot);
    #endregion

    #region Fields
    /// <summary>The suffix that makes a row's Absent twin's Id.</summary>
    public const string TwinSuffix = "Safe";

    private const Capability Env = Capability.EnvironmentProbe;
    #endregion
}
