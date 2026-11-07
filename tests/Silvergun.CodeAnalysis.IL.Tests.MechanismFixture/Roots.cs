// Reachability R1, S3 (docs/agent/tasks/reachability-r1.md; ADR 0037 decisions 4 and 7): one case per root class and
// per evidence tier, each reaching a benign sink stand-in (Environment.GetEnvironmentVariable, Dns.GetHostAddresses)
// beside its twin of the same shape that reaches none. The expectations are RootGroundTruth's rows, in the test
// project. Nothing here is ever executed: the assembly is read from disk as metadata.

// HostContract: below a contract declared in ...MechanismFixture.HostStubs, which is never indexed, so the supertypes are
// external, as in a real package.
namespace MechanismFixture.Roots.Host
{
    using System;
    using Microsoft.Build.Framework;
    using Microsoft.CodeAnalysis.Diagnostics;

    // An MSBuild task: the build host calls Execute.
    public sealed class EnvTask : ITask
    {
        public bool Execute() => Environment.GetEnvironmentVariable(Names.Variable) is not null;
    }

    // Twin.
    public sealed class SafeTask : ITask
    {
        public bool Execute() => string.Concat(Names.Variable, Names.Suffix).Length > 0;
    }

    // A Roslyn analyzer: the compiler host constructs it before it calls anything else.
    public sealed class EnvAnalyzer : DiagnosticAnalyzer
    {
        public EnvAnalyzer() => Captured = Environment.GetEnvironmentVariable(Names.Variable);

        public override void Initialize(object context)
        {
        }

        internal string Captured;
    }

    // Twin.
    public sealed class SafeAnalyzer : DiagnosticAnalyzer
    {
        public SafeAnalyzer() => Captured = string.Concat(Names.Variable, Names.Suffix);

        public override void Initialize(object context)
        {
        }

        internal string Captured;
    }
}

// The runtime classes (ADR 0037 amendment a1): a finalizer (Finalizer) and an [UnmanagedCallersOnly] export
// (NativeEntry); the StaticInit .cctors are the TypeInitializer cases.
namespace MechanismFixture.Roots.Runtime
{
    using System;
    using System.Runtime.InteropServices;

    public sealed class EnvFinalized
    {
        ~EnvFinalized() => Captured = Environment.GetEnvironmentVariable(Names.Variable);

        internal static string Captured;
    }

    // Twin.
    public sealed class SafeFinalized
    {
        ~SafeFinalized() => Captured = string.Concat(Names.Variable, Names.Suffix);

        internal static string Captured;
    }

    public static class Exports
    {
        [UnmanagedCallersOnly]
        public static int ExportsEnv() => Environment.GetEnvironmentVariable(Names.Variable)?.Length ?? 0;

        // Twin: also an export, so it is also a NativeEntry root.
        [UnmanagedCallersOnly]
        public static int ExportsSafe() => string.Concat(Names.Variable, Names.Suffix).Length;
    }
}

// PublicApi vs Hidden vs PublicContract: who outside the package can make the method run.
namespace MechanismFixture.Roots.Visibility
{
    using System;
    using System.Net;

    // Hidden: an internal method of an internal class, and nothing calls it.
    internal sealed class Unreached
    {
        internal string ReadsEnv() => Environment.GetEnvironmentVariable(Names.Variable);
    }

    // Twin.
    internal sealed class UnreachedSafe
    {
        internal string ReadsSafe() => string.Concat(Names.Variable, Names.Suffix);
    }

    // PublicApi: a private explicit implementation of a public interface, on a public type.
    public interface IResolver
    {
        object Resolve();
    }

    public sealed class NetResolver : IResolver
    {
        object IResolver.Resolve() => Dns.GetHostAddresses(Names.Host);
    }

    // Twin: its own interface, so it shares no slot with the interesting case.
    public interface ISafeResolver
    {
        object Resolve();
    }

    public sealed class SafeResolver : ISafeResolver
    {
        object ISafeResolver.Resolve() => string.Concat(Names.Host, Names.Suffix);
    }

    // PublicContract, rule (a): an internal implementation of a public interface, escaping through a public factory.
    public interface IGauge
    {
        string Read();
    }

    internal sealed class EnvGauge : IGauge
    {
        public string Read() => Environment.GetEnvironmentVariable(Names.Variable);
    }

    // Twin.
    public interface ISafeGauge
    {
        string Read();
    }

    internal sealed class SafeGauge : ISafeGauge
    {
        public string Read() => string.Concat(Names.Variable, Names.Suffix);
    }

    public static class Gauges
    {
        public static IGauge Create() => new EnvGauge();

        public static ISafeGauge CreateSafe() => new SafeGauge();
    }

    // PublicContract, rule (b): an internal class's override of a slot declared outside the package (Object.ToString).
    internal sealed class EnvLabel
    {
        public override string ToString() => Environment.GetEnvironmentVariable(Names.Variable);
    }

    // Twin.
    internal sealed class SafeLabel
    {
        public override string ToString() => string.Concat(Names.Variable, Names.Suffix);
    }
}

// Evidence tiers (the RTA label): what a path needs a Dispatch edge for, and whether its target's type is live.
namespace MechanismFixture.Roots.Tiers
{
    using System;

    // Never instantiated, internal (so no consumer can construct it), and reached only through an interface call: the
    // Dispatch edge to it is ChaOnly.
    internal interface IUnmade
    {
        string Run();
    }

    internal sealed class UnmadeProbe : IUnmade
    {
        public string Run() => Environment.GetEnvironmentVariable(Names.Variable);
    }

    // Twin.
    internal interface ISafeUnmade
    {
        string Run();
    }

    internal sealed class UnmadeSafeProbe : ISafeUnmade
    {
        public string Run() => string.Concat(Names.Variable, Names.Suffix);
    }

    // The same internal shape, but the package does `newobj` it: the Dispatch edge is Instantiated.
    internal interface IMade
    {
        string Run();
    }

    internal sealed class MadeProbe : IMade
    {
        public string Run() => Environment.GetEnvironmentVariable(Names.Variable);
    }

    // Twin.
    internal interface ISafeMade
    {
        string Run();
    }

    internal sealed class MadeSafeProbe : ISafeMade
    {
        public string Run() => string.Concat(Names.Variable, Names.Suffix);
    }

    public static class Callers
    {
        // castclass + callvirt IUnmade.Run: the receiver comes from outside, and nothing makes an UnmadeProbe.
        public static string CallsUnmade(object probe) => ((IUnmade)probe).Run();

        public static string CallsUnmadeSafe(object probe) => ((ISafeUnmade)probe).Run();

        public static string CallsMade()
        {
            IMade probe = new MadeProbe();
            return probe.Run();
        }

        public static string CallsMadeSafe()
        {
            ISafeMade probe = new MadeSafeProbe();
            return probe.Run();
        }
    }
}

// The presence parity oracle (ADR 0037 decision 9) compares the scanner's Call, Construct, MethodPointerLoad and
// NativeImport findings with the graph's sink edges. The rest of the fixture reaches its sinks by call/callvirt only, so
// these two give the oracle a `newobj` and an `ldftn` of a capability. Constructing a FileInfo touches no file.
namespace MechanismFixture.Parity
{
    using System;
    using System.IO;

    public static class Kinds
    {
        // newobj System.IO.FileInfo::.ctor: a Construct finding, a NewObj edge.
        public static object ConstructsFileInfo() => new FileInfo(Names.FilePath);

        // ldftn Environment.GetEnvironmentVariable (a method-group conversion): a MethodPointerLoad finding, an Ldftn edge.
        public static Func<string, string> LoadsEnvPointer() => Environment.GetEnvironmentVariable;

        // Twins.
        public static object ConstructsSafe() => new Uri(Names.Host, UriKind.Relative);

        public static Func<string, string, string> LoadsSafePointer() => string.Concat;
    }
}
