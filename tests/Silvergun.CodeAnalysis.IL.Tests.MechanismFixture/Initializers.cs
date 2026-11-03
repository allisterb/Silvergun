// Mechanism: type initializers. A static field initializer and an explicit static constructor both compile to
// .cctor, which no IL instruction ever calls: the runtime runs it on first access. A2 adds a TypeInitializer
// edge from any method that touches a static member of an own type that has a .cctor.
namespace MechanismFixture.StaticInit
{
    using System;

    // Field initializer only: the compiler synthesizes .cctor (and marks the type beforefieldinit).
    public static class FieldInit
    {
        public static readonly string Value = Environment.GetEnvironmentVariable(Names.Variable);
    }

    // Explicit static constructor (no beforefieldinit).
    public static class ExplicitInit
    {
        static ExplicitInit()
        {
            Value = Environment.GetEnvironmentVariable(Names.Variable);
        }

        public static readonly string Value;
    }

    // Twin: same shape, benign initializer.
    public static class SafeFieldInit
    {
        public static readonly string Value = string.Concat(Names.Variable, Names.Suffix);
    }

    public static class Triggers
    {
        // Only READS a static field: there is no call instruction to the .cctor at all.
        public static string TriggersInit() => FieldInit.Value;

        public static string TriggersExplicitInit() => ExplicitInit.Value;

        // Twin.
        public static string TriggersSafeInit() => SafeFieldInit.Value;
    }

    // A2 S3 (cha-a2-dispatch-and-implicit-edges.md §8): an instantiable class with an explicit static constructor,
    // reached only by `newobj` of its instance constructor - no static member of it is ever named outside it.
    public sealed class Constructed
    {
        static Constructed()
        {
            Captured = Environment.GetEnvironmentVariable(Names.Variable);
        }

        internal static string Captured;
    }

    // Twin: same shape, benign static constructor.
    public sealed class SafeConstructed
    {
        static SafeConstructed()
        {
            Captured = string.Concat(Names.Variable, Names.Suffix);
        }

        internal static string Captured;
    }

    public static class Creators
    {
        // Only CONSTRUCTS: newobj Constructed::.ctor(), whose static constructor the runtime runs first.
        public static object CreatesExplicitInit() => new Constructed();

        // Twin.
        public static object CreatesSafeInit() => new SafeConstructed();
    }

    // A2 S3 review W3: a STRUCT with an explicit static constructor (so not beforefieldinit). Calling an instance method
    // of it runs the static constructor first (ECMA-335 II.10.5.3.1), though no static member is named and nothing is
    // constructed: `default(ValueInit).M()` is initobj + call ValueInit::M().
    public struct ValueInit
    {
        static ValueInit()
        {
            Captured = Environment.GetEnvironmentVariable(Names.Variable);
        }

        internal static string Captured;

        public int M() => 1;
    }

    // Twin: same shape, benign static constructor.
    public struct SafeValueInit
    {
        static SafeValueInit()
        {
            Captured = string.Concat(Names.Variable, Names.Suffix);
        }

        internal static string Captured;

        public int M() => 2;
    }

    public static class ValueCallers
    {
        public static int CallsValueMember() => default(ValueInit).M();

        // Twin.
        public static int CallsSafeValueMember() => default(SafeValueInit).M();
    }
}

// Mechanism: a module initializer - runs when the assembly is loaded, with no caller in IL other than the
// compiler-synthesized <Module>..cctor (which the analysis-net model does not surface at all).
namespace MechanismFixture.ModuleInit
{
    using System;
    using System.Runtime.CompilerServices;

    // CA2255 warns that [ModuleInitializer] belongs in application code. A library module initializer is
    // precisely the install-time vector this fixture exists to model, so the warning is the point.
#pragma warning disable CA2255

    internal static class Startup
    {
        [ModuleInitializer]
        internal static void Init() => Captured = Environment.GetEnvironmentVariable(Names.Variable);

        internal static string Captured;
    }

    // Twin: a second module initializer with a benign body.
    internal static class SafeStartup
    {
        [ModuleInitializer]
        internal static void InitSafe() => Captured = string.Concat(Names.Variable, Names.Suffix);

        internal static string Captured;
    }

#pragma warning restore CA2255
}
