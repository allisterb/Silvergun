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
