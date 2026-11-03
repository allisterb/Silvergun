// Mechanism: a plain `call` straight to the sink - the floor every other mechanism builds on.
namespace MechanismFixture.Direct
{
    using System;

    public static class Probes
    {
        public static string ReadsEnv() => Environment.GetEnvironmentVariable(Names.Variable);

        // Twin: identical except the sink is a `safe` call.
        public static string ReadsEnvSafe() => string.Concat(Names.Variable, Names.Suffix);
    }
}

// Mechanism: transitivity through own code - three own hops before the sink.
namespace MechanismFixture.Transitive
{
    using System;

    public static class Chain
    {
        public static string Outer() => Middle() + "!";

        public static string Middle() => Inner() + "?";

        public static string Inner() => Environment.GetEnvironmentVariable(Names.Variable);

        // Twin chain.
        public static string OuterSafe() => MiddleSafe() + "!";

        public static string MiddleSafe() => InnerSafe() + "?";

        public static string InnerSafe() => string.Concat(Names.Variable, Names.Suffix);
    }
}

// Mechanism: the path leaves this assembly - only a graph holding both assemblies can see it (A2Multi).
namespace MechanismFixture.CrossAssembly
{
    using MechanismFixture.Dependency;

    public static class Callers
    {
        public static string UsesDependency() => EnvReader.Read();

        // Twin.
        public static string UsesDependencySafe() => EnvReader.ReadSafe();
    }
}

// Mechanism: only safe APIs (string, Math, System.Collections.*) - nothing may ever be reported from here.
namespace MechanismFixture.Safe
{
    using System;
    using System.Collections.Generic;

    public static class Pure
    {
        public static int SafeOnly(string text)
        {
            var lengths = new List<int> { text.Length, Names.Variable.Length };
            return Math.Max(lengths.Count, string.Concat(text, Names.Suffix).Length);
        }
    }
}
