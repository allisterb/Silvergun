// Mechanism: platform callbacks - an own override of a platform virtual (IComparer<T>.Compare,
// Object.ToString) that only the platform calls. The platform is a graph leaf, so there is no edge from the
// caller to the override (KnownGap); the override is still an entry point, so the capability is still found.
namespace MechanismFixture.PlatformCallback
{
    using System;
    using System.Collections.Generic;

    public sealed class EnvComparer : IComparer<string>
    {
        public int Compare(string x, string y) => string.CompareOrdinal(Environment.GetEnvironmentVariable(x), y);
    }

    public sealed class SafeComparer : IComparer<string>
    {
        public int Compare(string x, string y) => string.CompareOrdinal(string.Concat(x, Names.Suffix), y);
    }

    public sealed class EnvToString
    {
        public override string ToString() => Environment.GetEnvironmentVariable(Names.Variable);
    }

    public sealed class SafeToString
    {
        public override string ToString() => string.Concat(Names.Variable, Names.Suffix);
    }

    public static class Callbacks
    {
        public static string[] SortsWithComparer(string[] items)
        {
            Array.Sort(items, new EnvComparer());
            return items;
        }

        public static string ConcatsObject() => string.Concat(new EnvToString());

        // Twins.
        public static string[] SortsWithComparerSafe(string[] items)
        {
            Array.Sort(items, new SafeComparer());
            return items;
        }

        public static string ConcatsObjectSafe() => string.Concat(new SafeToString());
    }
}

// Mechanism: the constructs a call graph cannot see through - reflection, function pointers, `dynamic` and
// P/Invoke. Each is either classified by the map at the platform node (reflection, dynamic), reachable by an
// ldftn even though the call itself is opaque (function pointer), or a bodyless extern (P/Invoke).
namespace MechanismFixture.Opacity
{
    using System;
    using System.Runtime.InteropServices;

    public static class Targets
    {
        public static string ReadsEnv() => Environment.GetEnvironmentVariable(Names.Variable);

        public static string ReadsEnvSafe() => string.Concat(Names.Variable, Names.Suffix);
    }

    public sealed class Runner
    {
        public string Run() => string.Concat(Names.Variable, Names.Suffix);
    }

    public static class Reflective
    {
        // Looked up by NAME STRING, then invoked: no edge to Targets.ReadsEnv exists in IL at all.
        public static object InvokesByName() => typeof(Targets).GetMethod("ReadsEnv").Invoke(null, null);

        // Twin: the lookup without the invocation.
        public static object InvokesByNameSafe() => typeof(Targets).GetMethod("ReadsEnv");
    }

    public static unsafe class Pointers
    {
        // ldftn Targets.ReadsEnv, then calli.
        public static string CallsThroughPointer()
        {
            delegate*<string> read = &Targets.ReadsEnv;
            return read();
        }

        // Twin.
        public static string CallsThroughPointerSafe()
        {
            delegate*<string> read = &Targets.ReadsEnvSafe;
            return read();
        }
    }

    public static class Dynamic
    {
        public static object CallsDynamic(object target)
        {
            dynamic runner = target;
            return runner.Run();
        }

        // Twin: the same call, statically bound.
        public static object CallsStatically(Runner target) => target.Run();
    }

    public static class Native
    {
        [DllImport("libc")]
        private static extern int getpid();

        public static int CallsNative() => getpid();

        // Twin: a managed computation in place of the native call.
        public static int CallsManaged() => Math.Abs(Names.Variable.Length);
    }
}
