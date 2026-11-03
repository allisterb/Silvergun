// Mechanism: lambdas handed to (or kept from) the platform. Every lambda body is a compiler-generated method
// that only an `ldftn` in the enclosing method names; the platform API that later invokes it is a graph leaf.
// Each case is its own class so the compiler-generated names (<>c, <>c__DisplayClassN_M, <M>b__N_M) of one
// case cannot shift when another is edited.
namespace MechanismFixture.Lambda
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Threading.Tasks;

    // Non-capturing lambda passed to LINQ (System.Linq.Enumerable is `safe`): cached in <>c.
    public static class LinqCase
    {
        public static int CountsSetVariables(string[] names) =>
            names.Where(name => Environment.GetEnvironmentVariable(name) != null).Count();

        // Twin.
        public static int CountsSetVariablesSafe(string[] names) =>
            names.Where(name => string.Concat(name, Names.Suffix) != null).Count();
    }

    // Capturing lambda: the body lives on a display class, instantiated by the enclosing method.
    public static class CaptureCase
    {
        public static string Captures(string name)
        {
            Func<string> read = () => Environment.GetEnvironmentVariable(name);
            return read();
        }

        // Twin.
        public static string CapturesSafe(string name)
        {
            Func<string> read = () => string.Concat(name, Names.Suffix);
            return read();
        }
    }

    // Lazy<T> factory.
    public static class LazyCase
    {
        public static string LazyFactory()
        {
            var lazy = new Lazy<string>(() => Environment.GetEnvironmentVariable(Names.Variable));
            return lazy.Value;
        }

        // Twin.
        public static string LazyFactorySafe()
        {
            var lazy = new Lazy<string>(() => string.Concat(Names.Variable, Names.Suffix));
            return lazy.Value;
        }
    }

    // Task.Run - the lambda starts a process (ProcessExecution sink).
    public static class TaskRunCase
    {
        public static Task<int> RunsOnThreadPool() => Task.Run(() => Process.Start(Names.Program).Id);

        // Twin.
        public static Task<int> RunsOnThreadPoolSafe() => Task.Run(() => string.Concat(Names.Program, Names.Suffix).Length);
    }

    // List<T>.Sort(Comparison<T>) (System.Collections.* is `safe`).
    public static class SortCase
    {
        public static List<string> SortsWithLambda(List<string> items)
        {
            items.Sort((left, right) => string.CompareOrdinal(Environment.GetEnvironmentVariable(left), right));
            return items;
        }

        // Twin.
        public static List<string> SortsWithLambdaSafe(List<string> items)
        {
            items.Sort((left, right) => string.CompareOrdinal(string.Concat(left, Names.Suffix), right));
            return items;
        }
    }

    // Event: subscribe and raise in DIFFERENT methods. The subscriber holds the ldftn (Present); the raiser only
    // calls Action.Invoke on the backing field (KnownGap, same reason as DelegateField).
    public sealed class Publisher
    {
        public event Action Raised;

        public void Subscribe() => Raised += OnRaised;

        public void Raise() => Raised?.Invoke();

        public string Last => last;

        private void OnRaised() => last = Environment.GetEnvironmentVariable(Names.Variable);

        private string last;
    }

    // Twin publisher.
    public sealed class SafePublisher
    {
        public event Action Raised;

        public void SubscribeSafe() => Raised += OnRaisedSafe;

        public void RaiseSafe() => Raised?.Invoke();

        public string Last => last;

        private void OnRaisedSafe() => last = string.Concat(Names.Variable, Names.Suffix);

        private string last;
    }
}

// Mechanism: local functions - called directly (a plain call to a compiler-named static method) and converted
// to a delegate (an ldftn).
namespace MechanismFixture.LocalFunction
{
    using System;

    public static class LocalCalls
    {
        public static string CallsLocal()
        {
            return Read();

            static string Read() => Environment.GetEnvironmentVariable(Names.Variable);
        }

        public static string ConvertsLocal()
        {
            Func<string> read = Read;
            return read();

            static string Read() => Environment.GetEnvironmentVariable(Names.Variable);
        }

        // Twins.
        public static string CallsLocalSafe()
        {
            return Read();

            static string Read() => string.Concat(Names.Variable, Names.Suffix);
        }

        public static string ConvertsLocalSafe()
        {
            Func<string> read = Read;
            return read();

            static string Read() => string.Concat(Names.Variable, Names.Suffix);
        }
    }
}
