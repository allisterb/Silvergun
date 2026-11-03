// Mechanism: Debug-built state machines. The same shapes as MechanismFixture.Async and MechanismFixture.Iterator,
// compiled without optimization: every async state machine is a CLASS, and the stub constructs it (newobj) before
// starting it (Start<S>). The body - and the sink - live in MoveNext, which no IL instruction calls.
namespace MechanismFixture.Debug.Async
{
    using System;
    using System.Threading.Tasks;

    public static class AsyncProbes
    {
        public static async Task<string> Probe()
        {
            await Task.Yield();
            return Environment.GetEnvironmentVariable(Names.Variable);
        }

        // Twin.
        public static async Task<string> ProbeSafe()
        {
            await Task.Yield();
            return string.Concat(Names.Variable, Names.Suffix);
        }
    }

    // An async lambda handed to Task.Run: lambda method AND a state machine nested in <>c.
    public static class AsyncLambdaCase
    {
        public static Task<string> RunsAsyncLambda() =>
            Task.Run(async () =>
            {
                await Task.Yield();
                return Environment.GetEnvironmentVariable(Names.Variable);
            });

        // Twin.
        public static Task<string> RunsAsyncLambdaSafe() =>
            Task.Run(async () =>
            {
                await Task.Yield();
                return string.Concat(Names.Variable, Names.Suffix);
            });
    }
}

// Mechanism: a Debug-built iterator. The stub only constructs the enumerator class; the sink runs in its MoveNext,
// before the first yield.
namespace MechanismFixture.Debug.Iterator
{
    using System;
    using System.Collections.Generic;

    public static class Sequences
    {
        public static IEnumerable<string> Enum()
        {
            var value = Environment.GetEnvironmentVariable(Names.Variable);
            yield return value;
        }

        // Twin.
        public static IEnumerable<string> EnumSafe()
        {
            var value = string.Concat(Names.Variable, Names.Suffix);
            yield return value;
        }
    }
}
