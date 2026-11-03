// Mechanism: async state machines. The stub only builds and starts the state machine (a STRUCT, since this
// project is Release-built); the body - and the sink - live in its MoveNext, which no IL instruction calls.
namespace MechanismFixture.Async
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

    // An async local function.
    public static class AsyncLocalCase
    {
        public static Task<string> CallsAsyncLocal()
        {
            return Read();

            static async Task<string> Read()
            {
                await Task.Yield();
                return Environment.GetEnvironmentVariable(Names.Variable);
            }
        }

        // Twin.
        public static Task<string> CallsAsyncLocalSafe()
        {
            return Read();

            static async Task<string> Read()
            {
                await Task.Yield();
                return string.Concat(Names.Variable, Names.Suffix);
            }
        }
    }
}

// Mechanism: iterators. The stub only constructs the enumerator class; the sink runs in its MoveNext, before
// the first yield. A consumer that receives the sequence as a parameter only ever calls the platform's
// IEnumerator.MoveNext, which CHA fans out to every own IEnumerator implementor.
namespace MechanismFixture.Iterator
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

    public static class Consumers
    {
        // The consumer in "another method": it never names the iterator, only IEnumerable<string>.
        public static int Consumes(IEnumerable<string> items)
        {
            var count = 0;
            foreach (var item in items)
                if (item != null)
                    count++;
            return count;
        }

        public static int ConsumesEnum() => Consumes(Sequences.Enum());

        // Twin driver: hands the consumer only the benign sequence - but the consumer is shared, so under CHA
        // it still reaches the interesting iterator's MoveNext.
        public static int ConsumesEnumSafe() => Consumes(Sequences.EnumSafe());
    }
}
