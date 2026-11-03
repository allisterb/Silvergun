// Mechanism: async iterators (A2 S2, docs/agent/tasks/cha-a2-dispatch-and-implicit-edges.md §3). Its own
// namespace, so no <X>d__N ordinal in MechanismFixture.Async or MechanismFixture.Iterator moves. The state
// machine is a CLASS even in Release, below both IAsyncStateMachine and IAsyncEnumerator<string>: the stub only
// does newobj of it, and the sink runs in its MoveNext, which MoveNextAsync reaches through
// AsyncIteratorMethodBuilder.MoveNext<S>. A consumer that receives the sequence as a parameter (`await foreach`)
// runs in its own async state machine and only ever calls the platform's IAsyncEnumerator<string>.MoveNextAsync,
// which CHA fans out to every own implementor's explicit MoveNextAsync.
namespace MechanismFixture.AsyncIterator
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public static class Sequences
    {
        public static async IAsyncEnumerable<string> Env()
        {
            await Task.Yield();
            yield return Environment.GetEnvironmentVariable(Names.Variable);
        }

        // Twin.
        public static async IAsyncEnumerable<string> EnvSafe()
        {
            await Task.Yield();
            yield return string.Concat(Names.Variable, Names.Suffix);
        }
    }

    public static class Consumers
    {
        // The consumer in "another method": it never names the iterator, only IAsyncEnumerable<string>.
        public static async Task<int> Consumes(IAsyncEnumerable<string> items)
        {
            var count = 0;
            await foreach (var item in items)
                if (item != null)
                    count++;
            return count;
        }

        public static Task<int> ConsumesEnv() => Consumes(Sequences.Env());

        // Twin driver: hands the consumer only the benign sequence - but the consumer is shared, so under CHA
        // it still reaches the interesting iterator's MoveNext.
        public static Task<int> ConsumesEnvSafe() => Consumes(Sequences.EnvSafe());
    }
}
