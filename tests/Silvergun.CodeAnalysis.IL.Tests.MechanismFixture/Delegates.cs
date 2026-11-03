// Mechanism: a delegate created and invoked in the SAME method. The `ldftn` that names the target sits in the
// method that also invokes it, so an ldftn edge alone recovers the path.
namespace MechanismFixture.DelegateLocal
{
    using System;

    public static class LocalDelegates
    {
        public static string InvokesLocalDelegate()
        {
            Func<string> read = ReadsEnv;
            return read();
        }

        public static string ReadsEnv() => Environment.GetEnvironmentVariable(Names.Variable);

        // Twin.
        public static string InvokesLocalDelegateSafe()
        {
            Func<string> read = ReadsEnvSafe;
            return read();
        }

        public static string ReadsEnvSafe() => string.Concat(Names.Variable, Names.Suffix);
    }
}

// Mechanism: a delegate STORED by one method and INVOKED by another. The storing method holds the ldftn
// (Present); the invoking method only calls the platform's Func<string>.Invoke, which names no target
// (KnownGap until a delegate-target set exists - research §5.4.4).
namespace MechanismFixture.DelegateField
{
    using System;

    public static class Holder
    {
        public static void Store() => callback = ReadsEnv;

        public static string Fire() => callback?.Invoke();

        public static string ReadsEnv() => Environment.GetEnvironmentVariable(Names.Variable);

        private static Func<string> callback;
    }

    // Twin cluster: a separate field, so the twin's ldftn and Invoke can never alias the interesting ones.
    public static class SafeHolder
    {
        public static void StoreSafe() => callback = ReadsEnvSafe;

        public static string FireSafe() => callback?.Invoke();

        public static string ReadsEnvSafe() => string.Concat(Names.Variable, Names.Suffix);

        private static Func<string> callback;
    }
}

// Mechanism: interface dispatch. CHA fans a callvirt on IProbe.Run out to every implementor, so
// ShouldHaveNoCapability - whose receiver is only ever QuietProbe - still reaches EnvProbe.Run
// (KnownImprecision; ideal Absent). The twin uses a separate interface whose ONLY implementor is benign.
namespace MechanismFixture.Interface
{
    using System;

    public interface IProbe
    {
        string Run();
    }

    public sealed class EnvProbe : IProbe
    {
        public string Run() => Environment.GetEnvironmentVariable(Names.Variable);
    }

    public sealed class QuietProbe : IProbe
    {
        public string Run() => string.Concat(Names.Variable, Names.Suffix);
    }

    public interface ISafeProbe
    {
        string Run();
    }

    public sealed class SafeProbe : ISafeProbe
    {
        public string Run() => string.Concat(Names.Variable, Names.Suffix);
    }

    public static class Dispatch
    {
        public static string CallsThroughInterface()
        {
            IProbe probe = new EnvProbe();
            return probe.Run();
        }

        public static string ShouldHaveNoCapability()
        {
            IProbe probe = new QuietProbe();
            return probe.Run();
        }

        // Twin.
        public static string CallsThroughSafeInterface()
        {
            ISafeProbe probe = new SafeProbe();
            return probe.Run();
        }
    }
}

// Mechanism: virtual dispatch through a base-typed receiver; only the override reaches the sink.
namespace MechanismFixture.Virtual
{
    using System;

    public class Worker
    {
        public virtual string Run() => string.Concat(Names.Variable, Names.Suffix);
    }

    public sealed class EnvWorker : Worker
    {
        public override string Run() => Environment.GetEnvironmentVariable(Names.Variable);
    }

    // Twin hierarchy: neither the base nor the override reaches a sink.
    public class SafeWorker
    {
        public virtual string Run() => string.Concat(Names.Variable, Names.Suffix);
    }

    public sealed class SafeDerivedWorker : SafeWorker
    {
        public override string Run() => string.Concat(Names.Suffix, Names.Variable);
    }

    public static class Callers
    {
        public static string CallsThroughBase()
        {
            Worker worker = new EnvWorker();
            return worker.Run();
        }

        // Twin.
        public static string CallsThroughSafeBase()
        {
            SafeWorker worker = new SafeDerivedWorker();
            return worker.Run();
        }
    }
}

// Mechanism: a type test guarding an interface call. Nothing ever passes an IFileToucher, but CHA cannot know
// that, so CallsMaybeTouch reaches FileToucher.Touch (KnownImprecision; ideal Absent). The twin's interface
// has only a benign implementor.
namespace MechanismFixture.TypeTest
{
    using System.IO;

    public interface IFileToucher
    {
        string Touch();
    }

    public sealed class FileToucher : IFileToucher
    {
        public string Touch() => File.ReadAllText(Names.FilePath);
    }

    public interface ISafeToucher
    {
        string Touch();
    }

    public sealed class SafeToucher : ISafeToucher
    {
        public string Touch() => string.Concat(Names.FilePath, Names.Suffix);
    }

    public static class Inspector
    {
        public static string MaybeTouch(object candidate) => candidate is IFileToucher toucher ? toucher.Touch() : null;

        public static string CallsMaybeTouch() => MaybeTouch(Names.FilePath);

        // Twin.
        public static string MaybeTouchSafe(object candidate) => candidate is ISafeToucher toucher ? toucher.Touch() : null;

        public static string CallsMaybeTouchSafe() => MaybeTouchSafe(Names.FilePath);
    }
}
