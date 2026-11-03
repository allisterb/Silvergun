// CHA phase A2, slice S1 (docs/agent/tasks/cha-a2-dispatch-and-implicit-edges.md §8): dispatch shapes the A1
// fixture deliberately lacked. Each namespace is one mechanism; every interesting case has a twin, and a twin
// whose path necessarily goes through the same platform virtual is a KnownImprecision row (A1 spec §1.7).

// Mechanism: `callvirt System.Object::ToString` on an object-typed parameter (decision D1: platform-declared virtuals
// fan out to every own override). The twin describer is only ever handed a safe object, but its callvirt fans out to
// EnvDescribed.ToString too. DescribesNumber is the Absent row: Roslyn calls Int32.ToString with a plain `call`, so
// a value-type receiver does not dispatch at all.
namespace MechanismFixture.ObjectVirtual
{
    using System;

    public sealed class EnvDescribed
    {
        public override string ToString() => Environment.GetEnvironmentVariable(Names.Variable);
    }

    public sealed class SafeDescribed
    {
        public override string ToString() => string.Concat(Names.Variable, Names.Suffix);
    }

    public static class Describers
    {
        public static string Describe(object item) => item.ToString();

        public static string DescribesEnv() => Describe(new EnvDescribed());

        // Twin: its own describer, only ever given SafeDescribed.
        public static string DescribeSafe(object item) => item.ToString();

        public static string DescribesSafe() => DescribeSafe(new SafeDescribed());

        // `call instance string System.Int32::ToString()` - non-virtual, so nothing to fan out.
        public static string DescribesNumber(int number) => number.ToString();
    }
}

// Mechanism: a C# explicit interface implementation. Its metadata name is the interface-qualified
// `MechanismFixture.ExplicitImpl.IExplicitProbe.Run`, which CHA must still match against a call to `Run`.
namespace MechanismFixture.ExplicitImpl
{
    using System;

    public interface IExplicitProbe
    {
        string Run();
    }

    public sealed class EnvExplicitProbe : IExplicitProbe
    {
        string IExplicitProbe.Run() => Environment.GetEnvironmentVariable(Names.Variable);
    }

    public interface ISafeExplicitProbe
    {
        string Run();
    }

    public sealed class SafeExplicitProbe : ISafeExplicitProbe
    {
        string ISafeExplicitProbe.Run() => string.Concat(Names.Variable, Names.Suffix);
    }

    public static class Callers
    {
        public static string CallsExplicit()
        {
            IExplicitProbe probe = new EnvExplicitProbe();
            return probe.Run();
        }

        // Twin: a separate interface whose only implementor is benign.
        public static string CallsSafeExplicit()
        {
            ISafeExplicitProbe probe = new SafeExplicitProbe();
            return probe.Run();
        }
    }
}

// Mechanism: a call through a PLATFORM generic interface instantiation (`IComparer<string>.Compare`) to an own
// implementor. The twin does not need the platform interface, so it uses its own generic interface with the same
// method shape and only a benign implementor (A1 spec §1.7's twin rule: Absent with its own interface).
namespace MechanismFixture.GenericInterface
{
    using System;
    using System.Collections.Generic;

    public sealed class EnvOrder : IComparer<string>
    {
        public int Compare(string x, string y) => string.CompareOrdinal(Environment.GetEnvironmentVariable(Names.Variable), y);
    }

    public interface ISafeComparer<T>
    {
        int Compare(T x, T y);
    }

    public sealed class SafeOrder : ISafeComparer<string>
    {
        public int Compare(string x, string y) => string.CompareOrdinal(x, y);
    }

    public static class Sorters
    {
        public static int ComparesThroughInterface()
        {
            IComparer<string> comparer = new EnvOrder();
            return comparer.Compare(Names.Variable, Names.Suffix);
        }

        // Twin.
        public static int ComparesThroughSafeInterface()
        {
            ISafeComparer<string> comparer = new SafeOrder();
            return comparer.Compare(Names.Variable, Names.Suffix);
        }
    }
}

// Mechanism: a C# 11 static abstract interface member. `T.Make()` compiles to `constrained. !!T call IFactory::Make()`,
// and CCIProvider drops the prefix, so Model sees a plain static `call` to the abstract interface method: CHA's
// static rule must fan it out to EnvFactory.Make.
namespace MechanismFixture.StaticAbstract
{
    using System;

    public interface IFactory
    {
        static abstract string Make();
    }

    public sealed class EnvFactory : IFactory
    {
        public static string Make() => Environment.GetEnvironmentVariable(Names.Variable);
    }

    public interface ISafeFactory
    {
        static abstract string Make();
    }

    public sealed class SafeFactory : ISafeFactory
    {
        public static string Make() => string.Concat(Names.Variable, Names.Suffix);
    }

    public static class Builders
    {
        public static string Build<T>() where T : IFactory => T.Make();

        public static string BuildsEnv() => Build<EnvFactory>();

        // Twin.
        public static string BuildSafe<T>() where T : ISafeFactory => T.Make();

        public static string BuildsSafe() => BuildSafe<SafeFactory>();
    }
}

// Mechanism: an open hierarchy (decision D2). EnvStream overrides a PLATFORM virtual (Stream.Flush) through a
// platform base (MemoryStream) the subtype map never sees, so `callvirt Stream::Flush` reaches it only by the
// open-type rule - which also makes the twin FlushItSafe reach it (KnownImprecision). FlushesJournal is the Absent
// row: its declared type is own (Journal), so the open-type rule does not apply.
namespace MechanismFixture.OpenHierarchy
{
    using System;
    using System.IO;

    public sealed class EnvStream : MemoryStream
    {
        public override void Flush() => _ = Environment.GetEnvironmentVariable(Names.Variable);
    }

    public sealed class SafeStream : MemoryStream
    {
        public override void Flush() => _ = string.Concat(Names.Variable, Names.Suffix);
    }

    public class Journal
    {
        public virtual void Flush() => _ = string.Concat(Names.Suffix, Names.Variable);
    }

    public sealed class SafeJournal : Journal
    {
        public override void Flush() => _ = string.Concat(Names.Variable, Names.Suffix);
    }

    public static class Flushers
    {
        public static void FlushIt(Stream stream) => stream.Flush();

        public static void FlushesEnvStream() => FlushIt(new EnvStream());

        // Twin: its own flusher, only ever given SafeStream.
        public static void FlushItSafe(Stream stream) => stream.Flush();

        public static void FlushesSafeStream() => FlushItSafe(new SafeStream());

        public static void FlushesJournal()
        {
            Journal journal = new SafeJournal();
            journal.Flush();
        }
    }
}

// Mechanism: an interface implemented by a method INHERITED from a base class that does not itself implement the
// interface (A2 S1 review C1): `class EnvInheritor : EnvBase, IInheritedProbe {}` - the CLR fills IInheritedProbe.Run
// with EnvBase.Run, which is declared in a type that is not below the interface at all. PlainBase.Run is NOT virtual in
// source; Roslyn emits it `virtual final` so that it can fill the slot. The twin's base and interface are benign.
namespace MechanismFixture.InheritedImpl
{
    using System;

    public interface IInheritedProbe
    {
        string Run();
    }

    public class EnvBase
    {
        public virtual string Run() => Environment.GetEnvironmentVariable(Names.Variable);
    }

    public sealed class EnvInheritor : EnvBase, IInheritedProbe
    {
    }

    public interface IPlainProbe
    {
        string Run();
    }

    public class PlainBase
    {
        public string Run() => Environment.GetEnvironmentVariable(Names.Variable);
    }

    public sealed class PlainInheritor : PlainBase, IPlainProbe
    {
    }

    public interface ISafeInheritedProbe
    {
        string Run();
    }

    public class SafeBase
    {
        public virtual string Run() => string.Concat(Names.Variable, Names.Suffix);
    }

    public sealed class SafeInheritor : SafeBase, ISafeInheritedProbe
    {
    }

    public static class Callers
    {
        public static string CallsInherited()
        {
            IInheritedProbe probe = new EnvInheritor();
            return probe.Run();
        }

        public static string CallsPlainInherited()
        {
            IPlainProbe probe = new PlainInheritor();
            return probe.Run();
        }

        // Twin.
        public static string CallsSafeInherited()
        {
            ISafeInheritedProbe probe = new SafeInheritor();
            return probe.Run();
        }
    }
}

// Mechanism: a C# 11 static abstract interface member implemented by a static method INHERITED from a base class that
// does not itself implement the interface (A2 S1 review 2, W-B): `class SC : SB, IFactory {}` - `T.Make()` with T = SC
// runs SB.Make, which is declared in a type that is not below IFactory at all. csc accepts it, but (the CLR does not
// fill a static slot from a base class by itself) synthesizes a static stub in SC, bound to IFactory.Make by a
// MethodImpl, that calls SB.Make - so CHA reaches the stub as it would any implementation. The stub-less hand-written
// IL form the W-B rule is for is emitted in MechanismDispatchPremiseTests, which also pins this shape; no ground-truth
// row (yet).
namespace MechanismFixture.StaticInherited
{
    using System;

    public interface IFactory
    {
        static abstract string Make();
    }

    public class SB
    {
        public static string Make() => Environment.GetEnvironmentVariable(Names.Variable);
    }

    public sealed class SC : SB, IFactory
    {
    }

    public static class Builders
    {
        public static string Create<T>() where T : IFactory => T.Make();

        public static string CreatesSC() => Create<SC>();
    }
}
