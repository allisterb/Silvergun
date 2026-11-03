// Mechanism: generics. Every call site below is a reference through an INSTANTIATION (Foo<A>, Box<int>,
// Wraps<int>), which carries substituted parameter types - so its call-site name differs from the definition's
// node id (ADR-0020 amendment 6). The waypoints name the DEFINITIONS (!0 / !!0).
namespace MechanismFixture.Generics
{
    using System;

    // A constrained interface call inside a generic method, instantiated from non-generic code.
    public interface IBaz
    {
        string Baz();
    }

    public sealed class A : IBaz
    {
        public string Baz() => Environment.GetEnvironmentVariable(Names.Variable);
    }

    public interface ISafeBaz
    {
        string Baz();
    }

    public sealed class SafeA : ISafeBaz
    {
        public string Baz() => string.Concat(Names.Variable, Names.Suffix);
    }

    public static class Constrained
    {
        public static string Foo<T>(T item) where T : IBaz => item.Baz();

        public static string Bar() => Foo(new A());

        // Twin.
        public static string FooSafe<T>(T item) where T : ISafeBaz => item.Baz();

        public static string BarSafe() => FooSafe(new SafeA());
    }

    // An own generic type, called through a closed instantiation: the known 95-99% join miss.
    public sealed class Box<T>
    {
        public T Item;

        public string Run() => Environment.GetEnvironmentVariable(Names.Variable);
    }

    public sealed class SafeBox<T>
    {
        public T Item;

        public string Run() => string.Concat(Names.Variable, Names.Suffix);
    }

    public static class Boxes
    {
        public static string RunsBox() => new Box<int>().Run();

        // Twin.
        public static string RunsSafeBox() => new SafeBox<int>().Run();
    }

    // A capturing lambda nested in a generic method: its display class is itself generic.
    public static class Closures
    {
        public static string Wraps<T>(T value, string name)
        {
            Func<string> read = () => value is null ? null : Environment.GetEnvironmentVariable(name);
            return read();
        }

        public static string WrapsInt() => Wraps(42, Names.Variable);

        // Twin.
        public static string WrapsSafe<T>(T value, string name)
        {
            Func<string> read = () => value is null ? null : string.Concat(name, Names.Suffix);
            return read();
        }

        public static string WrapsIntSafe() => WrapsSafe(42, Names.Variable);
    }
}
