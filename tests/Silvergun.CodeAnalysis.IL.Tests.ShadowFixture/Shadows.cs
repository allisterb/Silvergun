extern alias platform;

// The shadows: the platform's namespace, type and member names, with benign bodies. Declared in source, so inside
// this assembly an unqualified System.Environment / System.IDisposable binds to THESE (CS0436).
namespace System
{
    public static class Environment
    {
        public static string GetEnvironmentVariable(string variable) => string.Concat(variable, ShadowFixture.Names.Suffix);
    }

    public interface IDisposable
    {
        void Dispose();
    }
}

namespace ShadowFixture
{
    internal static class Names
    {
        public const string Variable = "SILVERGUN_SHADOW_FIXTURE";
        public const string Suffix = "=";
    }

    public static class Callers
    {
        // The REAL sink: [System.Runtime]System.Environment.GetEnvironmentVariable(System.String).
        public static string ReadsPlatformEnvironment() => platform::System.Environment.GetEnvironmentVariable(Names.Variable);

        // The own shadow, same node id: System.Environment.GetEnvironmentVariable(System.String).
        public static string ReadsShadowEnvironment() => System.Environment.GetEnvironmentVariable(Names.Variable);
    }

    // Implements the PLATFORM System.IDisposable.
    public sealed class PlatformDisposable : platform::System.IDisposable
    {
        public void Dispose()
        {
        }
    }

    // Implements the OWN System.IDisposable.
    public sealed class ShadowDisposable : System.IDisposable
    {
        public void Dispose()
        {
        }
    }
}
