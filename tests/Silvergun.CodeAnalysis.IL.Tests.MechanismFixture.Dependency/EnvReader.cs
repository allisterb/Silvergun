namespace MechanismFixture.Dependency
{
    using System;

    // The far side of the CrossAssembly mechanism: MechanismFixture.CrossAssembly.Callers calls into here, so the
    // only path from those callers to the sink crosses an assembly boundary. Read is the interesting method,
    // ReadSafe its uninteresting twin (identical except the sink is a `safe` string call).
    public static class EnvReader
    {
        public static string Read() => Environment.GetEnvironmentVariable(Variable);

        public static string ReadSafe() => string.Concat(Variable, "=");

        private const string Variable = "SILVERGUN_MECHANISM_FIXTURE";
    }
}
