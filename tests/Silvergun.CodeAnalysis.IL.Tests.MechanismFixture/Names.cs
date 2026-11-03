namespace MechanismFixture
{
    // Constants shared by every mechanism. `const`, so each use is an inline ldstr: no fixture method gains a
    // call or a field load (and so no graph edge) just by naming one.
    //
    // NOTHING in this assembly is ever executed by the test suite - it is read from disk as metadata - but the
    // sink arguments are still chosen to be inert if it ever were: an environment variable nobody sets, a
    // relative file that does not exist, a host under the reserved .invalid TLD, a program that does not exist.
    internal static class Names
    {
        public const string Variable = "SILVERGUN_MECHANISM_FIXTURE";
        public const string FilePath = "silvergun-mechanism-fixture.txt";
        public const string Host = "silvergun-mechanism-fixture.invalid";
        public const string Program = "silvergun-mechanism-fixture-does-not-exist";
        public const string Suffix = "=";
    }
}
