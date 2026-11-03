namespace MechanismFixture.Debug
{
    // Constants shared by every Debug mechanism, as in MechanismFixture's Names. `const`, so each use is an inline
    // ldstr: no fixture method gains a call or a field load (and so no graph edge) just by naming one.
    //
    // NOTHING in this assembly is ever executed by the test suite - it is read from disk as metadata - but the
    // sink argument is still chosen to be inert if it ever were: an environment variable nobody sets.
    internal static class Names
    {
        public const string Variable = "SILVERGUN_MECHANISM_FIXTURE";
        public const string Suffix = "=";
    }
}
