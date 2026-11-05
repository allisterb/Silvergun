// N2 (S1 review): an assembly-only new slot masks an override only from its own assembly.
namespace RootFixture.Other
{
    public class OtherBase
    {
        // Hides Object.ToString with a slot only this assembly can override.
        internal new virtual string ToString() => "other";
    }

    // Same assembly: overrides the internal slot, so the slot is own and the override Hidden.
    internal sealed class SameAssemblyOverride : OtherBase
    {
        internal override string ToString() => "same";
    }
}
