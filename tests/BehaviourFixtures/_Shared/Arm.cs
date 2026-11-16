// The inertness gate of every behaviour fixture: NOT const, so Roslyn keeps the code after `if (!Arm.Armed) return;`.
internal static class Arm
{
    internal static readonly bool Armed = false;
}
