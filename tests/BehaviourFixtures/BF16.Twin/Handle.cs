// Inert fixture: never executed (gated by Arm.Armed). BF16 twin: a finalizer that frees a GCHandle.
using System.Runtime.InteropServices;

namespace Behaviour
{
    public sealed class Pinned
    {
        private GCHandle handle = GCHandle.Alloc(new byte[16], GCHandleType.Pinned);

        ~Pinned()
        {
            if (!Arm.Armed) return;
            if (handle.IsAllocated)
                handle.Free();
        }
    }
}
