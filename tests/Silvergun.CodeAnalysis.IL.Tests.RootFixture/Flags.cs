// Model flags the analysis-net fork records (R1 S1.1): visibility of types, methods, fields and enum constants;
// abstract/sealed classes; sealed, new-slot and P/Invoke methods. Pinned by ModelDefinitionFlagsTests.
#pragma warning disable CS0169, CS0414, CS0628, CS0649

namespace RootFixture.Flags
{
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;

    public class Accessibility
    {
        public void PublicMethod() { }

        internal void InternalMethod() { }

        private void PrivateMethod() { }

        protected void ProtectedMethod() { }

        protected internal void ProtectedInternalMethod() { }

        private protected void PrivateProtectedMethod() { }

        public int PublicField;
        internal int InternalField;
        private int privateField;
        protected int ProtectedField;
        protected internal int ProtectedInternalField;
        private protected int PrivateProtectedField;

        // Nested at depth 1 and depth 2.
        public class PublicNested
        {
            public class PublicDeeper
            {
            }

            private class PrivateDeeper
            {
            }
        }

        private class PrivateNested
        {
        }

        protected class ProtectedNested
        {
        }

        internal class InternalNested
        {
        }

        protected internal class ProtectedInternalNested
        {
        }

        private protected class PrivateProtectedNested
        {
        }
    }

    internal class InternalType
    {
    }

    public struct PublicStruct
    {
        public int X;
    }

    internal struct InternalStruct
    {
    }

    public interface IPublicInterface
    {
        void Run();
    }

    internal interface IInternalInterface
    {
    }

    public enum PublicEnum
    {
        First,
        Second,
    }

    internal enum InternalEnum
    {
        Only,
    }

    public abstract class AbstractShape
    {
        public abstract void Draw();

        public virtual void Resize() { }

        public void Plain() { }
    }

    public class OpenShape : AbstractShape
    {
        public override void Draw() { }

        public sealed override void Resize() { }
    }

    public sealed class SealedShape : AbstractShape
    {
        public override void Draw() { }
    }

    public static class StaticShape
    {
        public static void Nothing() { }
    }

    public class ExplicitShape : IPublicInterface
    {
        void IPublicInterface.Run() { }
    }

    public static class Externs
    {
        [DllImport("kernel32.dll")]
        public static extern uint GetTickCount();

        // An internalcall: external like the P/Invoke, but not a P/Invoke.
        [MethodImpl(MethodImplOptions.InternalCall)]
        public static extern void InternalCall();

        public static uint Managed() => 0;
    }
}
