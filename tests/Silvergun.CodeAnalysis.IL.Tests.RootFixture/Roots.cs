// Root classes (R1 S1.2; ADR 0037 decision 4): one namespace per rule, each positive case beside its negative twin.
// Pinned by RootClassTests. Nothing here is ever executed; the assembly is read as metadata.
#pragma warning disable CA2255, CS0465, CS0628, CS0649

// LoadTime: a static method carrying a `root-attribute ... LoadTime` attribute.
namespace RootFixture.LoadTime
{
    using System;
    using System.Runtime.CompilerServices;

    internal static class Startup
    {
        [ModuleInitializer]
        internal static void OnLoad() { }

        // Twin: static, same shape, no attribute.
        internal static void NotOnLoad() { }
    }

    // Attributes no built-in entry names, for the tests that supply their own map.
    [AttributeUsage(AttributeTargets.Method)]
    internal sealed class CustomLoadAttribute : Attribute
    {
    }

    [AttributeUsage(AttributeTargets.Method)]
    internal sealed class CustomInvokeAttribute : Attribute
    {
    }

    internal static class Custom
    {
        [CustomLoad]
        internal static void StaticLoad() { }

        [CustomInvoke]
        internal static void StaticInvoke() { }
    }

    internal sealed class CustomInstance
    {
        // LoadTime needs a static method; RuntimeInvoked does not.
        [CustomLoad]
        internal void InstanceLoad() { }

        [CustomInvoke]
        internal void InstanceInvoke() { }
    }
}

// HostContract: every method, constructors included, of an own type below a `host-contract` type.
namespace RootFixture.Host
{
    using Microsoft.Build.Framework;
    using Microsoft.CodeAnalysis.Diagnostics;

    internal class BuildTask : ITask
    {
        public bool Execute() => true;

        internal void Helper() { }
    }

    // Below the contract through an own base class.
    internal sealed class DerivedBuildTask : BuildTask
    {
        internal void More() { }
    }

    // Below the contract through an own interface, which is tagged itself (S1 review: own interfaces and abstract
    // classes too, since their members run through a concrete subtype).
    internal interface IOwnTask : ITask
    {
        void Log();
    }

    internal sealed class ViaOwnInterface : IOwnTask
    {
        public bool Execute() => false;

        public void Log() { }
    }

    // An own abstract class directly below the contract.
    internal abstract class AbstractTask : ITask
    {
        public abstract bool Execute();

        internal void Shared() { }
    }

    // Below the stub's abstract analyzer: its constructor is what the compiler host runs first.
    internal sealed class Analyzer : DiagnosticAnalyzer
    {
        public Analyzer() { }

        public override void Initialize(object context) { }
    }

    // Twins: the same shape below a contract no entry names, and below none at all.
    internal sealed class NotATask : HostStubs.INotAHostTask
    {
        public bool Execute() => true;
    }

    internal sealed class PlainTask
    {
        public bool Execute() => true;
    }
}

// RuntimeInvoked: a .cctor, a Finalize override, a `root-attribute ... RuntimeInvoked` method.
namespace RootFixture.Runtime
{
    using System;
    using System.Runtime.InteropServices;

    internal static class WithTypeInitializer
    {
        static WithTypeInitializer()
        {
            Value = Environment.TickCount;
        }

        internal static int Value;
    }

    // Twin: a static method that is not a type initializer (and no .cctor at all: no field initializer).
    internal static class WithoutTypeInitializer
    {
        internal static void Initialize() => Value = 1;

        internal static int Value;
    }

    internal sealed class WithFinalizer
    {
        ~WithFinalizer() { }
    }

    // Twins: a new-slot Finalize (hides Object.Finalize, so the runtime never calls it), and a Finalize overload.
    internal class WithNewSlotFinalize
    {
        internal virtual void Finalize() { }
    }

    internal sealed class WithFinalizeOverload
    {
        internal void Finalize(int reason) { }
    }

    internal static class Exports
    {
        [UnmanagedCallersOnly]
        internal static int Exported() => 1;

        // Twin: same shape, no attribute.
        internal static int NotExported() => 1;
    }
}

// PublicApi: visible on a chain of visible types; Family only on an unsealed type; a private explicit implementation.
namespace RootFixture.Api
{
    public class OpenType
    {
        public void PublicMethod() { }

        protected void ProtectedMethod() { }

        protected internal void ProtectedInternalMethod() { }

        internal void InternalMethod() { }

        private protected void PrivateProtectedMethod() { }

        private void PrivateMethod() { }

        public class PublicNested
        {
            public void PublicMethod() { }
        }

        protected class ProtectedNested
        {
            public void PublicMethod() { }
        }

        private class PrivateNested
        {
            public void PublicMethod() { }
        }
    }

    public sealed class SealedType
    {
        public void PublicMethod() { }

        protected void ProtectedMethod() { }

        protected internal void ProtectedInternalMethod() { }

        // Family and FamilyOrAssembly nested types of a sealed container: no subclass can name them (CS0628 allows it).
        protected class ProtectedNested
        {
            public void M() { }
        }

        protected internal class ProtectedInternalNested
        {
            public void M() { }
        }
    }

    public interface IApi
    {
        void Run();
    }

    public sealed class PublicExplicit : IApi
    {
        void IApi.Run() { }
    }

    internal interface IInternalApi
    {
        void Run();
    }

    // Twin: a private explicit implementation of an internal interface, on an internal type.
    internal sealed class InternalExplicit : IInternalApi
    {
        void IInternalApi.Run() { }
    }

    internal class InternalType
    {
        public void PublicMethod() { }
    }
}

// PublicContract: (a) a CHA target of a visible own virtual; (b) filling a slot declared outside the index.
namespace RootFixture.Contract
{
    using System;
    using System.Collections.Generic;

    // (a): an internal implementation of a public interface, escaping through a public factory.
    public interface IWidget
    {
        void Spin();
    }

    internal sealed class Widget : IWidget
    {
        public void Spin() { }
    }

    public static class WidgetFactory
    {
        public static IWidget Create() => new Widget();
    }

    // Twin of (a): the same shape behind an internal interface.
    internal interface IGadget
    {
        void Spin();
    }

    internal sealed class Gadget : IGadget
    {
        public void Spin() { }
    }

    // (b), override: Object.ToString's slot is the platform's.
    internal sealed class Printable
    {
        public override string ToString() => "printable";
    }

    // (b), new slot: IComparer<string>.Compare's slot is the platform's.
    internal sealed class OrdinalComparer : IComparer<string>
    {
        public int Compare(string x, string y) => string.CompareOrdinal(x, y);
    }

    // Twins of (b): a new virtual slot no external interface can name, and an override of an own slot.
    internal class OwnSlot
    {
        public virtual void Go() { }
    }

    internal sealed class OwnSlotOverride : OwnSlot
    {
        public override void Go() { }
    }
}

// Hidden: none of the above.
namespace RootFixture.Hidden
{
    internal sealed class Unreferenced
    {
        internal void Nothing() { }
    }
}

// Native imports: own, external and a P/Invoke.
namespace RootFixture.Native
{
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;

    internal static class NativeMethods
    {
        [DllImport("kernel32.dll")]
        internal static extern uint GetTickCount();

        // Twins: an internalcall (external, not a P/Invoke) and a managed method of the same shape.
        [MethodImpl(MethodImplOptions.InternalCall)]
        internal static extern uint InternalTickCount();

        internal static uint ManagedTickCount() => 0;
    }

    // A delegate: its .ctor, Invoke, BeginInvoke and EndInvoke are runtime-implemented, so external with no body, yet no
    // internalcall (reachability R1, S3): they run what the delegate was bound to.
    internal delegate uint TickSource();
}

// COM interop (S3 review W1): a [ComImport] class, whose implicit constructor C# emits `runtime managed internalcall`, and
// a [ComImport] interface. Both members are body-less, and calling either goes to a COM object: a NativeInterop sink,
// never an internalcall. The twin is an ordinary own interface of the same shape.
namespace RootFixture.Com
{
    using System.Runtime.InteropServices;

    [ComImport, Guid("5B0E3C2A-8F57-4C0E-9C11-7D2A41E3B6F1")]
    public class CoThing
    {
    }

    [ComImport, Guid("0F6E9B47-3A1D-4E52-A8C3-2B9D7E4F1A60"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICoThing
    {
        void Run();
    }

    public interface IPlainThing
    {
        void Run();
    }

    public static class ComCallers
    {
        public static object MakesCoThing() => new CoThing();

        public static void CallsCoThing(ICoThing thing) => thing.Run();

        // Twin: the same call through an ordinary own interface (no implementor).
        public static void CallsPlainThing(IPlainThing thing) => thing.Run();
    }
}

// Live (the RTA tier): a type, or an own subtype, that is concrete and instantiated, a value type, or constructible.
namespace RootFixture.Live
{
    internal sealed class NeverMade
    {
        internal void Run() { }
    }

    internal sealed class Made
    {
        internal void Run() { }
    }

    public class PubliclyConstructible
    {
        public PubliclyConstructible() { }
    }

    // Twin: public, but its only constructor is internal, and nothing makes one.
    public class InternallyConstructible
    {
        internal InternallyConstructible() { }
    }

    internal struct Value
    {
        internal int X;
    }

    internal abstract class AbstractBase
    {
        internal abstract void Run();
    }

    internal sealed class Concrete : AbstractBase
    {
        internal override void Run() { }
    }

    // Twin: the same hierarchy, never instantiated.
    internal abstract class LonelyBase
    {
        internal abstract void Run();
    }

    internal sealed class LonelyConcrete : LonelyBase
    {
        internal override void Run() { }
    }

    public static class Makers
    {
        public static object MakeMade() => new Made();

        public static object MakeConcrete() => new Concrete();
    }
}
