// Reachability R2b, S1 (ADR 0037 amendment a1/a2): the runtime classes, and the Direct label on delegate creation and
// method handles.
// Pinned by DelegateRootTests. Nothing here is ever executed; the assembly is read as metadata. Every payload is an
// inert capability reference (a relative dummy file name, an HttpClient with no address).
#pragma warning disable CA2255

namespace DelegateRootFixture
{
    internal static class Names
    {
        internal const string File = "x";
        internal const string Suffix = "y";
    }
}

// Adversarial: a type initializer that only CREATES a delegate to its payload (an ldftn) and hands it to something that
// runs it later. Each must reach the payload's capability at TypeInitializer, without the Direct label. Each twin has the
// same shape, with a payload that reaches no capability.
namespace DelegateRootFixture.Scheduled
{
    using System;
    using System.IO;
    using System.Net.Http;
    using System.Reflection;
    using System.Runtime.Loader;
    using System.Threading;
    using System.Threading.Tasks;

    internal static class ViaTaskRun
    {
        static ViaTaskRun() => Task.Run(Payload);

        private static void Payload() => _ = File.Exists(Names.File);
    }

    internal static class ViaTaskRunSafe
    {
        static ViaTaskRunSafe() => Task.Run(Payload);

        private static void Payload() => _ = string.Concat(Names.File, Names.Suffix);
    }

    internal static class ViaThread
    {
        static ViaThread() => new Thread(Payload).Start();

        private static void Payload() => _ = File.Exists(Names.File);
    }

    internal static class ViaThreadSafe
    {
        static ViaThreadSafe() => new Thread(Payload).Start();

        private static void Payload() => _ = string.Concat(Names.File, Names.Suffix);
    }

    internal static class ViaTimer
    {
        static ViaTimer() => timer = new Timer(Payload, null, 0, Timeout.Infinite);

        private static void Payload(object state) => _ = new HttpClient();

        private static Timer timer;
    }

    internal static class ViaTimerSafe
    {
        static ViaTimerSafe() => timer = new Timer(Payload, null, 0, Timeout.Infinite);

        private static void Payload(object state) => _ = string.Concat(Names.File, Names.Suffix);

        private static Timer timer;
    }

    internal static class ViaResolving
    {
        static ViaResolving() => AssemblyLoadContext.Default.Resolving += Payload;

        private static Assembly Payload(AssemblyLoadContext context, AssemblyName name)
        {
            _ = File.Exists(Names.File);
            return null;
        }
    }

    internal static class ViaResolvingSafe
    {
        static ViaResolvingSafe() => AssemblyLoadContext.Default.Resolving += Payload;

        private static Assembly Payload(AssemblyLoadContext context, AssemblyName name)
        {
            _ = string.Concat(Names.File, Names.Suffix);
            return null;
        }
    }

    // One own helper between the initializer and whatever runs the delegate: the shape that defeats a "scheduled
    // delegate" heuristic (amendment a2, rejected alternative).
    internal static class ViaHelper
    {
        static ViaHelper() => Helper(new Action(Payload));

        private static void Helper(Action action) => action();

        private static void Payload() => _ = File.Exists(Names.File);
    }

    internal static class ViaHelperSafe
    {
        static ViaHelperSafe() => Helper(new Action(Payload));

        private static void Helper(Action action) => action();

        private static void Payload() => _ = string.Concat(Names.File, Names.Suffix);
    }

    // Control: a type initializer that calls the capability itself, with no delegate: Direct. Named to sort after every
    // Via* type, so only the Direct-first example order (not node order) puts it first.
    internal static class WithoutDelegate
    {
        static WithoutDelegate() => _ = File.Exists(Names.File);
    }

    internal static class WithoutDelegateSafe
    {
        static WithoutDelegateSafe() => _ = string.Concat(Names.File, Names.Suffix);
    }
}

// Adversarial, by a method handle (S0-S3 review, W3): a type initializer that only BUILDS an expression tree over its
// payload. The lambda's body compiles to an ldtoken of Payload (MethodBase.GetMethodFromHandle, then Expression.Call), so
// the payload is reached by a LoadToken edge alone; it would run only if the tree were compiled and invoked, which
// nothing here does. It must reach the payload's capability at TypeInitializer, without the Direct label. The twin has
// the same shape with a payload that reaches no capability.
namespace DelegateRootFixture.Tokens
{
    using System;
    using System.IO;
    using System.Linq.Expressions;

    internal static class ViaExpressionTree
    {
        static ViaExpressionTree() => expression = () => Payload();

        private static void Payload() => _ = File.Exists(Names.File);

        private static Expression<Action> expression;
    }

    internal static class ViaExpressionTreeSafe
    {
        static ViaExpressionTreeSafe() => expression = () => Payload();

        private static void Payload() => _ = string.Concat(Names.File, Names.Suffix);

        private static Expression<Action> expression;
    }
}

// Name bounding (amendment a5; S0-S3 review W2): a public method whose node id is over 1,024 chars, so a report on this
// assembly cuts exactly one name. C# caps an identifier at 512 chars and metadata a type's full name at 1,023, so the
// length comes from the signature: three parameters of one type named "Long_Name_" 45 times (450 chars). Inert like
// every payload here.
namespace DelegateRootFixture.LongNames
{
    public sealed class Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_
    {
    }

    public static class Probe
    {
        public static bool Exists(
            Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_ a,
            Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_ b,
            Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_Long_Name_ c) =>
            System.IO.File.Exists(DelegateRootFixture.Names.File);
    }
}

// Finalizer: ~T() overrides Object.Finalize, run on the GC's finalizer thread.
namespace DelegateRootFixture.Finalizers
{
    using System.IO;

    internal sealed class FileFinalized
    {
        ~FileFinalized() => _ = File.Exists(Names.File);
    }

    internal sealed class SafeFinalized
    {
        ~SafeFinalized() => _ = string.Concat(Names.File, Names.Suffix);
    }
}

// NativeEntry: an [UnmanagedCallersOnly] method, which native code calls in to.
namespace DelegateRootFixture.Exports
{
    using System.IO;
    using System.Runtime.InteropServices;

    internal static class NativeExports
    {
        [UnmanagedCallersOnly]
        internal static int ProbesFile() => File.Exists(Names.File) ? 1 : 0;

        [UnmanagedCallersOnly]
        internal static int ProbesNothing() => string.Concat(Names.File, Names.Suffix).Length;
    }
}
