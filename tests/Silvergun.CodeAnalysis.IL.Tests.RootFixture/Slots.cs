// PublicContract rule (b) regressions from the S1 review (R1 S1.2, the PublicContract row): virtuals whose slot may be
// declared outside the index, which the first ImplementsExternalSlot missed. Every type is internal, so PublicApi never
// applies. Pinned by RootClassTests. Nothing here is ever executed.
#pragma warning disable CS0659, CS0661

namespace RootFixture.Slots
{
    using System;
    using System.Collections.Generic;

    // Records: D.Equals(object) overrides the platform slot; D.Equals(R) overrides R.Equals(R), which implements the
    // platform IEquatable<R> (so it is a CHA target of a rule-(b) method, rule a).
    internal record R(int X);

    internal record D(int X, int Y) : R(X);

    // An own class ancestor's new slot of the same name and arity but different parameters does not mask Equals(object).
    internal class EqBase
    {
        public virtual bool Equals(EqBase other) => ReferenceEquals(this, other);
    }

    internal sealed class EqDerived : EqBase
    {
        public override bool Equals(object obj) => obj is EqDerived;
    }

    // An own interface declaring ToString does not mask Object.ToString's slot.
    internal interface INamed
    {
        string ToString();
    }

    internal sealed class Named : INamed
    {
        public override string ToString() => "named";
    }

    // One new-slot method fills an own interface's slot and the platform's at once.
    internal interface IMyDisposable
    {
        void Dispose();
    }

    internal sealed class Both : IDisposable, IMyDisposable
    {
        public void Dispose() { }
    }

    // An interface's explicit default implementation of a platform interface member.
    internal interface IDim : IEnumerable<int>
    {
        IEnumerator<int> IEnumerable<int>.GetEnumerator() => null;
    }

    // An abstract own base implementing a platform interface: the abstract slot (rule b) and its override (rule a).
    internal abstract class CmpBase : IComparer<string>
    {
        public abstract int Compare(string x, string y);
    }

    internal sealed class CmpImpl : CmpBase
    {
        public override int Compare(string x, string y) => string.CompareOrdinal(x, y);
    }

    // Twins: a fresh internal virtual nothing outside declares, and an override of an own new slot with exactly the
    // same, fully known parameters.
    internal class Fresh
    {
        internal virtual void Go() { }
    }

    internal class SlotBase
    {
        internal virtual void Take(string value) { }
    }

    internal sealed class SlotOverride : SlotBase
    {
        internal override void Take(string value) { }
    }

    // Errs toward true: a generic ancestor's slot (parameter !0) does not mask an override in a closed subclass.
    internal class GenericSlot<T>
    {
        internal virtual void Take(T value) { }
    }

    internal sealed class ClosedSlotOverride : GenericSlot<string>
    {
        internal override void Take(string value) { }
    }

    // N2: from another assembly, OtherBase's internal slot is inaccessible, so this binds to Object.ToString's slot.
    internal sealed class CrossAssemblyOverride : RootFixture.Other.OtherBase
    {
        public override string ToString() => "cross";
    }
}

// N1 (S1 review): a public static method may implement a platform static abstract member that generic code calls back.
namespace RootFixture.Statics
{
    using System.Numerics;

    internal readonly struct Num : IAdditionOperators<Num, Num, Num>
    {
        public static Num operator +(Num left, Num right) => left;

        // Twin: private and not an explicit implementation.
        private static Num Twice(Num value) => value + value;

        internal static Num UseTwice(Num value) => Twice(value);
    }

    // Twin: a public static method on an internal type that implements no external interface.
    internal static class Helpers
    {
        public static int Pure(int value) => value;
    }
}
