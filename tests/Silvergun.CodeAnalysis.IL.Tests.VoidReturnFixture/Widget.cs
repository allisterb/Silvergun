namespace Silvergun.CodeAnalysis.IL.Tests.VoidReturnFixture
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Regression fixture for the TAC void-return fix (docs/agent/measurements/tac-platformtypes-spike.md):
    /// <c>ext/analysis-net</c>'s <c>Disassembler</c> compared method return types against
    /// <c>PlatformTypes.Void</c>, which is pinned to assembly <c>"mscorlib"</c>, so the comparison never
    /// matched on modern IL (<c>[System.Runtime]</c>/<c>[System.Private.CoreLib]</c> <c>System.Void</c>).
    /// This source is compiled TWICE, byte-for-byte identical - once for <c>net472</c> (mscorlib, the
    /// control that was never affected) and once for <c>net10.0</c> (the flavour that broke) - so tests can
    /// assert both that the lifted TAC on the fixed flavour is correct AND that the two builds agree, which
    /// is the property the fix restores. Every method here is analyzed statically; nothing is ever executed.
    /// </summary>
    public class Widget
    {
        private readonly List<int> items = new List<int>();
        private int count;

        /// <summary>Plain void setter - fix site 1 (<c>ProcessReturn</c>): a bare <c>ret</c> with no operand.</summary>
        public int Count
        {
            get { return count; }
            set { count = value; }
        }

        /// <summary>A loop calling a void method (<c>List&lt;T&gt;.Add</c>) - fix site 2 (direct call).</summary>
        public void FillItems(int n)
        {
            for (var i = 0; i < n; i++)
            {
                items.Add(i);
            }
        }

        /// <summary><c>try/finally</c> calling a void method (<c>Console.WriteLine</c>) in the <c>finally</c> - fix site 2.</summary>
        public void SafeClear()
        {
            try
            {
                items.Clear();
                count = 0;
            }
            finally
            {
                Console.WriteLine("cleared");
            }
        }

        /// <summary><c>try/catch/finally</c>, also calling a void method in the <c>finally</c> - fix site 2.</summary>
        public void RiskyOperation()
        {
            try
            {
                count = 10 / count;
            }
            catch (DivideByZeroException)
            {
                count = -1;
            }
            finally
            {
                Console.WriteLine("done");
            }
        }

        /// <summary>A single, explicit direct call to a void method on the same type - fix site 2, isolated
        /// from any loop/EH shape so a regression here cannot hide behind one of the other methods.</summary>
        public void CallsHelper()
        {
            Helper();
        }

        /// <summary>
        /// Positive control for the call-site assertions: calls a NON-void method (<c>Math.Abs</c>), whose
        /// TAC call instruction must still get a result variable - proves "no result on a void call" isn't
        /// vacuously true for every call regardless of the callee's signature.
        /// </summary>
        public int CallsNonVoidMethod()
        {
            return Math.Abs(count);
        }

        private void Helper()
        {
            count++;
        }
    }
}
