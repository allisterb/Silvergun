// Mechanism: expression trees. The lambda is never compiled to an own method: C# builds an Expression tree that
// names the sink by METADATA TOKEN (ldtoken + MethodBase.GetMethodFromHandle + Expression.Call), and Compile() turns
// it into code at run time. No call/callvirt/newobj/ldftn names the sink, so the static graph has no edge to it -
// a KnownGap until A2 decides on an ldtoken method edge (spec §2.5). Compile itself is classified
// DynamicCodeLoading, so both methods - interesting and twin - DO reach a capability; the rows are about the sink.
namespace MechanismFixture.ExpressionTree
{
    using System;
    using System.Linq.Expressions;

    public static class Trees
    {
        public static string CompilesEnvTree()
        {
            Expression<Func<string>> read = () => Environment.GetEnvironmentVariable(Names.Variable);
            return read.Compile()();
        }

        // Twin: the same tree shape with the sink replaced by safe System.String.Concat.
        public static string CompilesSafeTree()
        {
            Expression<Func<string>> read = () => string.Concat(Names.Variable, Names.Suffix);
            return read.Compile()();
        }
    }
}
