namespace Silvergun.CodeAnalysis.IL;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

using Microsoft.Cci;

/// <summary>
/// One page of a method's CIL listing (<see cref="MethodListing"/>). <see cref="Type"/>, <see cref="Name"/>, <see cref="Id"/>
/// and every package name or string in <see cref="Text"/> went through the caller's display function. <see cref="Next"/> is
/// the IL offset the next page starts at, or null when the listing is whole from the page's start.
/// </summary>
public sealed record MethodListingPage(bool Found, string? Type, string? Name, string? Id, MemberBody Body, uint IlBytes, int MaxStack, int Locals,
    int Instructions, int Shown, uint? Next, string Text)
{
    #region Properties
    /// <summary>Exception handlers the page that ends the listing could not show: they did not fit, or were past the cap.</summary>
    public int HandlersNotShown { get; init; }
    #endregion
}

/// <summary>
/// Lists one method's CIL from CCI's operations (MCP task S3, <c>disassemble</c>): a header, one line per instruction from an
/// IL offset, and the exception handlers once the listing reaches the end. Member and type operands carry their own metadata
/// token when they have one. CCI's array pseudo-instructions are shown as the calls they replace. Every operand is read under
/// its own guard; never throws.
/// </summary>
public static class MethodListing
{
    #region Methods
    /// <summary>
    /// The page of the method with MethodDef <paramref name="token"/> from IL offset <paramref name="from"/>, within
    /// <paramref name="maxChars"/>. <paramref name="display"/> turns package text into displayable text of at most the given
    /// chars (escaped, bounded).
    /// </summary>
    public static MethodListingPage Render(AssemblyAnalyzer assembly, uint token, uint from, int maxChars, Func<string, int, string> display)
    {
        if (Find(assembly, token) is not { } method)
            return new(false, null, null, null, MemberBody.None, 0, 0, 0, 0, 0, null, string.Empty);

        var context = new Context(display);
        var type = context.Show(Guard(() => AssemblyAnalyzer.TypeName(method.ContainingTypeDefinition), "<unknown>"));
        var name = context.Show(AssemblyAnalyzer.SafeName(method));
        var id = context.Show(CciNames.Of(method).ToString(), IdChars);
        var read = AssemblyAnalyzer.TryReadBody(method);
        var text = new StringBuilder();
        text.Append(CultureInfo.InvariantCulture, $".method {id}  // token 0x{token:x8}\n");
        if (read.Body is not { } body)
        {
            var kind = read.IsUnreadable ? MemberBody.Unreadable : MemberBody.None;
            text.Append(read.IsUnreadable ? "// the body could not be read\n" : "// no IL body (abstract, extern, a P/Invoke or a runtime method)\n");
            return new(true, type, name, id, kind, 0, 0, 0, 0, 0, null, text.ToString().TrimEnd('\n'));
        }

        var size = Guard(() => body.Size);
        var locals = Guard(() => body.LocalVariables.ToArray(), []);
        var maxStack = Guard(() => (int)body.MaxStack);
        text.Append(CultureInfo.InvariantCulture, $".size {size}  .maxstack {maxStack}  .locals {locals.Length}{(Guard(() => body.LocalsAreZeroed) ? " init" : "")}\n");
        foreach (var (local, i) in locals.Take(MaxLocals).Select((l, i) => (l, i)))
            text.Append(CultureInfo.InvariantCulture, $"  V_{i}: {context.Show(Guard(() => CciNames.TypeName(local.Type), CanonicalName.UnknownPart), LocalChars)}\n");
        if (locals.Length > MaxLocals)
            text.Append(CultureInfo.InvariantCulture, $"  // {locals.Length - MaxLocals} more locals\n");

        context.Locals = locals;
        // The last lines (a note, a count) always fit in what the instructions and handlers leave.
        var limit = maxChars - NoteChars;
        var (instructions, shown, handlersNotShown) = (0, 0, 0);
        uint? next = null;
        try
        {
            foreach (var op in body.Operations)
            {
                if (++instructions > MaxInstructions)
                    break;
                if (next is not null || op.Offset < from)
                    continue;
                var line = Guard(() => Line(op, context), $"IL_{Guard(() => op.Offset):x4}: <unreadable instruction>") + "\n";
                if (text.Length + line.Length > limit)
                {
                    next = op.Offset;
                    continue;
                }
                text.Append(line);
                shown++;
            }
        }
        catch (Exception ex)
        {
            text.Append(CultureInfo.InvariantCulture, $"// the instructions could not all be read ({ex.GetType().Name})\n");
        }
        if (instructions > MaxInstructions)
            text.Append(CultureInfo.InvariantCulture, $"// stopped after {MaxInstructions} instructions\n");

        if (next is null)
        {
            var handlers = Guard(() => body.OperationExceptionInformation.Take(MaxHandlers).Select(h => Handler(h, context) + "\n").ToArray(),
                ["// the exception handlers could not be read\n"]);
            if (shown > 0 && text.Length + handlers.Sum(h => h.Length) > limit)
                next = size;   // the handlers come on a page of their own
            else
            {
                // As many as fit; the rest, and any past MaxHandlers, are counted (S3 review W4).
                var fit = 0;
                while (fit < handlers.Length && text.Length + handlers[fit].Length <= limit)
                    text.Append(handlers[fit++]);
                // Unread handlers (the "could not be read" line stands for them) are not counted as shown.
                handlersNotShown = Guard(() => body.OperationExceptionInformation.Count(), -1) is var total and >= 0 ? Math.Max(0, total - fit) : 0;
                if (handlersNotShown > 0)
                    text.Append(CultureInfo.InvariantCulture, $"// {handlersNotShown} more exception handlers not shown\n");
            }
        }
        return new(true, type, name, id, MemberBody.Il, size, maxStack, locals.Length, Math.Min(instructions, MaxInstructions), shown, next, text.ToString().TrimEnd('\n'))
        {
            HandlersNotShown = handlersNotShown,
        };
    }

    // The method definition with `token`, by the module's token decoder, else by a walk.
    private static IMethodDefinition? Find(AssemblyAnalyzer assembly, uint token)
    {
        if (Guard(() => (assembly.Module as ITokenDecoder)?.GetObjectForToken(token) as IMethodDefinition) is { } decoded && AssemblyMembers.Token(decoded) == token)
            return decoded;
        return Guard(() => assembly.Module.GetAllTypes().SelectMany(t => t.Methods).FirstOrDefault(m => AssemblyMembers.Token(m) == token));
    }

    private static string Line(IOperation op, Context context)
    {
        var (opcode, operand) = op.OperationCode switch
        {
            OperationCode.Array_Create or OperationCode.Array_Create_WithLowerBound => ("newobj", ArrayMethod(op.Value, ".ctor", context)),
            OperationCode.Array_Get => ("call", ArrayMethod(op.Value, "Get", context)),
            OperationCode.Array_Set => ("call", ArrayMethod(op.Value, "Set", context)),
            OperationCode.Array_Addr => ("call", ArrayMethod(op.Value, "Address", context)),
            var code => (code.ToString().ToLowerInvariant().Replace('_', '.'), Operand(op, context)),
        };
        return operand.Length == 0 ? $"IL_{op.Offset:x4}: {opcode}" : $"IL_{op.Offset:x4}: {opcode} {operand}";
    }

    private static string Operand(IOperation op, Context context) => op.Value switch
    {
        null when IsArgument(op.OperationCode) => "this",
        null => string.Empty,
        string s => $"\"{context.Show(s, StringChars)}\"",
        uint target => $"IL_{target:x4}",
        uint[] targets => $"({string.Join(", ", targets.Take(MaxSwitchTargets).Select(t => $"IL_{t:x4}"))}{(targets.Length > MaxSwitchTargets ? $", ... {targets.Length - MaxSwitchTargets} more" : "")})",
        IParameterDefinition parameter => Guard(() => parameter.Name.Value, "") is { Length: > 0 } named ? context.Show(named) : $"arg{Guard(() => (int)parameter.Index)}",
        ILocalDefinition local => Array.IndexOf(context.Locals, local) is var i and >= 0 ? $"V_{i}" : "V_?",
        IFunctionPointerTypeReference pointer => $"{Token(pointer)}{context.Show(CciNames.TypeName(pointer), IdChars)}",
        IMethodReference method => $"{Token(method)}{context.Show(CciNames.Of(method).ToString(), IdChars)}",
        IFieldReference field => $"{Token(field)}{context.Show(CciNames.TypeName(Guard(() => field.ContainingType)))}::{context.Show(Guard(() => field.Name.Value, ""))}",
        ITypeReference type => $"{Token(type)}{context.Show(CciNames.TypeName(type))}",
        float f => f.ToString("R", CultureInfo.InvariantCulture),
        double d => d.ToString("R", CultureInfo.InvariantCulture),
        IFormattable number => number.ToString(null, CultureInfo.InvariantCulture),
        var other => $"<{other.GetType().Name}>",
    };

    private static string ArrayMethod(object? value, string name, Context context) =>
        $"{context.Show(value is ITypeReference type ? CciNames.TypeName(type) : CanonicalName.UnknownPart)}::{name}";

    private static string Handler(IOperationExceptionInformation h, Context context)
    {
        var kind = h.HandlerKind switch
        {
            HandlerKind.Catch => $"catch {Token(h.ExceptionType)}{context.Show(CciNames.TypeName(h.ExceptionType))}",
            HandlerKind.Filter => $"filter IL_{h.FilterDecisionStartOffset:x4}",
            HandlerKind.Finally => "finally",
            HandlerKind.Fault => "fault",
            _ => "handler",
        };
        return $".try IL_{h.TryStartOffset:x4} to IL_{h.TryEndOffset:x4} {kind} handler IL_{h.HandlerStartOffset:x4} to IL_{h.HandlerEndOffset:x4}";
    }

    // "[0x0a000012] " for a reference read from a metadata table; nothing for one that only occurs in a signature.
    private static string Token(object reference) =>
        Guard(() => reference is IMetadataObjectWithToken { TokenValue: var token } && token != uint.MaxValue ? $"[0x{token:x8}] " : "", "");

    private static bool IsArgument(OperationCode code) => code is OperationCode.Ldarg_0 or OperationCode.Ldarg_1 or OperationCode.Ldarg_2 or OperationCode.Ldarg_3
        or OperationCode.Ldarg or OperationCode.Ldarg_S or OperationCode.Ldarga or OperationCode.Ldarga_S or OperationCode.Starg or OperationCode.Starg_S;

    private static T Guard<T>(Func<T> read, T fallback = default!) => AssemblyMembers.Guard(read, fallback);
    #endregion

    #region Fields
    private const int NameChars = 512;
    private const int IdChars = 1024;
    private const int StringChars = 512;
    private const int LocalChars = 128;
    private const int NoteChars = 128;
    private const int MaxLocals = 16;
    private const int MaxSwitchTargets = 32;
    private const int MaxHandlers = 64;
    private const int MaxInstructions = 1_000_000;
    #endregion

    #region Types
    // The page's locals (ldloc operands name them by index) and the caller's display function.
    private sealed class Context(Func<string, int, string> display)
    {
        public ILocalDefinition[] Locals { get; set; } = [];

        public string Show(string? text, int max = NameChars) => display(text ?? CanonicalName.UnknownPart, max);
    }
    #endregion
}
