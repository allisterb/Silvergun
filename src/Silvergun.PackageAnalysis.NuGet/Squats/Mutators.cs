// Ported from OSSGadget (oss-find-squats-lib/Mutators), (c) Microsoft Corporation, MIT License.
// Copy authorized 2026-07-16. Source: reference/projects/OSSGadget-main/src/oss-find-squats-lib/Mutators/*.cs
// Faithful ports of the pure-string Generate(string) form. The PackageURL/Generate(PackageURL) overload and
// the packageurl-dotnet dependency were dropped. Homoglyph and keyboard tables are kept verbatim.
// NamespaceInNameMutator/RemoveNamespaceMutator operated on purl namespaces (npm-style scopes) via PackageURL;
// NuGet package ids carry no such namespace, so those ports yield nothing for a plain id (retained for parity).
namespace Silvergun.PackageAnalysis.NuGet.Squats;

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;

/// <summary>Adds a character from a default keyboard set at each position.</summary>
public sealed class AddCharacterMutator : IMutator
{
    #region Constructors
    public AddCharacterMutator(char[]? additionalChars = null, char[]? overrideChars = null, char[]? skipChars = null)
    {
        if (overrideChars != null) characters = overrideChars.ToList();
        if (additionalChars != null) characters.AddRange(additionalChars);
        if (skipChars != null) characters.RemoveAll(skipChars.Contains);
    }
    #endregion

    #region Properties
    public MutatorType Kind => MutatorType.AddCharacter;
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string arg)
    {
        for (int i = 0; i < arg.Length + 1; i++)
        {
            // Can't add a character before an @ for a scoped package.
            if (i == 0 && arg[i] == '@') continue;

            foreach (char c in characters)
            {
                yield return new Mutation(
                    Mutated: $"{arg[..i]}{c}{arg[i..]}",
                    Original: arg,
                    Reason: $"Character Added: {c}",
                    Mutator: Kind);
            }
        }
    }
    #endregion

    #region Fields
    private readonly List<char> characters = new()
    {
        '1','2','3','4','5','6','7','8','9','0','-','q','w','e','r','t','y','u','i','o','p','a','s','d','f','g','h','j','k','l','z','x','c','v','b','n','m','.',
    };
    #endregion
}

/// <summary>Adds a character that already exists in the string at each position.</summary>
public sealed class AddContainingCharacterMutator : IMutator
{
    #region Properties
    public MutatorType Kind => MutatorType.AddContainingCharacter;
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string arg)
    {
        char[] chars = arg.Distinct().ToArray();
        for (int i = 0; i < arg.Length + 1; i++)
        {
            // Can't add a character before an @ for a scoped package.
            if (i == 0 && arg[i] == '@') continue;

            foreach (char c in chars)
            {
                yield return new Mutation(
                    Mutated: $"{arg[..i]}{c}{arg[i..]}",
                    Original: arg,
                    Reason: $"Containing Character Added: {c}",
                    Mutator: Kind);
            }
        }
    }
    #endregion
}

/// <summary>Swaps similar-looking ASCII letters (e.g. m => n, r => n) using a built-in homoglyph table.</summary>
public sealed class AsciiHomoglyphMutator : IMutator
{
    #region Properties
    public MutatorType Kind => MutatorType.AsciiHomoglyph;
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string arg)
    {
        // Assumption is that the attacker is making just one change.
        for (int i = 0; i < arg.Length; i++)
        {
            if (homoglyphs.TryGetValue(arg[i], out string? swaps))
            {
                foreach (char c in swaps)
                {
                    yield return new Mutation(
                        Mutated: arg.ReplaceCharAtPosition(c, i),
                        Original: arg,
                        Reason: $"Ascii Homoglpyh: {arg[i]} => {c}",
                        Mutator: Kind);
                }
            }
        }
    }
    #endregion

    #region Fields
    private static readonly Dictionary<char, string> homoglyphs = new()
    {
        ['a'] = "eoq4",
        ['b'] = "dhp",
        ['c'] = "o",
        ['d'] = "bpq",
        ['e'] = "ao",
        ['f'] = "t",
        ['g'] = "pq",
        ['h'] = "b",
        ['i'] = "lj",
        ['j'] = "il",
        ['l'] = "ij1",
        ['m'] = "n",
        ['n'] = "rmu",
        ['o'] = "cea0",
        ['p'] = "bdqg",
        ['q'] = "adpg",
        ['r'] = "n",
        ['t'] = "f",
        ['u'] = "n",
        ['0'] = "o",
        ['1'] = "l",
        ['4'] = "a"
    };
    #endregion
}

/// <summary>Flips each bit of each byte and keeps results that remain well-formed relative URIs.</summary>
public sealed class BitFlipMutator : IMutator
{
    #region Properties
    public MutatorType Kind => MutatorType.BitFlip;
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string arg)
    {
        byte[] byteArray = Encoding.UTF8.GetBytes(arg);
        for (int i = 0; i < byteArray.Length; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                byte mask = (byte)(1 << j);
                byteArray[i] = (byte)(byteArray[i] ^ mask);
                string newString = Encoding.UTF8.GetString(byteArray);
                bool valid = true;

                for (int k = 0; k < newString.Length && valid; k++)
                {
                    if (!Uri.IsWellFormedUriString(newString, UriKind.Relative))
                    {
                        valid = false;
                    }
                }
                if (valid)
                {
                    yield return new Mutation(
                        Mutated: newString,
                        Original: arg,
                        Reason: $"Bit Flips: Byte {i}, Bit {j}",
                        Mutator: Kind);
                }
                // Restore the byte for the next bit.
                byteArray[i] = (byte)(byteArray[i] ^ mask);
            }
        }
    }
    #endregion
}

/// <summary>Replaces each character with a QWERTY-adjacent key (fat-finger), and appends one at the end.</summary>
public sealed class CloseLettersMutator : IMutator
{
    #region Constructors
    public CloseLettersMutator(char[]? additionalExcludedChars = null, char[]? overrideExcludedChars = null, char[]? skipExcludedChars = null)
    {
        if (overrideExcludedChars != null) excludedCharacters = overrideExcludedChars.ToList();
        if (additionalExcludedChars != null) excludedCharacters.AddRange(additionalExcludedChars);
        if (skipExcludedChars != null) excludedCharacters.RemoveAll(skipExcludedChars.Contains);
    }
    #endregion

    #region Properties
    public MutatorType Kind => MutatorType.CloseLetters;
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string arg)
    {
        for (int i = 0; i < arg.Length; i++)
        {
            foreach (char c in QwertyKeyboardHelper.GetNeighboringCharacters(arg[i]))
            {
                if (i == 0 && c == '/') continue;
                if (excludedCharacters.Contains(c)) continue;

                yield return new Mutation(
                    Mutated: arg.ReplaceCharAtPosition(c, i),
                    Original: arg,
                    Reason: $"Close Letters on QWERTY Keyboard: {arg[i]} => {c}",
                    Mutator: Kind);
            }
        }

        // Also try adding an additional neighbouring character to the end.
        foreach (char c in QwertyKeyboardHelper.GetNeighboringCharacters(arg.Last()))
        {
            if (excludedCharacters.Contains(c)) continue;

            yield return new Mutation(
                Mutated: string.Concat(arg, c),
                Original: arg,
                Reason: $"Close Letters on QWERTY Keyboard, added to end: {arg} => {c}",
                Mutator: Kind);
        }
    }
    #endregion

    #region Fields
    private readonly List<char> excludedCharacters = new() { ',', '[', ']', '=', ';', '\'' };
    #endregion
}

/// <summary>Inserts a QWERTY-adjacent character before each position (adjacent-key double press).</summary>
public sealed class DoubleHitMutator : IMutator
{
    #region Constructors
    public DoubleHitMutator(char[]? additionalExcludedChars = null, char[]? overrideExcludedChars = null, char[]? skipExcludedChars = null)
    {
        if (overrideExcludedChars != null) excludedCharacters = overrideExcludedChars.ToList();
        if (additionalExcludedChars != null) excludedCharacters.AddRange(additionalExcludedChars);
        if (skipExcludedChars != null) excludedCharacters.RemoveAll(skipExcludedChars.Contains);
    }
    #endregion

    #region Properties
    public MutatorType Kind => MutatorType.DoubleHit;
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string arg)
    {
        for (int i = 0; i < arg.Length; i++)
        {
            foreach (char c in QwertyKeyboardHelper.GetNeighboringCharacters(arg[i]))
            {
                if (i == 0 && c == '/') continue;
                if (excludedCharacters.Contains(c)) continue;

                yield return new Mutation(
                    Mutated: string.Concat(arg[..i], c, arg[i..]),
                    Original: arg,
                    Reason: $"Double hit character: {c}",
                    Mutator: Kind);
            }
        }
    }
    #endregion

    #region Fields
    private readonly List<char> excludedCharacters = new() { ',', '[', ']', '=', ';', '\'' };
    #endregion
}

/// <summary>Duplicates a character, or duplicates and replaces the next one.</summary>
public sealed class DuplicatorMutator : IMutator
{
    #region Properties
    public MutatorType Kind => MutatorType.Duplicator;
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string arg)
    {
        for (int i = 0; i < arg.Length; i++)
        {
            yield return new Mutation(
                Mutated: string.Concat(arg[..i], arg[i], arg[i..]),
                Original: arg,
                Reason: $"Letter Duplicated: {arg[i]}",
                Mutator: Kind);
        }

        for (int i = 0; i < arg.Length - 2; i++)
        {
            string mutated = string.Concat(arg[..(i + 1)], arg[i], arg[(i + 2)..]);
            if (!mutated.Equals(arg))
            {
                yield return new Mutation(
                    Mutated: mutated,
                    Original: arg,
                    Reason: $"Letter Duplicated and Replaced: {arg[i]}",
                    Mutator: Kind);
            }
        }

        string tail = string.Concat(arg[..arg.Length], arg[^1]);
        if (!tail.Equals(arg))
        {
            yield return new Mutation(
                Mutated: tail,
                Original: arg,
                Reason: "Letter Duplicated and Replaced",
                Mutator: Kind);
        }
    }
    #endregion
}

/// <summary>
/// Moves a purl namespace into the name. NuGet package ids carry no purl namespace, so this yields nothing
/// for a plain id (retained for parity with the OSSGadget mutator set).
/// </summary>
public sealed class NamespaceInNameMutator : IMutator
{
    #region Properties
    public MutatorType Kind => MutatorType.NamespaceInName;
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string arg) => Enumerable.Empty<Mutation>();
    #endregion
}

/// <summary>Adds or removes a leading prefix. Defaults: ".", "x", "-", "X", "_".</summary>
public sealed class PrefixMutator : IMutator
{
    #region Constructors
    public PrefixMutator(string[]? additionalPrefixes = null, string[]? overridePrefixes = null, string[]? skipPrefixes = null)
    {
        if (overridePrefixes != null) prefixes = overridePrefixes.ToList();
        if (additionalPrefixes != null) prefixes.AddRange(additionalPrefixes);
        if (skipPrefixes != null) prefixes.RemoveAll(skipPrefixes.Contains);
    }
    #endregion

    #region Properties
    public MutatorType Kind => MutatorType.Prefix;
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string arg)
    {
        // Can't add a character before an @ for a scoped package.
        if (arg.StartsWith('@'))
        {
            IEnumerable<Mutation> addedWithScope = prefixes.Select(s => new Mutation(
                Mutated: $"@{s}{arg[1..]}",
                Original: arg,
                Reason: $"Prefix Added: {s}",
                Mutator: Kind));

            IEnumerable<Mutation> removedWithScope = prefixes.Where(arg[1..].StartsWith).Select(s => new Mutation(
                Mutated: '@' + arg[1..].ReplaceAtStart(s, string.Empty),
                Original: arg,
                Reason: $"Prefix Removed: {s}",
                Mutator: Kind));

            return addedWithScope.Concat(removedWithScope);
        }

        IEnumerable<Mutation> added = prefixes.Select(s => new Mutation(
            Mutated: string.Concat(s, arg),
            Original: arg,
            Reason: $"Prefix Added: {s}",
            Mutator: Kind));

        IEnumerable<Mutation> removed = prefixes.Where(arg.StartsWith).Select(s => new Mutation(
            Mutated: arg.ReplaceAtStart(s, string.Empty),
            Original: arg,
            Reason: $"Prefix Removed: {s}",
            Mutator: Kind));

        return added.Concat(removed);
    }
    #endregion

    #region Fields
    private readonly List<string> prefixes = new() { ".", "x", "-", "X", "_" };
    #endregion
}

/// <summary>Removes each character in the string.</summary>
public sealed class RemovedCharacterMutator : IMutator
{
    #region Properties
    public MutatorType Kind => MutatorType.RemovedCharacter;
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string arg)
    {
        for (int i = 0; i < arg.Length; i++)
        {
            // Removing a leading @ for a scoped package is pointless.
            if (i == 0 && arg[i] == '@') continue;

            yield return new Mutation(
                Mutated: $"{arg[..i]}{arg[(i + 1)..]}",
                Original: arg,
                Reason: $"Character Removed: {i} ('{arg[i]}')",
                Mutator: Kind);
        }
    }
    #endregion
}

/// <summary>
/// Removes a purl namespace. NuGet package ids carry no purl namespace, so this yields nothing for a plain id
/// (retained for parity with the OSSGadget mutator set).
/// </summary>
public sealed class RemoveNamespaceMutator : IMutator
{
    #region Properties
    public MutatorType Kind => MutatorType.RemovedNamespace;
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string arg) => Enumerable.Empty<Mutation>();
    #endregion
}

/// <summary>Removes each separator-delimited section (e.g. foo-bar-js => bar-js, foo-js, foo-bar).</summary>
public sealed class RemoveSeparatedSectionMutator : IMutator
{
    #region Constructors
    public RemoveSeparatedSectionMutator(char[]? additionalSeparators = null, char[]? overrideSeparators = null, char[]? skipSeparators = null)
    {
        if (overrideSeparators != null) Separators = new HashSet<char>(overrideSeparators);
        if (additionalSeparators != null) Separators.UnionWith(additionalSeparators);
        if (skipSeparators != null) Separators.ExceptWith(skipSeparators);
    }
    #endregion

    #region Properties
    public MutatorType Kind => MutatorType.RemoveSeparatedSection;

    public HashSet<char> Separators { get; set; } = SeparatorRemovedMutator.DefaultSeparators.ToHashSet();
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string arg)
    {
        foreach (char separator in Separators)
        {
            string[] splits = arg.Split(separator, StringSplitOptions.RemoveEmptyEntries);

            if (splits.Length >= 2)
            {
                for (int i = 0; i < splits.Length; i++)
                {
                    yield return new Mutation(
                        Mutated: $"{string.Join(separator, splits[..i])}{string.Join(separator, splits[(i + 1)..])}",
                        Original: arg,
                        Reason: $"Separated Section Removed: {i} ('{arg[i]}')",
                        Mutator: Kind);
                }
            }
        }
    }
    #endregion
}

/// <summary>Replaces each character with a character from a default keyboard set.</summary>
public sealed class ReplaceCharacterMutator : IMutator
{
    #region Constructors
    public ReplaceCharacterMutator(char[]? additionalChars = null, char[]? overrideChars = null, char[]? skipChars = null)
    {
        if (overrideChars != null) characters = overrideChars.ToList();
        if (additionalChars != null) characters.AddRange(additionalChars);
        if (skipChars != null) characters.RemoveAll(skipChars.Contains);
    }
    #endregion

    #region Properties
    public MutatorType Kind => MutatorType.ReplaceCharacter;
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string arg)
    {
        for (int i = 0; i < arg.Length; i++)
        {
            // Don't replace a leading @ — that would break a scoped package.
            if (i == 0 && arg[i] == '@') continue;

            foreach (char c in characters)
            {
                // Skip replacing a character with itself.
                if (char.ToLower(arg[i]) == c) continue;

                yield return new Mutation(
                    Mutated: arg.ReplaceCharAtPosition(c, i),
                    Original: arg,
                    Reason: $"Character Replaced: {c}",
                    Mutator: Kind);
            }
        }
    }
    #endregion

    #region Fields
    private readonly List<char> characters = new()
    {
        '1','2','3','4','5','6','7','8','9','0','-','q','w','e','r','t','y','u','i','o','p','a','s','d','f','g','h','j','k','l','z','x','c','v','b','n','m','.',
    };
    #endregion
}

/// <summary>Swaps each separator for each other separator. Default separators: '.', '-', '_'.</summary>
public sealed class SeparatorChangedMutator : IMutator
{
    #region Constructors
    public SeparatorChangedMutator(char[]? additionalSeparators = null, char[]? overrideSeparators = null)
    {
        if (overrideSeparators != null) Separators = new HashSet<char>(overrideSeparators);
        if (additionalSeparators != null) Separators = new HashSet<char>(Separators.Concat(additionalSeparators));
    }
    #endregion

    #region Properties
    public MutatorType Kind => MutatorType.SeparatorChanged;

    public HashSet<char> Separators { get; set; } = SeparatorRemovedMutator.DefaultSeparators.ToHashSet();
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string target)
    {
        foreach (char separator in Separators)
        {
            if (target.Contains(separator))
            {
                foreach (char otherSeparator in Separators.Except(new[] { separator }))
                {
                    yield return new Mutation(
                        Mutated: target.Replace(separator, otherSeparator),
                        Original: target,
                        Reason: $"Separator Changed: {separator} => {otherSeparator}",
                        Mutator: Kind);
                }
            }
        }
    }
    #endregion
}

/// <summary>Removes each separator. Default separators: '.', '-', '_'.</summary>
public sealed class SeparatorRemovedMutator : IMutator
{
    #region Constructors
    public SeparatorRemovedMutator(char[]? additionalSeparators = null, char[]? overrideSeparators = null)
    {
        if (overrideSeparators != null) Separators = new HashSet<char>(overrideSeparators);
        if (additionalSeparators != null) Separators = new HashSet<char>(Separators.Concat(additionalSeparators));
    }
    #endregion

    #region Properties
    public MutatorType Kind => MutatorType.SeparatorRemoved;

    public HashSet<char> Separators { get; set; } = DefaultSeparators.ToHashSet();

    public static ImmutableHashSet<char> DefaultSeparators => ImmutableHashSet.Create('.', '-', '_');
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string target)
    {
        foreach (char separator in Separators)
        {
            if (target.Contains(separator))
            {
                yield return new Mutation(
                    Mutated: target.Replace(separator.ToString(), string.Empty),
                    Original: target,
                    Reason: $"Separator Removed {separator}",
                    Mutator: Kind);
            }
        }
    }
    #endregion
}

/// <summary>Applies known token substitutions in both directions (e.g. js &lt;=&gt; javascript).</summary>
public sealed class SubstitutionMutator : IMutator
{
    #region Constructors
    public SubstitutionMutator(IList<(string Original, string Substitution)>? substitutions = null)
    {
        this.substitutions = substitutions ?? new List<(string Original, string Substitution)>();
    }
    #endregion

    #region Properties
    public MutatorType Kind => MutatorType.Substitution;
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string arg)
    {
        foreach ((string original, string substitution) in substitutions)
        {
            if (arg.Contains(original))
            {
                yield return new Mutation(
                    Mutated: arg.Replace(original, substitution),
                    Original: arg,
                    Reason: $"String Substituted: {original} => {substitution}",
                    Mutator: Kind);
            }

            if (arg.Contains(substitution))
            {
                yield return new Mutation(
                    Mutated: arg.Replace(substitution, original),
                    Original: arg,
                    Reason: $"String Substituted: {substitution} => {original}",
                    Mutator: Kind);
            }
        }
    }
    #endregion

    #region Fields
    private readonly IList<(string Original, string Substitution)> substitutions;
    #endregion
}

/// <summary>Adds or removes a trailing suffix. Defaults include digits, "s", "ng", and separators.</summary>
public sealed class SuffixMutator : IMutator
{
    #region Constructors
    public SuffixMutator(string[]? additionalSuffixes = null, string[]? overrideSuffixes = null, string[]? skipSuffixes = null)
    {
        if (overrideSuffixes != null) suffixes = overrideSuffixes.ToList();
        if (additionalSuffixes != null) suffixes.AddRange(additionalSuffixes);
        if (skipSuffixes != null) suffixes.RemoveAll(skipSuffixes.Contains);
    }
    #endregion

    #region Properties
    public MutatorType Kind => MutatorType.Suffix;
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string arg)
    {
        IEnumerable<Mutation> added = suffixes.Select(s => new Mutation(
            Mutated: string.Concat(arg, s),
            Original: arg,
            Reason: $"Suffix Added: {s}",
            Mutator: Kind));

        IEnumerable<Mutation> removed = suffixes.Where(arg.EndsWith).Select(s => new Mutation(
            Mutated: arg.ReplaceAtEnd(s, string.Empty),
            Original: arg,
            Reason: $"Suffix Removed: {s}",
            Mutator: Kind));

        return added.Concat(removed);
    }
    #endregion

    #region Fields
    private readonly List<string> suffixes = new() { "s", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "ng", "-ng", ".", "x", "-", "_" };
    #endregion
}

/// <summary>Swaps each adjacent pair of letters (transposition).</summary>
public sealed class SwapOrderOfLettersMutator : IMutator
{
    #region Properties
    public MutatorType Kind => MutatorType.SwapOrderOfLetters;
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string arg)
    {
        for (int i = 0; i < arg.Length - 1; i++)
        {
            // Don't swap a character for the same character (foo -> foo).
            if (arg[i + 1] == arg[i]) continue;

            yield return new Mutation(
                Mutated: string.Concat(arg[..i], arg[i + 1], arg[i], arg.Substring(i + 2, arg.Length - (i + 2))),
                Original: arg,
                Reason: "Letters Swapped",
                Mutator: Kind);
        }
    }
    #endregion
}

/// <summary>Swaps similar-looking Unicode confusables for each character using a built-in table.</summary>
public sealed class UnicodeHomoglyphMutator : IMutator
{
    #region Properties
    public MutatorType Kind => MutatorType.UnicodeHomoglyph;
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string arg)
    {
        // Assumption is that the attacker is making just one change.
        for (int i = 0; i < arg.Length; i++)
        {
            if (homoglyphs.TryGetValue(arg[i], out string? swaps))
            {
                foreach (char c in swaps)
                {
                    yield return new Mutation(
                        Mutated: arg.ReplaceCharAtPosition(c, i),
                        Original: arg,
                        Reason: $"Unicode Homoglyph: {arg[i]} => {c}",
                        Mutator: Kind);
                }
            }
        }
    }
    #endregion

    #region Fields
    private static readonly Dictionary<char, string> homoglyphs = new()
    {
        ['a'] = "αа⍺ａ𝐚𝑎𝒂𝒶𝓪𝔞𝕒𝖆𝖺𝗮𝘢𝙖𝚊𝛂𝛼𝜶𝝰𝞪",
        ['b'] = "ƄЬᏏᖯｂ𝐛𝑏𝒃𝒷𝓫𝔟𝕓𝖇𝖻𝗯𝘣𝙗𝚋",
        ['c'] = "ϲсᴄⅽⲥꮯｃ𐐽𝐜𝑐𝒄𝒸𝓬𝔠𝕔𝖈𝖼𝗰𝘤𝙘𝚌",
        ['d'] = "ԁᏧᑯⅆⅾꓒｄ𝐝𝑑𝒅𝒹𝓭𝔡𝕕𝖉𝖽𝗱𝘥𝙙𝚍",
        ['e'] = "еҽ℮ℯⅇꬲｅ𝐞𝑒𝒆𝓮𝔢𝕖𝖊𝖾𝗲𝘦𝙚𝚎",
        ['f'] = "ſϝքẝꞙꬵｆ𝐟𝑓𝒇𝒻𝓯𝔣𝕗𝖋𝖿𝗳𝘧𝙛𝚏𝟋",
        ['g'] = "ƍɡցᶃℊｇ𝐠𝑔𝒈𝓰𝔤𝕘𝖌𝗀𝗴𝘨𝙜𝚐",
        ['h'] = "һհᏂℎｈ𝐡𝒉𝒽𝓱𝔥𝕙𝖍𝗁𝗵𝘩𝙝𝚑",
        ['i'] = "ıɩɪ˛ͺιіӏᎥιℹⅈⅰ⍳ꙇꭵｉ𑣃𝐢𝑖𝒊𝒾𝓲𝔦𝕚𝖎𝗂𝗶𝘪𝙞𝚒𝚤𝛊𝜄𝜾𝝸𝞲",
        ['j'] = "ϳјⅉｊ𝐣𝑗𝒋𝒿𝓳𝔧𝕛𝖏𝗃𝗷𝘫𝙟𝚓",
        ['k'] = "ｋ𝐤𝑘𝒌𝓀𝓴𝔨𝕜𝖐𝗄𝗸𝘬𝙠𝚔",
        ['m'] = "ｍ",
        ['n'] = "ոռｎ𝐧𝑛𝒏𝓃𝓷𝔫𝕟𝖓𝗇𝗻𝘯𝙣𝚗",
        ['p'] = "ρϱр⍴ⲣｐ𝐩𝑝𝒑𝓅𝓹𝔭𝕡𝖕𝗉𝗽𝘱𝙥𝚙𝛒𝛠𝜌𝜚𝝆𝝔𝞀𝞎𝞺𝟈",
        ['q'] = "ԛգզｑ𝐪𝑞𝒒𝓆𝓺𝔮𝕢𝖖𝗊𝗾𝘲𝙦𝚚",
        ['r'] = "гᴦⲅꭇꭈꮁｒ𝐫𝑟𝒓𝓇𝓻𝔯𝕣𝖗𝗋𝗿𝘳𝙧𝚛",
        ['s'] = "ƽѕꜱꮪｓ𐑈𑣁𝐬𝑠𝒔𝓈𝓼𝔰𝕤𝖘𝗌𝘀𝘴𝙨𝚜",
        ['t'] = "ｔ𝐭𝑡𝒕𝓉𝓽𝔱𝕥𝖙𝗍𝘁𝘵𝙩𝚝",
        ['u'] = "ʋυսᴜꞟꭎꭒｕ𐓶𑣘𝐮𝑢𝒖𝓊𝓾𝔲𝕦𝖚𝗎𝘂𝘶𝙪𝚞𝛖𝜐𝝊𝞄𝞾",
        ['v'] = "νѵטᴠⅴ∨⋁ꮩｖ𑜆𑣀𝐯𝑣𝒗𝓋𝓿𝔳𝕧𝖛𝗏𝘃𝘷𝙫𝚟𝛎𝜈𝝂𝝼𝞶",
        ['w'] = "ɯѡԝաᴡꮃｗ𑜊𑜎𑜏𝐰𝑤𝒘𝓌𝔀𝔴𝕨𝖜𝗐𝘄𝘸𝙬𝚠𝞪",
        ['x'] = "×хᕁᕽ᙮ⅹ⤫⤬⨯ｘ𝐱𝑥𝒙𝓍𝔁𝔵𝕩𝖝𝗑𝘅𝘹𝙭𝚡",
        ['y'] = "ɣʏγуүყᶌỿℽꭚｙ𑣜𝐲𝑦𝒚𝓎𝔂𝔶𝕪𝖞𝗒𝘆𝘺𝙮𝚢𝛄𝛾𝜸𝝲𝞬",
        ['z'] = "ᴢꮓｚ𑣄𝐳𝑧𝒛𝓏𝔃𝔷𝕫𝖟𝗓𝘇𝘻𝙯𝚣",
        ['~'] = "˜῀⁓∼",
        ['.'] = "ɑαа⍺ａ𝐚𝑎𝒂𝒶𝓪𝔞𝕒𝖆𝖺𝗮𝘢𝙖𝚊𝛂𝛼𝜶𝝰𝞪",
        ['_'] = "ߺ﹍﹎﹏＿",
        ['-'] = "ˉ‾▔﹉﹊﹋﹌￣",
    };
    #endregion
}

/// <summary>Swaps each vowel for each other vowel.</summary>
public sealed class VowelSwapMutator : IMutator
{
    #region Properties
    public MutatorType Kind => MutatorType.VowelSwap;
    #endregion

    #region Methods
    public IEnumerable<Mutation> Generate(string arg)
    {
        for (int i = 0; i < arg.Length; i++)
        {
            if (vowels.Contains(char.ToLower(arg[i])))
            {
                foreach (char vowel in vowels)
                {
                    if (vowel != char.ToLower(arg[i]))
                    {
                        yield return new Mutation(
                            Mutated: arg.ReplaceCharAtPosition(vowel, i),
                            Original: arg,
                            Reason: $"Swap Vowel: {arg[i]} => {vowel}",
                            Mutator: Kind);
                    }
                }
            }
        }
    }
    #endregion

    #region Fields
    private readonly HashSet<char> vowels = new() { 'a', 'e', 'i', 'o', 'u', 'y' };
    #endregion
}
