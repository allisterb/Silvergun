// Ported from OSSGadget (oss-find-squats-lib), (c) Microsoft Corporation, MIT License.
// Copy authorized 2026-07-16. Source: reference/projects/OSSGadget-main/src/oss-find-squats-lib/QwertyKeyboardHelper.cs
// The keyboard map and location tables are kept verbatim.
namespace Silvergun.PackageAnalysis.NuGet.Squats;

using System.Collections.Generic;

/// <summary>A helper for utilities related to the ANSI (USA) QWERTY keyboard.</summary>
public static class QwertyKeyboardHelper
{
    #region Methods
    /// <summary>Gets the neighboring characters on the keyboard for <paramref name="c"/>.</summary>
    public static IEnumerable<char> GetNeighboringCharacters(char c)
    {
        if (!locations.ContainsKey(c))
        {
            yield break;
        }

        int loc = locations[c];

        int yOrigin = loc / 100;
        int xOrigin = loc % 100;

        int[][] neighbors =
        {
            new[] { xOrigin - 1, yOrigin - 1 }, new[] { xOrigin, yOrigin - 1 }, new[] { xOrigin + 1, yOrigin - 1 },
            new[] { xOrigin - 1, yOrigin }, new[] { xOrigin + 1, yOrigin }, new[] { xOrigin - 1, yOrigin + 1 },
            new[] { xOrigin, yOrigin + 1 }, new[] { xOrigin + 1, yOrigin + 1 },
        };

        foreach (int[] n in neighbors)
        {
            int x = n[0];
            int y = n[1];

            // The neighboring position must be a valid location on the keyboard.
            if (x < 0 || y is < 0 or > 3)
            {
                continue;
            }

            string row = keymap[y];

            if (x >= row.Length)
            {
                continue;
            }

            yield return row[x];
        }
    }
    #endregion

    #region Fields
    /// <summary>The keymap of an ANSI QWERTY keyboard (USA style).</summary>
    private static readonly string[] keymap = { "1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./", };

    private static readonly Dictionary<char, int> locations = new()
    {
        ['1'] = 0,
        ['2'] = 1,
        ['3'] = 2,
        ['4'] = 3,
        ['5'] = 4,
        ['6'] = 5,
        ['7'] = 6,
        ['8'] = 7,
        ['9'] = 8,
        ['0'] = 9,
        ['-'] = 10,
        ['='] = 11,
        ['q'] = 100,
        ['w'] = 101,
        ['e'] = 102,
        ['r'] = 103,
        ['t'] = 104,
        ['y'] = 105,
        ['u'] = 106,
        ['i'] = 107,
        ['o'] = 108,
        ['p'] = 109,
        ['['] = 110,
        [']'] = 111,
        ['\\'] = 111,
        ['a'] = 200,
        ['s'] = 201,
        ['d'] = 202,
        ['f'] = 203,
        ['g'] = 204,
        ['h'] = 205,
        ['j'] = 206,
        ['k'] = 207,
        ['l'] = 208,
        [';'] = 209,
        ['\''] = 210,
        ['z'] = 300,
        ['x'] = 301,
        ['c'] = 302,
        ['v'] = 303,
        ['b'] = 304,
        ['n'] = 305,
        ['m'] = 306,
        [','] = 307,
        ['.'] = 308,
        ['/'] = 309,
    };
    #endregion
}
