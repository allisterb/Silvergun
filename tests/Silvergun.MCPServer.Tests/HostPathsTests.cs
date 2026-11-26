namespace Silvergun.MCPServer.Tests;

using System;
using System.IO;
using System.Text.Json.Nodes;

using Silvergun.MCPServer.Jobs;

/// <summary>D6.5's host-path reducer, in-process: every known prefix becomes its label, in both spellings, in every string leaf.</summary>
public sealed class HostPathsTests
{
    #region Methods
    [Fact]
    public void Reduce_ReplacesTheLongestKnownPrefixFirst_InBothSpellings()
    {
        var root = Path.Combine(Path.GetTempPath(), "sg-cache");
        var known = HostPaths.ForServer(root);
        var file = Path.Combine(root, "abc", "files", "lib", "x.dll");

        var reduced = HostPaths.Reduce($"could not open {file}; doubled {file.Replace(Backslash, Backslash + Backslash)}", known);

        Assert.DoesNotContain(root, reduced, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(root.Replace(Backslash, Backslash + Backslash), reduced, StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith("could not open <cache>", reduced);   // the cache root, not the shorter temp prefix
    }

    [WindowsOnlyFact]
    public void Reduce_OnWindows_IsCaseInsensitive()
    {
        var root = Path.Combine(Path.GetTempPath(), "sg-cache");

        Assert.Equal("<cache>" + Backslash + "x", HostPaths.Reduce(root.ToUpperInvariant() + Backslash + "x", HostPaths.ForServer(root)));
    }

    /// <summary>ReduceAll must walk nested objects and arrays: every real summary has both.</summary>
    [Fact]
    public void ReduceAll_OverNestedObjectsAndArrays_ReducesEveryStringLeaf()
    {
        var root = Path.Combine(Path.GetTempPath(), "sg-cache");
        var leak = Path.Combine(root, "abc", "x.dll");
        var node = new JsonObject
        {
            ["top"] = leak,
            ["nested"] = new JsonObject { ["reason"] = new JsonObject { ["untrusted"] = leak } },
            ["list"] = new JsonArray(leak, new JsonObject { ["path"] = leak }, 3, true),
        };

        var reduced = HostPaths.ReduceAll(node, HostPaths.ForServer(root))!;

        // Decoded leaves: the serialized form escapes '<' and '>', so it is checked only for what must be absent.
        var leaves = new[]
        {
            reduced["top"]!.GetValue<string>(),
            reduced["nested"]!["reason"]!["untrusted"]!.GetValue<string>(),
            reduced["list"]![0]!.GetValue<string>(),
            reduced["list"]![1]!["path"]!.GetValue<string>(),
        };
        Assert.All(leaves, leaf =>
        {
            Assert.StartsWith("<cache>", leaf);
            Assert.DoesNotContain("sg-cache", leaf);
        });
        Assert.Equal(3, reduced["list"]![2]!.GetValue<int>());
        Assert.True(reduced["list"]![3]!.GetValue<bool>());
        Assert.DoesNotContain("sg-cache", reduced.ToJsonString());
    }
    #endregion

    #region Fields
    private const string Backslash = @"\";
    #endregion
}
