namespace Silvergun.MCPServer.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

/// <summary>
/// Task S0, driven through the SDK's own client: <see cref="McpClient"/> over <see cref="StdioClientTransport"/>, which
/// launches the real CLI apphost with <c>mcp ...</c> as a child. Each test gets its own child and its own temp root, cache
/// and log directories. Disposing the client closes the child's stdin and kills it after the transport's shutdown timeout,
/// so a hung server never outlives its test; every call also carries <see cref="McpCli.Timeout"/>.
/// </summary>
public sealed class McpClientTests
{
    #region Methods
    [Fact]
    public async Task ToolsList_ReturnsGetServerInfo_WithReadOnlyAnnotations()
    {
        using var dirs = new TestDirs();
        using var cts = new CancellationTokenSource(McpCli.Timeout);
        var stderr = new List<string>();
        await using var client = await ConnectAsync(McpCli.Args(dirs), dirs, stderr, cts.Token);

        var tools = await client.ListToolsAsync(cancellationToken: cts.Token);

        var tool = Assert.Single(tools, t => t.Name == ToolNames.GetServerInfo);
        var annotations = tool.ProtocolTool.Annotations;
        Assert.NotNull(annotations);
        Assert.True(annotations.ReadOnlyHint, "readOnlyHint");
        Assert.True(annotations.IdempotentHint, "idempotentHint");
        Assert.False(annotations.DestructiveHint, "destructiveHint");
        Assert.False(annotations.OpenWorldHint, "openWorldHint");
    }

    /// <summary>D7: every tool is read-only toward the user's machine and closed-world (S5's tools are the only open-world ones).</summary>
    [Fact]
    public async Task ToolsList_JobTools_AreReadOnly_Idempotent_AndClosedWorld()
    {
        using var dirs = new TestDirs();
        using var cts = new CancellationTokenSource(McpCli.Timeout);
        var stderr = new List<string>();
        await using var client = await ConnectAsync(McpCli.Args(dirs), dirs, stderr, cts.Token);

        var tools = await client.ListToolsAsync(cancellationToken: cts.Token);

        foreach (var name in new[] { ToolNames.AnalyzePackage, ToolNames.WaitForJob, ToolNames.CancelJob, ToolNames.GetSummary })
        {
            var annotations = Assert.Single(tools, t => t.Name == name).ProtocolTool.Annotations;
            Assert.NotNull(annotations);
            Assert.True(annotations.ReadOnlyHint, $"{name}: readOnlyHint");
            Assert.True(annotations.IdempotentHint, $"{name}: idempotentHint");
            Assert.False(annotations.DestructiveHint, $"{name}: destructiveHint");
            Assert.False(annotations.OpenWorldHint, $"{name}: openWorldHint");
        }
    }

    [Fact]
    public async Task Guide_IsReadableAsMarkdown()
    {
        using var dirs = new TestDirs();
        using var cts = new CancellationTokenSource(McpCli.Timeout);
        var stderr = new List<string>();
        await using var client = await ConnectAsync(McpCli.Args(dirs), dirs, stderr, cts.Token);

        var result = await client.ReadResourceAsync(GuideResource.Uri, cancellationToken: cts.Token);

        var contents = Assert.IsType<TextResourceContents>(Assert.Single(result.Contents));
        Assert.Equal("text/markdown", contents.MimeType);
        Assert.Equal(GuideResource.Uri, contents.Uri);
        Assert.Matches(new Regex(@"^#+ What Silvergun does not see\s*$", RegexOptions.Multiline), contents.Text);
        Assert.Equal(GuideResource.Text, contents.Text);   // the resource only delivers the one text (D11)
    }

    [Fact]
    public async Task GetServerInfo_ReturnsEnvelopeAndSettings()
    {
        using var dirs = new TestDirs();
        var secondRoot = dirs.NewDir("sg-second-root");
        using var cts = new CancellationTokenSource(McpCli.Timeout);
        var stderr = new List<string>();
        await using var client = await ConnectAsync(
            McpCli.Args(dirs, "--root", secondRoot, "--max-jobs", "2", "--cache-max-gb", "3"), dirs, stderr, cts.Token);

        var result = await client.CallToolAsync(ToolNames.GetServerInfo, new Dictionary<string, object?>(), cancellationToken: cts.Token);

        Assert.False(result.IsError ?? false, $"isError: {Describe(result)}");
        Assert.True(result.StructuredContent.HasValue, "no structuredContent");
        var s = result.StructuredContent.Value;

        Assert.True(s.GetProperty("ok").GetBoolean());
        Assert.Equal("Succeeded", s.GetProperty("status").GetString());
        Assert.False(s.GetProperty("retry").GetBoolean());
        Assert.Matches("^[0-9a-f]{16}$", s.GetProperty("instanceId").GetString());
        var startedAt = s.GetProperty("startedAt").GetString()!;
        Assert.True(DateTimeOffset.TryParse(startedAt, out var started), $"startedAt '{startedAt}' is not a timestamp");
        Assert.EndsWith("Z", startedAt);   // UTC, round-trip form
        Assert.Equal(TimeSpan.Zero, started.Offset);
        Assert.True(s.GetProperty("uptimeMs").GetInt64() >= 0);

        var versions = s.GetProperty("versions");
        Assert.Equal(ServerState.SilvergunVersion, versions.GetProperty("silvergun").GetString());
        Assert.Equal(ServerState.SdkVersion, versions.GetProperty("mcpSdk").GetString());
        Assert.False(string.IsNullOrWhiteSpace(ServerState.SdkVersion));
        Assert.Equal(client.NegotiatedProtocolVersion, versions.GetProperty("protocol").GetString());
        Assert.False(string.IsNullOrWhiteSpace(client.NegotiatedProtocolVersion));
        Assert.Matches("^[0-9a-f]{64}$", versions.GetProperty("rulesHash").GetString());
        Assert.Equal(Silvergun.MCPServer.Jobs.BuildIdentity.RulesHash, versions.GetProperty("rulesHash").GetString());
        Assert.Equal(Silvergun.MCPServer.Jobs.BuildIdentity.BuildKey, versions.GetProperty("cacheBuildKey").GetString());

        var settings = s.GetProperty("settings");
        var roots = settings.GetProperty("roots").EnumerateArray().Select(r => r.GetString()!).ToArray();
        Assert.Equal([Path.GetFileName(dirs.Root), Path.GetFileName(secondRoot)], roots);
        Assert.All(roots, r =>
        {
            Assert.DoesNotContain(Path.DirectorySeparatorChar, r);
            Assert.DoesNotContain(Path.AltDirectorySeparatorChar, r);
            Assert.DoesNotContain(':', r);
            Assert.DoesNotContain(dirs.Base, r, StringComparison.OrdinalIgnoreCase);
        });
        Assert.False(settings.GetProperty("network").GetBoolean());
        Assert.Equal(2, settings.GetProperty("maxJobs").GetInt32());
        Assert.Equal(3, settings.GetProperty("cacheMaxGb").GetInt32());

        var limits = s.GetProperty("limits");
        Assert.Equal(McpLimits.ResponseBudgetChars, limits.GetProperty("responseBudgetChars").GetInt32());
        Assert.Equal(McpLimits.MaxQueuedJobs, limits.GetProperty("maxQueuedJobs").GetInt32());
        Assert.Equal(McpLimits.DefaultWaitSeconds, limits.GetProperty("defaultWaitSeconds").GetInt32());
        Assert.Equal(McpLimits.MaxWaitSeconds, limits.GetProperty("maxWaitSeconds").GetInt32());
        Assert.Equal(McpLimits.StandardJobBudgetSeconds, limits.GetProperty("standardJobBudgetSeconds").GetInt32());
        Assert.Equal(McpLimits.DeepJobBudgetSeconds, limits.GetProperty("deepJobBudgetSeconds").GetInt32());
        Assert.Equal(McpLimits.JobMemoryBytes, limits.GetProperty("jobMemoryBytes").GetInt64());
        Assert.Equal(McpLimits.DeepJobMemoryBytes, limits.GetProperty("deepJobMemoryBytes").GetInt64());

        // No host path anywhere in the result (D6.5): not the roots, not the cache, not the log directory.
        var whole = s.GetRawText();
        foreach (var hostPath in new[] { dirs.Base, dirs.Root, secondRoot, dirs.Cache, dirs.Logs })
            Assert.DoesNotContain(JsonEncodedText.Encode(hostPath).ToString(), whole, StringComparison.OrdinalIgnoreCase);

        // The same JSON, serialized in one text block.
        var text = Assert.IsType<TextContentBlock>(Assert.Single(result.Content));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(text.Text), JsonNode.Parse(whole)), $"text block differs from structuredContent:\n{text.Text}\n{whole}");
    }

    [Fact]
    public async Task Instructions_AreUnder4000Chars_AndPointToGuide()
    {
        using var dirs = new TestDirs();
        using var cts = new CancellationTokenSource(McpCli.Timeout);
        var stderr = new List<string>();
        await using var client = await ConnectAsync(McpCli.Args(dirs), dirs, stderr, cts.Token);

        var instructions = client.ServerInstructions;

        Assert.False(string.IsNullOrWhiteSpace(instructions));
        Assert.True(instructions.Length <= 4_000, $"instructions are {instructions.Length} chars");
        Assert.Contains(GuideResource.Uri, instructions);
        Assert.Equal(SilvergunMcpServer.Instructions, instructions);
    }
    #endregion

    #region Methods: helpers
    private static async Task<McpClient> ConnectAsync(string[] args, TestDirs dirs, List<string> stderr, CancellationToken ct)
    {
        var transport = new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "silvergun-mcp-tests",
            Command = McpCli.Exe,
            Arguments = [.. args],
            WorkingDirectory = dirs.Root,
            StandardErrorLines = line => { lock (stderr) stderr.Add(line); },
            EnvironmentVariables = new Dictionary<string, string?> { ["NO_COLOR"] = "1", ["DOTNET_STARTUP_HOOKS"] = null },
        });
        try
        {
            return await McpClient.CreateAsync(transport, cancellationToken: ct);
        }
        catch (Exception ex)
        {
            string text;
            lock (stderr) text = string.Join('\n', stderr);
            throw new InvalidOperationException($"could not connect to `{string.Join(' ', args)}`: {ex.Message}\nstderr:\n{text}", ex);
        }
    }

    private static string Describe(CallToolResult result) =>
        string.Join('\n', result.Content.OfType<TextContentBlock>().Select(t => t.Text));
    #endregion
}
