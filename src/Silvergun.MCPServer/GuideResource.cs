namespace Silvergun.MCPServer;

using System.ComponentModel;
using System.IO;

using ModelContextProtocol.Server;

/// <summary>The one MCP resource (task D11): the guide's text lives in <c>Resources/guide.md</c>; this only delivers it.</summary>
[McpServerResourceType]
public sealed class GuideResource
{
    #region Properties
    /// <summary>The guide's Markdown, read once from the embedded resource.</summary>
    public static string Text => text.Value;
    #endregion

    #region Methods
    [McpServerResource(Name = "guide", Title = "Silvergun guide", UriTemplate = Uri, MimeType = "text/markdown")]
    [Description("How to read Silvergun's results, follow a finding, and what Silvergun cannot see.")]
    public static string Guide() => Text;

    private static string Load()
    {
        using var stream = typeof(GuideResource).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException($"Embedded resource {ResourceName} is missing from the build.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
    #endregion

    #region Fields
    public const string Uri = "silvergun://guide";

    private const string ResourceName = "Silvergun.MCPServer.Resources.guide.md";

    private static readonly Lazy<string> text = new(Load);
    #endregion
}
