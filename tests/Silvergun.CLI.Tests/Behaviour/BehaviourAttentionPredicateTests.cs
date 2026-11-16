namespace Silvergun.CLI.Tests.Behaviour;

using System.Text.Json.Nodes;

using Xunit;

/// <summary>
/// The observer's attention predicate on small hand-built scan-package JSON documents, no CLI run: one document per clause of
/// <c>PackageReportRenderer.Footer</c>'s predicate, and the negative cases (empty, a non-discriminating indicator alone).
/// </summary>
[Trait("Category", "Behaviour")]
public sealed class BehaviourAttentionPredicateTests
{
    #region Methods
    [Theory]
    [InlineData("""{"Assemblies":[{"Report":{"Findings":[{"Capability":"Network"}]}}]}""")]
    [InlineData("""{"Assemblies":[],"ScriptFindings":[{"RuleId":"SG0010"}]}""")]
    [InlineData("""{"Assemblies":[{"Obfuscation":{"Findings":[{"Kind":"EncodedExecutable"}]}}]}""")]
    [InlineData("""{"Assemblies":[],"YaraFindings":[{"RuleName":"r"}]}""")]
    [InlineData("""{"Assemblies":[],"Vulnerabilities":[{"Id":"v"}]}""")]
    [InlineData("""{"Assemblies":[{"Indicators":{"Findings":[{"Category":"ExfilSink"}]}}]}""")]
    [InlineData("""{"Assemblies":[{"Indicators":{"Findings":[{"Category":"GenericUrl"},{"Category":"CredentialPath"}]}}]}""")]
    public void HasAttention_OnEachFooterClause_IsTrue(string json) =>
        Assert.True(BehaviourObserver.HasAttention(JsonNode.Parse(json)!.AsObject()));

    [Theory]
    [InlineData("""{"Assemblies":[]}""")]
    [InlineData("""{"Assemblies":[{"Report":{"Findings":[]},"Indicators":{"Findings":[]},"Obfuscation":{"Findings":[]}}],"ScriptFindings":[],"YaraFindings":[],"Vulnerabilities":[]}""")]
    [InlineData("""{"Assemblies":[{"Indicators":{"Findings":[{"Category":"GenericUrl"}]}}]}""")]
    [InlineData("""{"Assemblies":[{"Indicators":{"Findings":[{"Category":"ReflectionTypeName"},{"Category":"PrivateIpLiteral"}]}}]}""")]
    public void HasAttention_WithNoFindingOrOnlyNonDiscriminatingIndicators_IsFalse(string json) =>
        Assert.False(BehaviourObserver.HasAttention(JsonNode.Parse(json)!.AsObject()));
    #endregion
}
