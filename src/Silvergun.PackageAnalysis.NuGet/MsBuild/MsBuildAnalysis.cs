namespace Silvergun.PackageAnalysis.NuGet.MsBuild;

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

/// <summary>
/// A package's MSBuild integration facts (MCP task S4): every <c>.targets</c> and <c>.props</c> file parsed with a safe
/// <see cref="XmlReader"/> (no DTD, no resolver, size- and depth-capped), its targets, <c>Exec</c> tasks, file-writing tasks,
/// <c>UsingTask</c>s, imports and notable properties, with values expanded across the package's own files
/// (<see cref="MsBuildExpander"/>). These are facts about text, never a record of what MSBuild would do. Never throws for
/// package content.
/// </summary>
public static class MsBuildAnalysis
{
    #region Methods
    /// <summary>
    /// The facts of <paramref name="scripts"/>' MSBuild files. <paramref name="packageFiles"/> are the full paths of every
    /// extracted file under <paramref name="contentRoot"/>, which references to the package's own files resolve against.
    /// </summary>
    public static MsBuildIntegration Analyze(string packageId, string contentRoot, IReadOnlyList<PackageScript> scripts, IEnumerable<string> packageFiles,
        long budgetChars = MsBuildExpander.DefaultBudgetChars)
    {
        var files = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var full in packageFiles.Where(f => f.StartsWith(contentRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal)))
        {
            var name = NuGetPackage.NuGetName(NuGetPackage.RelativeUnderRoot(contentRoot, full));
            if (!files.TryGetValue(name, out var list))
                files[name] = list = [];
            list.Add(full);
        }

        // Read every MSBuild file, within the package's caps; the element cap is the package's, not each file's (S4 review W7).
        var context = new Context(files);
        var read = new List<(PackageScript Script, string Name, Raw? Raw, MsBuildFileStatus Status, string? Reason)>();
        long total = 0;
        foreach (var s in scripts.Where(s => s.FullPath.StartsWith(contentRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal)))
        {
            var name = NuGetPackage.NuGetName(NuGetPackage.RelativeUnderRoot(contentRoot, s.FullPath));
            var kind = name.TrimEnd(' ', '.');
            if (!kind.EndsWith(".targets", StringComparison.OrdinalIgnoreCase) && !kind.EndsWith(".props", StringComparison.OrdinalIgnoreCase))
                continue;
            if (read.Count >= MaxFiles)
            {
                read.Add((s, name, null, MsBuildFileStatus.NotParsed, $"past the package's cap of {MaxFiles} MSBuild files"));
                continue;
            }
            var (raw, status, reason, bytes) = Read(s.FullPath, MaxPackageBytes - total, context);
            total += bytes;
            read.Add((s, name, raw, status, reason));
        }

        // Every definition in the package, for expansion: the latest kept, as MSBuild keeps the last (S4 review C6).
        var properties = new Dictionary<string, List<(string, string)>>(StringComparer.OrdinalIgnoreCase);
        var items = new Dictionary<string, List<(string, string)>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (_, name, raw, _, _) in read.Where(r => r.Raw is not null))
        {
            foreach (var p in raw!.Properties)
                Add(properties, p.Name, (p.Value, name), context);
            foreach (var i in raw.Items)
                Add(items, i.Type, (i.Include, name), context);
        }
        var expander = new MsBuildExpander(packageId, properties, items, budgetChars, context.Dropped, context.AnyProperty);
        var invoked = read.Where(r => r.Raw is not null).SelectMany(r => r.Raw!.Tasks).GroupBy(t => t.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

        var facts = read.Select(r => r.Raw is null
                ? Empty(r.Script.FullPath, r.Name, r.Status, r.Reason)
                : Facts(r.Script.FullPath, r.Name, r.Raw, expander, context, invoked))
            .ToList();
        // Loaded files first, so a row cap never hides what a build runs behind what it does not (S4 review W2).
        facts = [.. Loads(facts, packageId).OrderBy(f => f.Load)];
        return new(facts, new MsBuildPass(facts.Count, facts.Count(f => f.Status == MsBuildFileStatus.Parsed), facts.Count(f => f.Status == MsBuildFileStatus.NotParsed),
            facts.Count(f => f.Status == MsBuildFileStatus.NotProject), expander.BudgetSpent)
        {
            FactsCut = facts.Sum(f => f.FactsCut),
            ValuesCut = expander.Cuts + context.ValuesCut,
            AnyPropertySet = context.AnyProperty,
        }, Totals(facts));
    }

    /// <summary>
    /// The NuGet folder that imports <paramref name="name"/> (package-relative, as NuGet installs it) for package
    /// <paramref name="packageId"/>, or null: <c>build/[tfm/]id.{props,targets}</c>, the same under <c>buildTransitive/</c>,
    /// and <c>buildMultiTargeting/id.…</c> (or the legacy <c>buildCrossTargeting/</c>), case-insensitively.
    /// </summary>
    public static MsBuildAutoImport? AutoImportOf(string name, string packageId)
    {
        var segments = name.Split('/');
        var file = segments[^1].TrimEnd(' ', '.');
        if (!file.Equals(packageId + ".props", StringComparison.OrdinalIgnoreCase) && !file.Equals(packageId + ".targets", StringComparison.OrdinalIgnoreCase))
            return null;
        var folder = segments[0].ToLowerInvariant() switch
        {
            "build" => "build",
            "buildtransitive" => "buildTransitive",
            "buildmultitargeting" => "buildMultiTargeting",
            "buildcrosstargeting" => "buildCrossTargeting",
            _ => null,
        };
        return folder is null ? null
            : segments.Length == 2 ? new(folder, null)
            : segments.Length == 3 && folder is "build" or "buildTransitive" ? new(folder, segments[1])
            : null;
    }

    // The file's elements, or why it was not read.
    private static (Raw? Raw, MsBuildFileStatus Status, string? Reason, long Bytes) Read(string path, long allowance, Context context)
    {
        byte[] bytes;
        try
        {
            var info = new FileInfo(path);
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
                return (null, MsBuildFileStatus.NotParsed, "a link; not followed", 0);
            if (info.Length > MaxFileBytes)
                return (null, MsBuildFileStatus.NotParsed, $"over {MaxFileBytes} bytes", 0);
            if (info.Length > allowance)
                return (null, MsBuildFileStatus.NotParsed, $"past the package's cap of {MaxPackageBytes} bytes of MSBuild files", 0);
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            bytes = new byte[Math.Min(stream.Length, MaxFileBytes + 1)];
            stream.ReadExactly(bytes);
            if (stream.ReadByte() >= 0)
                return (null, MsBuildFileStatus.NotParsed, "grew while it was read", bytes.Length);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return (null, MsBuildFileStatus.NotParsed, $"could not be read ({ex.GetType().Name})", 0);
        }

        XDocument document;
        try
        {
            // A streaming pass first: a deep tree is refused before a document is built for it (S4 review C3).
            using (var scan = XmlReader.Create(new MemoryStream(bytes), xmlSettings))
                while (scan.Read())
                    if (scan.Depth > MaxXmlDepth)
                        return (null, MsBuildFileStatus.NotParsed, $"nested deeper than {MaxXmlDepth} elements", bytes.Length);
            using var reader = XmlReader.Create(new MemoryStream(bytes), xmlSettings);
            document = XDocument.Load(reader, LoadOptions.SetLineInfo);
        }
        catch (XmlException ex)
        {
            // Told by the bytes, not the exception's (localised) message.
            return (null, MsBuildFileStatus.NotParsed,
                Encoding.UTF8.GetString(bytes).Contains("<!DOCTYPE", StringComparison.OrdinalIgnoreCase) ? "has a DTD, which Silvergun does not process"
                    : $"not well-formed XML (line {ex.LineNumber})", bytes.Length);
        }
        if (document.Root is not { } root || !Is(root, "Project"))
            return (null, MsBuildFileStatus.NotProject, "its root element is not Project", bytes.Length);

        var raw = new Raw(context);
        Walk(root, raw, null, [], 0);
        return (raw, MsBuildFileStatus.Parsed, null, bytes.Length);
    }

    // The project-level elements under `container` (Project, When, Otherwise), and their own children.
    private static void Walk(XElement container, Raw raw, string? target, IReadOnlyList<string> conditions, int depth)
    {
        foreach (var e in container.Elements().Where(Msbuild))
        {
            if (!raw.Room())
                return;
            var conds = With(conditions, Attr(e, "Condition"), raw);
            switch (e.Name.LocalName.ToLowerInvariant())
            {
                case "propertygroup" or "itemgroup":
                    Group(e, raw, target, conds);
                    break;
                case "itemdefinitiongroup":
                    // Default metadata: one that carries properties for an MSBuild call could set any (S4 review round 5, C3).
                    if (e.Elements().Where(Msbuild).Any(HasPropertiesMetadata))
                        raw.AnyPropertySet();
                    break;
                case "target" when target is null:
                    var name = Attr(e, "Name") ?? "";
                    raw.Targets.Add(new(Line(e), name, Attr(e, "BeforeTargets"), Attr(e, "AfterTargets"), Attr(e, "DependsOnTargets"), conds, Attr(e, "Inputs"), Attr(e, "Outputs")));
                    foreach (var child in e.Elements().Where(Msbuild))
                    {
                        if (!raw.Room())
                            return;
                        var lower = child.Name.LocalName.ToLowerInvariant();
                        if (lower is "propertygroup" or "itemgroup")
                            Group(child, raw, name, With(conds, Attr(child, "Condition"), raw));
                        else if (lower != "onerror")
                        {
                            var attributes = child.Attributes().Where(a => a.Name.NamespaceName.Length == 0).GroupBy(a => a.Name.LocalName, StringComparer.OrdinalIgnoreCase)
                                .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.OrdinalIgnoreCase);
                            var taskConds = With(conds, Attr(child, "Condition"), raw);
                            // MSBuild runs <Microsoft.Build.Tasks.MakeDir> as MakeDir: tasks are matched by their last name (S4 review round 5, C2).
                            var taskName = child.Name.LocalName[(child.Name.LocalName.LastIndexOf('.') + 1)..];
                            raw.Tasks.Add(new(Line(child), name, taskName, attributes, taskConds));
                            Outputs(child, taskName, attributes, raw, name, taskConds);
                        }
                    }
                    break;
                case "usingtask":
                    var task = e.Elements().Where(Msbuild).FirstOrDefault(c => Is(c, "Task"));
                    var code = task?.Elements().Where(Msbuild).FirstOrDefault(c => Is(c, "Code"));
                    var (body, bodyChars) = code is null ? (null, 0) : Text(code, MaxBodyReadChars);
                    // A body past what is read is not searched whole: the file says so (S4 review round 2, W2).
                    if (bodyChars > MaxBodyReadChars)
                        raw.Cut++;
                    raw.UsingTasks.Add(new(Line(e), Attr(e, "TaskName") ?? "", Attr(e, "AssemblyFile"), Attr(e, "AssemblyName"), Attr(e, "TaskFactory"), conds,
                        task is not null, code is null ? null : Attr(code, "Type"), code is null ? null : Attr(code, "Language"), code is null ? null : Attr(code, "Source"),
                        body, bodyChars));
                    break;
                case "import":
                    raw.Imports.Add(new(Line(e), Attr(e, "Project") ?? "", Attr(e, "Sdk"), conds));
                    break;
                case "importgroup":
                    foreach (var i in e.Elements().Where(c => Msbuild(c) && Is(c, "Import")))
                        if (raw.Room())
                            raw.Imports.Add(new(Line(i), Attr(i, "Project") ?? "", Attr(i, "Sdk"), With(conds, Attr(i, "Condition"), raw)));
                    break;
                case "choose" when depth < MaxChooseDepth:
                    foreach (var branch in e.Elements().Where(c => Msbuild(c) && (Is(c, "When") || Is(c, "Otherwise"))))
                        Walk(branch, raw, target, With(conds, Attr(branch, "Condition"), raw), depth + 1);
                    break;
                case "choose":
                    raw.Cut++;
                    break;
            }
        }
    }

    // Properties and items a task sets (S4 review round 3, C1): CreateProperty's Value is a definition; any other task's
    // <Output PropertyName/ItemName> sets a value Silvergun cannot see, so the name is marked as one whose value may be
    // anything; an MSBuild task's Properties="A=B;…" are definitions. A key MSBuild expands or unescapes is read as it
    // would read it, or, when it holds a reference, as one that could be anything (S4 review round 6).
    private static void Outputs(XElement task, string taskName, Dictionary<string, string> attributes, Raw raw, string target, IReadOnlyList<string> conditions)
    {
        bool Named(string n) => taskName.Equals(n, StringComparison.OrdinalIgnoreCase);
        // CreateItem's metadata can carry properties for a later MSBuild call (S4 review round 5, C3).
        if (Named("CreateItem") && attributes.GetValueOrDefault("AdditionalMetadata") is { } metadata
            // MSBuild splits on raw ';', decodes each entry, then splits at '=': an escaped '=' is a separator (round 7, measured).
            && (HasReference(metadata) || metadata.Split(';').Any(m => MsBuildExpander.Unescape(m).Split('=')[0].Trim() is var key
                && (key.Equals("Properties", StringComparison.OrdinalIgnoreCase) || key.Equals("AdditionalProperties", StringComparison.OrdinalIgnoreCase)))))
            raw.AnyPropertySet();
        foreach (var output in task.Elements().Where(c => Msbuild(c) && Is(c, "Output")))
        {
            if (Attr(output, "PropertyName") is { Length: > 0 } property)
            {
                // MSBuild expands the name: one Silvergun cannot read could be any property (S4 review round 4, C1).
                if (!IsName(property))
                    raw.AnyPropertySet();
                else if (Named("CreateProperty") && string.Equals(Attr(output, "TaskParameter"), "Value", StringComparison.OrdinalIgnoreCase)
                    && attributes.GetValueOrDefault("Value") is { } value && raw.Room())
                    raw.Properties.Add(new(Line(output), target, property, Bound(value), conditions));
                else
                    raw.Unseen.Add(property);
            }
            if (Attr(output, "ItemName") is { Length: > 0 } item)
            {
                if (!IsName(item))
                    raw.AnyPropertySet();
                raw.Unseen.Add(item);
            }
        }
        // MSBuild's Properties="A=B;…" are definitions; a reference there, or projects from an item (whose metadata can carry
        // properties), could set any property. CallTarget has no Properties parameter (MSB4064, measured).
        if (Named("MSBuild"))
        {
            if (attributes.GetValueOrDefault("Projects") is { } projects && projects.Contains("@(", StringComparison.Ordinal))
                raw.AnyPropertySet();
            if (attributes.GetValueOrDefault("Properties") is { } assignments)
            {
                if (HasReference(assignments))
                    raw.AnyPropertySet();
                // The definition an entry with no separator continues: MSBuild appends it, with its ';', to the previous
                // value, so "Sub=x/;../y/" sets Sub to "x/;../y/" (S4 review round 9, measured).
                // The continued value is built once, within the cap: appending to a string per entry copied it whole each
                // time (S4 review round 10: 180 s and 1 TB allocated for one 4 MB file).
                int? last = null;
                StringBuilder? continued = null;
                void Close()
                {
                    if (last is { } i && continued is not null)
                        raw.Properties[i] = raw.Properties[i] with { Value = continued.ToString() };
                    (last, continued) = (null, null);
                }
                // MSBuild drops empty entries before it reads them.
                foreach (var assignment in assignments.Split(';').Where(a => a.Trim().Length > 0))
                {
                    // MSBuild splits on raw ';', decodes the entry, then splits at its first '=': Out%44ir is OutDir and
                    // OutDir%3Dx sets OutDir (both measured). The separator is the first raw '=' or "%3D" (one decoding
                    // pass); the name is decoded, the value stays raw, so an escaped %24(X) is never expanded (round 8).
                    if (Separator(assignment) is not ({ } at, var width))
                    {
                        if (last is { } i)
                        {
                            continued ??= new StringBuilder(raw.Properties[i].Value);
                            var room = MsBuildExpander.MaxValueChars + 1 - continued.Length;
                            if (room > 0)
                                continued.Append((";" + assignment).AsSpan(0, Math.Min(room, assignment.Length + 1)));
                        }
                        continue;
                    }
                    Close();
                    if (at == 0)
                        continue;
                    var property = MsBuildExpander.Unescape(assignment[..at]).Trim();
                    var value = assignment[(at + width)..];
                    if (!IsName(property))
                        raw.AnyPropertySet();
                    else if (raw.Room())
                    {
                        raw.Properties.Add(new(Line(task), target, property, Bound(value), conditions));
                        last = raw.Properties.Count - 1;
                    }
                }
                Close();
            }
        }
    }

    // An item (or item definition) with Properties or AdditionalProperties metadata, as an attribute or a child element.
    private static bool HasPropertiesMetadata(XElement e) =>
        Attr(e, "Properties") is not null || Attr(e, "AdditionalProperties") is not null
        || e.Elements().Any(m => Msbuild(m) && (Is(m, "Properties") || Is(m, "AdditionalProperties")));

    // Where an MSBuild property assignment's name ends: the first raw '=' or escaped "%3D", and its width; null when none.
    private static (int? At, int Width) Separator(string assignment)
    {
        for (var i = 0; i < assignment.Length; i++)
        {
            if (assignment[i] == '=')
                return (i, 1);
            if (assignment[i] == '%' && i + 2 < assignment.Length && assignment[i + 1] == '3' && assignment[i + 2] is 'D' or 'd')
                return (i, 3);
        }
        return (null, 0);
    }

    private static bool HasReference(string text) =>
        text.Contains("$(", StringComparison.Ordinal) || text.Contains("@(", StringComparison.Ordinal) || text.Contains("%(", StringComparison.Ordinal);

    private static bool IsName(string name) => name.Trim().All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-') && name.Trim().Length > 0;

    // A task-set value, bounded as a PropertyGroup's is (S4 review round 4, C2).
    private static string Bound(string value) => value.Length > MsBuildExpander.MaxValueChars + 1 ? value[..(MsBuildExpander.MaxValueChars + 1)] : value;

    // A PropertyGroup's properties or an ItemGroup's items.
    private static void Group(XElement group, Raw raw, string? target, IReadOnlyList<string> conditions)
    {
        var properties = Is(group, "PropertyGroup");
        foreach (var e in group.Elements().Where(Msbuild))
        {
            if (!raw.Room())
                return;
            if (properties)
                raw.Properties.Add(new(Line(e), target, e.Name.LocalName, Text(e, MsBuildExpander.MaxValueChars + 1).Text, With(conditions, Attr(e, "Condition"), raw)));
            else
            {
                // Item metadata that sets properties for an MSBuild call could set any property (S4 review round 4, C1).
                if (HasPropertiesMetadata(e))
                    raw.AnyPropertySet();
                if (Attr(e, "Include") is { } include)
                    raw.Items.Add(new(e.Name.LocalName, include));
            }
        }
    }

    private static MsBuildFileFacts Facts(string fullPath, string name, Raw raw, MsBuildExpander expander, Context context, Dictionary<string, int> invoked)
    {
        var dir = name.Contains('/') ? name[..name.LastIndexOf('/')] : "";
        IReadOnlyList<(string Text, bool Unresolved)> Candidates(string value) => expander.Expand(value, name);
        // Every path of a value, to the cap; `relative` resolves a relative path against this file's own directory (S4 review C7).
        (List<MsBuildPath> Paths, bool Cut) PathsOf(string value, bool relative = false)
        {
            // An unresolved candidate that yields no path is a path Silvergun cannot see, never none (S4 review round 5, C1).
            var all = Candidates(value).SelectMany(c => MsBuildExpander.Paths(c.Text, c.Unresolved, relative ? dir : null) is { Count: 0 } && c.Unresolved
                    ? [new MsBuildPath(MsBuildAnchor.Unknown, "", 0, true)]
                    : MsBuildExpander.Paths(c.Text, c.Unresolved, relative ? dir : null))
                .Distinct().Take(MaxDestinations + 1).ToList();
            if (all.Count <= MaxDestinations)
                return (all, false);
            context.ValuesCut++;
            return (all[..MaxDestinations], true);
        }
        IReadOnlyList<string> PackageFilesOf(IEnumerable<MsBuildPath> paths) => [.. paths.SelectMany(context.Lookup).Distinct().Take(MaxPackageFiles)];

        var execs = raw.Tasks.Where(t => t.Name.Equals("Exec", StringComparison.OrdinalIgnoreCase)).Select(t =>
        {
            var command = t.Attributes.GetValueOrDefault("Command") ?? "";
            var expanded = Candidates(command);
            return new MsBuildExecFact(t.Line, t.Target, command, t.Attributes.GetValueOrDefault("ContinueOnError"), t.Attributes.GetValueOrDefault("IgnoreExitCode"),
                t.Attributes.GetValueOrDefault("IgnoreStandardErrorWarningFormat"), t.Attributes.GetValueOrDefault("WorkingDirectory"), t.Conditions,
                expanded.Count > 0 ? MsBuildExpander.Program(expanded[0].Text) : null,
                PackageFilesOf(expanded.SelectMany(c => MsBuildExpander.AnchoredPaths(c.Text, c.Unresolved))),
                // The raw text too: a literal token is never lost to an expansion cap (S4 review round 2, C3).
                [.. expanded.Select(c => c.Text).Append(command).SelectMany(text => AgentConfigPaths.Mentioned(MsBuildExpander.Display(text))).Distinct(StringComparer.Ordinal)],
                expanded.Any(c => c.Unresolved));
        }).ToList();

        var writes = new List<MsBuildWriteFact>();
        foreach (var t in raw.Tasks)
        {
            if (!writers.TryGetValue(t.Name, out var attributes))
                continue;
            var sources = t.Attributes.GetValueOrDefault("SourceFiles") is { } s ? PathsOf(s).Paths : [];
            foreach (var (attribute, isFolder) in attributes)
            {
                if (t.Attributes.GetValueOrDefault(attribute) is not { } value)
                    continue;
                var (destinations, cut) = PathsOf(value);
                // The raw value's own paths too, so a literal token is never lost to an expansion cap (S4 review round 2, C3).
                var named = destinations.SelectMany(d => AgentConfigPaths.Named(AgentConfigPaths.Segments(d.Path), isFolder))
                    .Concat(MsBuildExpander.SplitList(MsBuildExpander.Display(value)).SelectMany(p => AgentConfigPaths.Named(AgentConfigPaths.Segments(p), isFolder)));
                // A folder destination takes each source's file name.
                if (isFolder)
                    named = named.Concat(destinations.SelectMany(d => sources.Where(src => src.Path.Length > 0)
                        .SelectMany(src => AgentConfigPaths.Named([.. AgentConfigPaths.Segments(d.Path), AgentConfigPaths.Segments(src.Path)[^1]], false))));
                writes.Add(new(t.Line, t.Target, writers.Keys.First(k => k.Equals(t.Name, StringComparison.OrdinalIgnoreCase)), attribute, value, t.Conditions,
                    destinations, [.. named.Distinct(StringComparer.Ordinal)], PackageFilesOf(sources)) { DestinationsCut = cut });
            }
        }

        var targets = raw.Targets.Select(t => new MsBuildTargetFact(t.Line, t.Name, t.BeforeTargets, t.AfterTargets, t.DependsOnTargets, t.Conditions, t.Inputs, t.Outputs,
            t.Outputs is { Length: > 0 } outputs ? OutputsWritten(outputs, t.Name, Candidates, writes, execs) : null)).ToList();

        var usingTasks = raw.UsingTasks.Select(u =>
        {
            var paths = (u.AssemblyFile is { } file ? PathsOf(file, relative: true).Paths : []).Concat(u.CodeSource is { } source ? PathsOf(source, relative: true).Paths : []);
            var body = u.Body is { Length: > MaxBodyChars } whole ? whole[..MaxBodyChars] : u.Body;
            return new MsBuildUsingTaskFact(u.Line, u.TaskName, u.AssemblyFile, u.AssemblyName, u.TaskFactory, u.Conditions, PackageFilesOf(paths), u.Inline, u.CodeType,
                u.CodeLanguage, u.CodeSource, body, u.BodyChars, invoked.GetValueOrDefault(u.TaskName[(u.TaskName.LastIndexOf('.') + 1)..]))
            {
                AgentConfigMentioned = u.Body is { } all ? AgentConfigPaths.Mentioned(all) : [],
            };
        }).ToList();

        var imports = raw.Imports.Select(i =>
        {
            var paths = i.Project.Length > 0 ? PathsOf(i.Project, relative: true).Paths : [];
            return new MsBuildImportFact(i.Line, i.Project, i.Sdk, i.Conditions, paths, PackageFilesOf(paths));
        }).ToList();

        // Restore and build switches, and any redefinition of a place or name Silvergun reads as known (S4 review C5).
        var notable = raw.Properties.Where(p => NotableProperties.Contains(p.Name) || MsBuildExpander.Overrides(p.Name)
                || p.Name.Equals(expander.PkgProperty, StringComparison.OrdinalIgnoreCase))
            .Select(p => new MsBuildPropertyFact(p.Line, p.Target, p.Name, p.Value, p.Conditions)).ToList();
        return new(fullPath, name, MsBuildFileStatus.Parsed, null, null, MsBuildLoad.None, [], targets, execs, writes, usingTasks, imports, notable, raw.Cut);
    }

    // Whether each of a target's Outputs is named by a write in the same target, by whole path or whole word; null when unknown.
    private static bool? OutputsWritten(string outputs, string target, Func<string, IReadOnlyList<(string Text, bool Unresolved)>> candidates,
        IReadOnlyList<MsBuildWriteFact> writes, IReadOnlyList<MsBuildExecFact> execs)
    {
        var expanded = candidates(outputs);
        if (expanded.Count == 0)
            return null;
        var paths = MsBuildExpander.Paths(expanded[0].Text, expanded[0].Unresolved);
        if (paths.Count == 0 || paths.Any(p => p.Anchor == MsBuildAnchor.Unknown))
            return null;
        var mine = writes.Where(w => w.Target == target).ToList();
        // An Exec's words, each reduced to its last path segment: a word must be the output's file name, not contain it (S4 review W6).
        var words = execs.Where(e => e.Target == target).SelectMany(e => candidates(e.Command))
            .SelectMany(c => MsBuildExpander.Display(c.Text).Split(commandBreaks, StringSplitOptions.RemoveEmptyEntries))
            .Select(w => AgentConfigPaths.Segments(w) is { Count: > 0 } segments ? segments[^1] : "")
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        bool Written(MsBuildPath o) =>
            mine.Any(w => w.Destinations.Any(d => string.Equals(d.Display, o.Display, StringComparison.OrdinalIgnoreCase)
                || (writers[w.Task].Any(a => a.Attribute == w.Attribute && a.IsFolder) && o.Display.StartsWith(d.Display + "/", StringComparison.OrdinalIgnoreCase))))
            || (o.Path.Split('/')[^1] is { Length: > 0 } last && words.Contains(last));
        return paths.All(Written);
    }

    // Each file's load (auto, imported or none) and who imports it, from the auto-imported files along their imports.
    private static List<MsBuildFileFacts> Loads(List<MsBuildFileFacts> facts, string packageId)
    {
        var byPath = facts.ToDictionary(f => f.FullPath, StringComparer.Ordinal);
        var importedBy = facts.SelectMany(f => f.Imports.SelectMany(i => i.PackageFiles).Where(byPath.ContainsKey).Select(target => (target, f.FullPath)))
            .GroupBy(e => e.target, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.Select(e => e.FullPath).Distinct(StringComparer.Ordinal).ToList(), StringComparer.Ordinal);
        var auto = facts.Where(f => AutoImportOf(f.Name, packageId) is not null).Select(f => f.FullPath).ToList();
        var reached = new HashSet<string>(auto, StringComparer.Ordinal);
        var queue = new Queue<string>(auto);
        while (queue.TryDequeue(out var next))
            foreach (var target in byPath[next].Imports.SelectMany(i => i.PackageFiles).Where(byPath.ContainsKey))
                if (reached.Add(target))
                    queue.Enqueue(target);
        return [.. facts.Select(f =>
        {
            var autoImport = AutoImportOf(f.Name, packageId);
            return f with
            {
                AutoImport = autoImport,
                Load = autoImport is not null ? MsBuildLoad.Auto : reached.Contains(f.FullPath) ? MsBuildLoad.Imported : MsBuildLoad.None,
                ImportedBy = importedBy.GetValueOrDefault(f.FullPath) ?? [],
            };
        })];
    }

    private static MsBuildTotals Totals(IReadOnlyList<MsBuildFileFacts> facts)
    {
        (int, int, int, int, int) Count(IEnumerable<MsBuildFileFacts> files) =>
            (files.Sum(f => f.Writes.Count(w => w.AgentConfig.Count > 0)), files.Sum(f => f.Writes.Count(w => w.OutsideOutput == true)),
             files.Sum(f => f.Execs.Count(e => e.PackageFiles.Count > 0)), files.Sum(f => f.UsingTasks.Count(u => u.Inline)),
             files.Sum(f => f.Writes.Count(w => w.OutsideOutput is null)));
        var (agent, outside, execs, inline, unknown) = Count(facts);
        var (loadedAgent, loadedOutside, loadedExecs, loadedInline, loadedUnknown) = Count(facts.Where(f => f.Load != MsBuildLoad.None));
        return new(agent, outside, execs, inline, loadedAgent, loadedOutside, loadedExecs, loadedInline)
        {
            UnknownDestinationWrites = unknown,
            LoadedUnknownDestinationWrites = loadedUnknown,
        };
    }

    private static MsBuildFileFacts Empty(string fullPath, string name, MsBuildFileStatus status, string? reason) =>
        new(fullPath, name, status, reason, null, MsBuildLoad.None, [], [], [], [], [], [], [], 0);

    private static void Add(Dictionary<string, List<(string, string)>> map, string key, (string, string) value, Context context)
    {
        if (!map.TryGetValue(key, out var list))
            map[key] = list = [];
        if (list.Count >= MaxDefinitions)
        {
            list.RemoveAt(0);
            context.ValuesCut++;
            context.Dropped.Add(key);
        }
        list.Add(value);
    }

    private static IReadOnlyList<string> With(IReadOnlyList<string> conditions, string? condition, Raw raw)
    {
        if (condition is not { Length: > 0 } c)
            return conditions;
        if (conditions.Count < MaxConditions)
            return [.. conditions, c];
        raw.Cut++;
        return conditions;
    }

    // An element MSBuild reads: in no namespace or MSBuild's own.
    private static bool Msbuild(XElement e) => e.Name.NamespaceName is "" or MsbuildNamespace;

    private static bool Is(XElement e, string name) => e.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase);

    private static string? Attr(XElement e, string name) =>
        e.Attributes().FirstOrDefault(a => a.Name.NamespaceName.Length == 0 && a.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value;

    // An element's text (its descendants' text, in order), at most `max` chars: never a re-serialisation of package markup (S4 review C2).
    // Also its whole length, counted without building it.
    private static (string Text, int Chars) Text(XElement e, int max)
    {
        var sb = new StringBuilder();
        long chars = 0;
        foreach (var t in e.DescendantNodes().OfType<XText>())
        {
            chars += t.Value.Length;
            if (sb.Length < max)
                sb.Append(t.Value, 0, Math.Min(t.Value.Length, max - sb.Length));
        }
        return (sb.ToString(), (int)Math.Min(chars, int.MaxValue));
    }

    private static int Line(XElement e) => ((IXmlLineInfo)e).LineNumber;
    #endregion

    #region Fields
    public const long MaxFileBytes = 4L * 1024 * 1024;
    public const long MaxPackageBytes = 64L * 1024 * 1024;
    public const int MaxFiles = 2_000;
    public const int MaxBodyChars = 64 * 1024;
    /// <summary>Elements a package reports at most, over all its files; the rest are counted in <see cref="MsBuildFileFacts.FactsCut"/>.</summary>
    public const int MaxElements = 200_000;
    /// <summary>Destinations of one value Silvergun keeps; past it, the write's <see cref="MsBuildWriteFact.DestinationsCut"/>.</summary>
    public const int MaxDestinations = 256;
    /// <summary>A file nested deeper is not parsed.</summary>
    public const int MaxXmlDepth = 64;

    /// <summary>Properties whose assignment changes how the consumer restores or builds.</summary>
    public static readonly IReadOnlySet<string> NotableProperties = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "RestoreAdditionalProjectSources", "RestoreSources", "RestoreConfigFile", "RestoreFallbackFolders", "DisableFastUpToDateCheck", "NuGetAudit",
    };

    private const string MsbuildNamespace = "http://schemas.microsoft.com/developer/msbuild/2003";
    private const int MaxChooseDepth = 16;
    private const int MaxPackageFiles = 8;
    private const int MaxDefinitions = 32;
    private const int MaxConditions = 8;
    private const int MaxBodyReadChars = 1024 * 1024;
    private const int MaxGlobs = 512;

    private static readonly char[] commandBreaks = [' ', '\t', '\r', '\n', '"', '\'', ';', '>', '<', '|', '&', ',', '(', ')', '='];

    // The writing tasks, and the attributes that name where they write (true: a folder).
    private static readonly Dictionary<string, (string Attribute, bool IsFolder)[]> writers = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Copy"] = [("DestinationFolder", true), ("DestinationFiles", false)],
        ["Move"] = [("DestinationFolder", true), ("DestinationFiles", false)],
        ["WriteLinesToFile"] = [("File", false)],
        ["WriteCodeFragment"] = [("OutputFile", false), ("OutputDirectory", true)],
        ["MakeDir"] = [("Directories", true)],
        ["Delete"] = [("Files", false)],
        ["RemoveDir"] = [("Directories", true)],
        ["Touch"] = [("Files", false)],
        ["Unzip"] = [("DestinationFolder", true)],
        ["ZipDirectory"] = [("DestinationFile", false)],
        ["DownloadFile"] = [("DestinationFolder", true)],
        ["XmlPoke"] = [("XmlInputPath", false)],
    };

    private static readonly XmlReaderSettings xmlSettings = new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        // Not 0, which XmlReaderSettings reads as "no limit": with DTDs prohibited only the predefined entities exist.
        MaxCharactersFromEntities = 1024,
        MaxCharactersInDocument = MaxFileBytes * 2,
        IgnoreComments = true,
        IgnoreProcessingInstructions = true,
        CloseInput = true,
    };
    #endregion

    #region Types
    // What the package's files share while they are read: the element budget, the cut values, and the package file lookup.
    private sealed class Context(Dictionary<string, List<string>> files)
    {
        public int Elements { get; set; }
        public int ValuesCut { get; set; }
        // Property and item names that lost a definition to the cap, or that a task sets unseen; one set serves both, a
        // conservative superset.
        public HashSet<string> Dropped { get; } = new(StringComparer.OrdinalIgnoreCase);

        // A task or item in the package could set a property Silvergun cannot name: every settable one may then be anything.
        public bool AnyProperty { get; set; }

        // The package files a package-anchored path names; a wildcard is matched as MSBuild globs it, once per pattern (S4 review W8).
        public IEnumerable<string> Lookup(MsBuildPath path)
        {
            if (path.Anchor != MsBuildAnchor.Package || path.Climbs > 0 || path.Path.Length == 0)
                return [];
            if (!path.Path.Contains('*') && !path.Path.Contains('?'))
                return files.GetValueOrDefault(path.Path) ?? [];
            if (globs.TryGetValue(path.Path, out var known))
                return known;
            if (globs.Count >= MaxGlobs)
            {
                ValuesCut++;
                return [];
            }
            var pattern = "^" + Regex.Escape(path.Path).Replace(@"\*\*/", "(?:.*/)?").Replace(@"\*\*", ".*").Replace(@"\*", "[^/]*").Replace(@"\?", "[^/]") + "$";
            List<string> matched;
            try
            {
                var glob = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, TimeSpan.FromMilliseconds(200));
                matched = [.. files.Where(f => glob.IsMatch(f.Key)).SelectMany(f => f.Value).Take(MaxPackageFiles)];
            }
            catch (Exception ex) when (ex is ArgumentException or RegexMatchTimeoutException or NotSupportedException)
            {
                ValuesCut++;
                matched = [];
            }
            return globs[path.Path] = matched;
        }

        private readonly Dictionary<string, List<string>> globs = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class Raw(Context context)
    {
        public List<RawProperty> Properties { get; } = [];
        public List<RawItem> Items { get; } = [];
        public List<RawTarget> Targets { get; } = [];
        public List<RawTask> Tasks { get; } = [];
        public List<RawUsingTask> UsingTasks { get; } = [];
        public List<RawImport> Imports { get; } = [];
        public int Cut { get; set; }

        // Names a task sets to a value Silvergun cannot see.
        public HashSet<string> Unseen => context.Dropped;

        // Something sets properties Silvergun cannot name.
        public void AnyPropertySet() => context.AnyProperty = true;

        // Whether another element may be kept, within the package's budget; counts the ones that may not.
        public bool Room()
        {
            if (context.Elements < MaxElements)
            {
                context.Elements++;
                return true;
            }
            Cut++;
            return false;
        }
    }

    private sealed record RawProperty(int Line, string? Target, string Name, string Value, IReadOnlyList<string> Conditions);
    private sealed record RawItem(string Type, string Include);
    private sealed record RawTarget(int Line, string Name, string? BeforeTargets, string? AfterTargets, string? DependsOnTargets, IReadOnlyList<string> Conditions, string? Inputs, string? Outputs);
    private sealed record RawTask(int Line, string Target, string Name, Dictionary<string, string> Attributes, IReadOnlyList<string> Conditions);
    private sealed record RawUsingTask(int Line, string TaskName, string? AssemblyFile, string? AssemblyName, string? TaskFactory, IReadOnlyList<string> Conditions,
        bool Inline, string? CodeType, string? CodeLanguage, string? CodeSource, string? Body, int BodyChars);
    private sealed record RawImport(int Line, string Project, string? Sdk, IReadOnlyList<string> Conditions);
    #endregion
}
