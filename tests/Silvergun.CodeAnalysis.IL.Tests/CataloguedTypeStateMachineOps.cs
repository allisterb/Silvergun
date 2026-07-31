// A DELIBERATE NAMESPACE/TYPE-NAME COLLISION WITH A CATALOGUED BCL TYPE.
//
// The subject of architect decision 2 in docs/agent/tasks/capability-map.md is a compiler-generated state machine
// NESTED INSIDE a catalogued type: CoreLib's real System.IO.File.<IterateFileLinesAsync>d__124..ctor, which the
// legacy StartsWith matcher reported as FileSystem (because "System.IO.File.<...>d__124".StartsWith("System.IO.File"))
// and the map's exact-type form does not. That shape cannot be authored inside an ordinary fixture type, because
// the property under test is a fact about the DECLARING TYPE'S NAME, not about the state machine.
//
// So the shape is reproduced by declaring a type whose full name is one the map catalogues -
// Microsoft.Win32.Registry ("capability Microsoft.Win32.Registry Registry") - and putting an iterator on it.
//
// MEASURED, not assumed: net10.0 on Windows DOES ship a Microsoft.Win32.Registry facade, so this declaration
// shadows it and the compiler reports CS0436 ("using the type defined in this project") at each use site. That is
// the intended binding - the fixture type is the one that must end up in this assembly's metadata - and the two use
// sites suppress the warning locally rather than repo-wide. Nothing in the suite calls the real registry API, so
// shadowing it costs nothing; the only requirement is the NAME.
//
// An ITERATOR rather than an async method on purpose: Roslyn emits an iterator's state machine as a CLASS (hence a
// newobj call site for its .ctor) in every build configuration, whereas an async state machine is a struct in
// Release. The call site under test must exist whether the suite is built Debug or Release.
namespace Microsoft.Win32
{
    using System.Collections.Generic;

    /// <summary>
    /// Named to collide with the catalogued <c>Microsoft.Win32.Registry</c> so its compiler-generated iterator
    /// state machine is nested under a <em>catalogued</em> type, exactly as CoreLib's
    /// <c>System.IO.File.&lt;IterateFileLinesAsync&gt;d__124</c> is. Analyzed statically, never executed — nothing
    /// here touches the registry or the file system.
    /// </summary>
    public static class Registry
    {
        /// <summary>
        /// SUBJECT (architect decision 2). Two facts live in this one method:
        /// <list type="number">
        /// <item><description>its kickoff body carries a <c>newobj</c> of the nested state machine
        /// <c>Microsoft.Win32.Registry.&lt;IterateLines&gt;d__0</c> — the call site the legacy prefix matcher
        /// classified and the map deliberately does not, because a state-machine constructor is not a capability
        /// use;</description></item>
        /// <item><description>its <c>MoveNext</c> carries a genuine <c>System.IO.File</c> call, which is a separate
        /// call site and must still be detected. Losing THAT would be a real regression.</description></item>
        /// </list>
        /// Never called.
        /// </summary>
        public static IEnumerable<string> IterateLines(string path)
        {
            foreach (var line in System.IO.File.ReadLines(path))
                yield return line;
        }

        /// <summary>
        /// The control that keeps the decision-2 assertion honest: an ordinary (non-iterator) member of the same
        /// catalogued type, whose own key <c>Microsoft.Win32.Registry.ReadsValue</c> DOES reach the type entry.
        /// Without it, "no finding for the state machine" could equally mean "the catalogued name is not in the
        /// map at all". Never called.
        /// </summary>
        public static string ReadsValue(string name) => name;
    }
}
