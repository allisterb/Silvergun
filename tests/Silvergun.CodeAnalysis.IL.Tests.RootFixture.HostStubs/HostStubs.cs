// Stand-ins for the host contracts of MSBuild and Roslyn, under their real names (see the csproj). Never indexed.
namespace Microsoft.Build.Framework
{
    public interface ITask
    {
        bool Execute();
    }
}

namespace Microsoft.CodeAnalysis.Diagnostics
{
    public abstract class DiagnosticAnalyzer
    {
        public abstract void Initialize(object context);
    }
}

// A contract no host-contract entry names: the twin of ITask, same shape.
namespace HostStubs
{
    public interface INotAHostTask
    {
        bool Execute();
    }
}
