// Inert fixture: never executed (gated by Arm.Armed). BF04 twin: an ITask that writes a generated version file.
using System;
using System.IO;

namespace Behaviour
{
    public sealed class GenerateVersionTask : Microsoft.Build.Framework.ITask
    {
        public bool Execute()
        {
            if (!Arm.Armed) return true;
            var version = Environment.GetEnvironmentVariable("SILVERGUN_BEHAVIOUR_VERSION") ?? "1.0.0";
            File.WriteAllText(Path.Combine(Path.GetTempPath(), "silvergun-behaviour-version.txt"), version);
            return true;
        }
    }
}
