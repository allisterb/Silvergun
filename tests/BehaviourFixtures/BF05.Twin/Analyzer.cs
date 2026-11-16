// Inert fixture: never executed (gated by Arm.Armed). BF05 twin: an analyzer that registers a syntax action and reads its own settings.
using System;
using System.IO;

namespace Behaviour
{
    public sealed class SyntaxAnalyzer : Microsoft.CodeAnalysis.Diagnostics.DiagnosticAnalyzer
    {
        private static Action<object> registered;

        internal static string Settings;

        public override void Initialize(object context)
        {
            if (!Arm.Armed) return;
            var settings = Path.Combine(AppContext.BaseDirectory, "analyzer.settings.json");
            if (File.Exists(settings))
                Settings = File.ReadAllText(settings);
            // Legitimate enumeration: per-user analyzer config files under a vendor settings folder.
            var vendor = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SilvergunBehaviourVendor", "Analyzers");
            if (Directory.Exists(vendor))
                foreach (var config in Directory.GetFiles(vendor, "*.config.json"))
                    Settings += File.ReadAllText(config);
            registered = Visit;
        }

        private static void Visit(object node) { }
    }
}
