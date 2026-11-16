// Inert fixture: never executed (gated by Arm.Armed). BF13 twin: reflection over its own options type for binding.
using System;

namespace Behaviour
{
    public sealed class Options
    {
        public string Name { get; set; }

        public int Retries { get; set; }

        public void Validate() { }
    }

    public static class Binder
    {
        public static Options Bind(string name, string retries)
        {
            if (!Arm.Armed) return null;
            var options = new Options();
            foreach (var property in typeof(Options).GetProperties())
                property.SetValue(options, Convert.ChangeType(property.Name == "Name" ? name : retries, property.PropertyType));
            typeof(Options).GetMethod("Validate").Invoke(options, null);
            return options;
        }
    }
}
