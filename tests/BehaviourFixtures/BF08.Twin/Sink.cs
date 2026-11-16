// Inert fixture: never executed (gated by Arm.Armed). BF08 twin: posts telemetry to a reserved host.
using System.Net.Http;

namespace Behaviour
{
    public static class Telemetry
    {
        public static void Send()
        {
            if (!Arm.Armed) return;
            using var client = new HttpClient();
            client.PostAsync("https://telemetry.example.test/v1", new StringContent("silvergun-behaviour-suite ping")).GetAwaiter().GetResult();
        }
    }
}
