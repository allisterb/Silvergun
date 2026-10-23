namespace Silvergun.PackageAnalysis.NuGet.Tests.FakeYaraProbe;

using System.Text;
using System.Text.Json;

/// <summary>
/// <b>Role 4 - a scripted fake of <c>silvergun __worker yara</c> (<c>--fake-worker &lt;script&gt;</c>).</b> The parent
/// backend, <c>YaraXWorkerScanner</c>, takes its worker command as configuration (ADR 0033 decision 8), so the
/// T5 round-2 tests point it at this role to replay exactly the stdout a hostile, broken, slow or genuine worker would
/// produce (worker protocol v1, <c>docs/agent/tasks/yarax-worker.md</c>). It never scans anything and holds no rules: what
/// it "finds" is whatever the script says, and a genuine-looking <c>ready</c> carries whatever hash the script gives it.
///
/// <para><b>Runs.</b> The parent starts one process per run (the availability probe is run 1, the first scan run 2, and so on).
/// Each start increments a counter kept next to the script (<c>&lt;script&gt;.runs</c>), and executes the section
/// <c>@run N</c> for its run number, or <c>@run *</c> when there is none. One command per line; <c>#</c> starts a
/// comment.</para>
///
/// <list type="table">
/// <item><term><c>pid &lt;file&gt;</c></term><description>append this process's id to <c>file</c> (the orphan checks).</description></item>
/// <item><term><c>requests &lt;file&gt;</c></term><description>append every request line read from now on to <c>file</c>.</description></item>
/// <item><term><c>readall</c></term><description>read requests until stdin closes.</description></item>
/// <item><term><c>out &lt;text&gt;</c> / <c>raw &lt;text&gt;</c></term><description>write <c>text</c> to stdout with / without a <c>\n</c>.</description></item>
/// <item><term><c>answer [k]</c></term><description>read up to <c>k</c> more requests (all, when absent) and answer each
/// <c>scanned</c> with one hit whose rule is <c>hit:&lt;file name&gt;</c>, so a test can check attribution.</description></item>
/// <item><term><c>clean [k]</c></term><description>as <c>answer</c>, with no hits.</description></item>
/// <item><term><c>skip [k]</c></term><description>count the next <c>k</c> requests as answered without writing anything
/// (the script wrote their records itself with <c>out</c>).</description></item>
/// <item><term><c>outbig &lt;index&gt; &lt;hits&gt;</c></term><description>a valid <c>scanned</c> result with that many
/// maximal hits (256-char rule and namespace, 64 tags of 256 chars): ~16.9 KB per hit, for the G4 output budget.</description></item>
/// <item><term><c>done [n]</c></term><description><c>done</c> with <c>n</c>, or the number of requests read so far.</description></item>
/// <item><term><c>err &lt;text&gt;</c> / <c>errflood &lt;bytes&gt;</c></term><description>stderr: one line (with <c>\n</c>,
/// <c>\e</c> and <c>\uXXXX</c> decoded), or that many bytes of short lines.</description></item>
/// <item><term><c>sleep &lt;ms&gt;</c> / <c>hang</c> / <c>flood</c> / <c>exit &lt;code&gt;</c></term><description>wait; wait
/// forever; write to stdout forever; exit now. A script that runs out exits 0.</description></item>
/// </list>
/// </summary>
internal static class FakeWorker
{
    #region Methods
    internal static int Run(string script)
    {
        var run = NextRun(script);
        var commands = Section(File.ReadAllLines(script), run);
        var session = new Session();
        foreach (var command in commands)
        {
            var (verb, rest) = Split(command);
            switch (verb)
            {
                case "pid": File.AppendAllText(rest, Environment.ProcessId + "\n"); break;
                case "requests": session.RequestLog = rest; break;
                case "readall": session.Read(int.MaxValue); break;
                case "out": session.Out(rest + "\n"); break;
                case "raw": session.Out(rest); break;
                case "answer": session.Answer(Count(rest), withHit: true); break;
                case "clean": session.Answer(Count(rest), withHit: false); break;
                case "skip": session.Skip(Count(rest)); break;
                case "outbig": session.OutBig(rest); break;
                case "done": session.Out($"{{\"type\":\"done\",\"count\":{(rest.Length == 0 ? session.Requests.Count : int.Parse(rest))}}}\n"); break;
                case "err": session.Err(Decode(rest) + "\n"); break;
                case "errflood": session.ErrFlood(int.Parse(rest)); break;
                case "sleep": Thread.Sleep(int.Parse(rest)); break;
                case "hang": Thread.Sleep(Timeout.Infinite); break;
                case "flood": session.Flood(); break;
                case "exit": return int.Parse(rest);
                default: throw new InvalidOperationException($"fake worker: unknown command '{verb}'");
            }
        }
        return 0;
    }

    // Run numbers are 1-based and per script; the scanner under test runs its workers one at a time.
    private static int NextRun(string script)
    {
        var counter = script + ".runs";
        var run = (File.Exists(counter) ? int.Parse(File.ReadAllText(counter)) : 0) + 1;
        File.WriteAllText(counter, run.ToString(System.Globalization.CultureInfo.InvariantCulture));
        return run;
    }

    private static IReadOnlyList<string> Section(string[] lines, int run)
    {
        List<string>? exact = null, fallback = null, current = null;
        foreach (var line in lines)
        {
            if (line.StartsWith("@run ", StringComparison.Ordinal))
            {
                current = [];
                var which = line[5..].Trim();
                if (which == "*")
                    fallback = current;
                else if (int.Parse(which) == run)
                    exact = current;
                continue;
            }
            if (current is not null && line.Length > 0 && !line.StartsWith('#'))
                current.Add(line);
        }
        return exact ?? fallback ?? [];
    }

    private static (string Verb, string Argument) Split(string command)
    {
        var space = command.IndexOf(' ');
        return space < 0 ? (command, string.Empty) : (command[..space], command[(space + 1)..]);
    }

    private static int Count(string rest) => rest.Length == 0 ? int.MaxValue : int.Parse(rest);

    // \n, \e (ESC) and \uXXXX in an `err` line, so a script can stage control and bidi characters on stderr.
    private static string Decode(string text)
    {
        var sb = new StringBuilder();
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] == '\\' && i + 1 < text.Length && text[i + 1] == 'n') { sb.Append('\n'); i++; }
            else if (text[i] == '\\' && i + 1 < text.Length && text[i + 1] == 'e') { sb.Append((char)0x1B); i++; }
            else if (text[i] == '\\' && i + 5 < text.Length && text[i + 1] == 'u') { sb.Append((char)Convert.ToInt32(text.Substring(i + 2, 4), 16)); i += 5; }
            else sb.Append(text[i]);
        }
        return sb.ToString();
    }
    #endregion

    #region Nested types
    private sealed class Session
    {
        public string? RequestLog { get; set; }

        public List<string> Requests { get; } = [];

        // Reads up to `count` more request lines, stopping early when stdin closes.
        public void Read(int count)
        {
            for (var i = 0; i < count; i++)
            {
                var line = stdin.ReadLine();
                if (line is null)
                    return;
                Requests.Add(line);
                if (RequestLog is not null)
                    File.AppendAllText(RequestLog, line + "\n");
            }
        }

        // Marks the next `count` requests answered without writing anything (the script wrote their lines itself).
        public void Skip(int count)
        {
            Fill(count);
            answered = Math.Min(Requests.Count, answered + count);
        }

        public void Answer(int count, bool withHit)
        {
            var from = answered;
            Fill(count);
            for (var i = from; i < Requests.Count && i - from < count; i++, answered++)
            {
                using var request = JsonDocument.Parse(Requests[i]);
                var path = request.RootElement.GetProperty("path").GetString()!;
                var hits = withHit ? $"{{\"rule\":{JsonSerializer.Serialize("hit:" + Path.GetFileName(path))},\"namespace\":\"default\",\"tags\":[]}}" : string.Empty;
                Out($"{{\"type\":\"result\",\"index\":{i},\"status\":\"scanned\",\"hits\":[{hits}]}}\n");
            }
        }

        // Reads until `count` requests past the answered ones are in hand (all of them for int.MaxValue).
        private void Fill(int count)
        {
            if (count == int.MaxValue)
                Read(int.MaxValue);
            else if (Requests.Count - answered < count)
                Read(count - (Requests.Count - answered));
        }

        public void OutBig(string rest)
        {
            var parts = rest.Split(' ');
            var name = new string('R', 256);
            var tags = "[" + string.Join(",", Enumerable.Repeat("\"" + new string('t', 256) + "\"", 64)) + "]";
            var hit = $"{{\"rule\":\"{name}\",\"namespace\":\"{new string('n', 256)}\",\"tags\":{tags}}}";
            Out($"{{\"type\":\"result\",\"index\":{parts[0]},\"status\":\"scanned\",\"hits\":[{string.Join(",", Enumerable.Repeat(hit, int.Parse(parts[1])))}]}}\n");
        }

        public void Out(string text)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            stdout.Write(bytes);
            stdout.Flush();
        }

        public void Err(string text)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            stderr.Write(bytes);
            stderr.Flush();
        }

        public void ErrFlood(int bytes)
        {
            var line = Encoding.ASCII.GetBytes(new string('e', 127) + "\n");
            for (var written = 0; written < bytes; written += line.Length)
                stderr.Write(line, 0, Math.Min(line.Length, bytes - written));
            stderr.Flush();
        }

        public void Flood()
        {
            var chunk = Encoding.ASCII.GetBytes(new string('x', 64 * 1024));
            while (true)
                stdout.Write(chunk);
        }

        private readonly Stream stdout = Console.OpenStandardOutput();
        private readonly Stream stderr = Console.OpenStandardError();
        private readonly StreamReader stdin = new(Console.OpenStandardInput(), new UTF8Encoding(false));
        private int answered;
    }
    #endregion
}
