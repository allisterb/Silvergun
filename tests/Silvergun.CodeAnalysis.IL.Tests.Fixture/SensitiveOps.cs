namespace Silvergun.CodeAnalysis.IL.Tests.Fixture;

using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

#pragma warning disable SYSLIB0014 // WebClient is obsolete; used only as a static-analysis target, never executed.

/// <summary>
/// Method bodies that call into sensitive BCL APIs. This type is the target under analysis
/// for the capability tests: the methods are statically disassembled, never executed, so the
/// bodies only need the calls present.
/// </summary>
public class SensitiveOps
{
    /// <summary>File-system reads: <see cref="File.ReadAllText(string)"/> and <see cref="Directory.Exists(string)"/>.</summary>
    public string ReadsFiles(string path)
    {
        if (Directory.Exists(path))
        {
            return File.ReadAllText(path);
        }
        return string.Empty;
    }

    /// <summary>Network access: constructs a <see cref="System.Net.WebClient"/> and calls DownloadString.</summary>
    public string TalksToNetwork()
    {
        var client = new System.Net.WebClient();
        return client.DownloadString("http://example.invalid");
    }

    /// <summary>
    /// Constructor-only sensitive call: builds a <see cref="FileStream"/> and returns it without
    /// touching any member. The single sensitive call is the <c>System.IO.FileStream..ctor</c>, so
    /// this method guards constructor-call detection specifically.
    /// </summary>
    public object CreatesFileStream(string path) => new FileStream(path, FileMode.Open);

    /// <summary>Process execution: <see cref="Process.Start(string)"/>.</summary>
    public Process SpawnsProcess(string exe)
    {
        return Process.Start(exe);
    }

    /// <summary>Environment probe: <see cref="Environment.GetEnvironmentVariable(string)"/> and <see cref="Environment.UserName"/>.</summary>
    public string ProbesEnvironment()
    {
        var path = Environment.GetEnvironmentVariable("PATH");
        var user = Environment.UserName;
        return path + user;
    }

    /// <summary>Dynamic code loading: <see cref="Assembly.Load(byte[])"/>.</summary>
    public Assembly LoadsCode(byte[] raw)
    {
        return Assembly.Load(raw);
    }

    /// <summary>Arithmetic only: must produce zero findings.</summary>
    public int Clean(int x)
    {
        var a = x * 3;
        var b = a + x - 7;
        return b * 2;
    }
}

#pragma warning restore SYSLIB0014
