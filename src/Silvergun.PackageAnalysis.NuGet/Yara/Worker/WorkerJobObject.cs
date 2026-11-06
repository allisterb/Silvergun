#if WINDOWS
namespace Silvergun.PackageAnalysis.NuGet.Yara.Worker;

using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

/// <summary>
/// A Windows Job Object with <c>JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE</c> (worker protocol v1 launch rule; ADR 0033
/// decision 3): every process assigned to it is terminated by the OS when the job's last handle closes, so a worker
/// cannot outlive its parent, even when the parent is killed and none of its own cleanup runs. Disposing this object
/// closes the handle, and therefore kills every worker still assigned to it. Thread-safe: the handle is a
/// <see cref="SafeHandle"/>, so an assignment racing a dispose fails with <see cref="ObjectDisposedException"/> instead of
/// using a closed handle. Plain kernel32 P/Invoke; no package dependency.
/// </summary>
internal sealed partial class WorkerJobObject : IDisposable
{
    #region Constructors
    private WorkerJobObject(SafeJobHandle handle) => this.handle = handle;
    #endregion

    #region Methods
    /// <summary>
    /// A new, unnamed job that kills its processes when closed, and, when <paramref name="processMemoryLimit"/> is not 0,
    /// caps each process's committed memory at that many bytes (<c>JOB_OBJECT_LIMIT_PROCESS_MEMORY</c>: an allocation past
    /// it fails). Throws <see cref="Win32Exception"/> on failure.
    /// </summary>
    internal static WorkerJobObject Create(ulong processMemoryLimit = 0)
    {
        var job = CreateJobObjectW(0, null);
        if (job.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            job.Dispose();
            throw new Win32Exception(error, "CreateJobObject failed");
        }

        var limits = new ExtendedLimitInformation
        {
            BasicLimitInformation = new() { LimitFlags = KillOnJobClose | (processMemoryLimit > 0 ? ProcessMemory : 0) },
            ProcessMemoryLimit = (nuint)processMemoryLimit,
        };
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref limits, (uint)Marshal.SizeOf<ExtendedLimitInformation>()))
        {
            var error = Marshal.GetLastPInvokeError();
            job.Dispose();
            throw new Win32Exception(error, "SetInformationJobObject(KILL_ON_JOB_CLOSE) failed");
        }

        return new WorkerJobObject(job);
    }

    /// <summary>Assigns <paramref name="process"/> to this job. Throws <see cref="Win32Exception"/> on failure.</summary>
    internal void Assign(Process process)
    {
        if (!AssignProcessToJobObject(handle, process.SafeHandle))
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "AssignProcessToJobObject failed");
    }

    /// <summary>Closes the job handle: every process still in the job is terminated (KILL_ON_JOB_CLOSE). Idempotent.</summary>
    public void Dispose() => handle.Dispose();

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeJobHandle CreateJobObjectW(nint jobAttributes, string? name);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetInformationJobObject(SafeJobHandle job, int infoClass, ref ExtendedLimitInformation info, uint length);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AssignProcessToJobObject(SafeJobHandle job, SafeProcessHandle process);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);
    #endregion

    #region Fields
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint KillOnJobClose = 0x2000;   // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    private const uint ProcessMemory = 0x100;     // JOB_OBJECT_LIMIT_PROCESS_MEMORY

    private readonly SafeJobHandle handle;
    #endregion

    #region Child types
    // A job handle; closed with CloseHandle.
    private sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeJobHandle() : base(ownsHandle: true) { }

        protected override bool ReleaseHandle() => CloseHandle(handle);
    }

    // JOBOBJECT_BASIC_LIMIT_INFORMATION (winnt.h), natural layout.
    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public nuint MinimumWorkingSetSize;
        public nuint MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public nuint Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    // IO_COUNTERS (winnt.h).
    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    // JOBOBJECT_EXTENDED_LIMIT_INFORMATION (winnt.h), natural layout.
    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimitInformation
    {
        public BasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public nuint ProcessMemoryLimit;
        public nuint JobMemoryLimit;
        public nuint PeakProcessMemoryUsed;
        public nuint PeakJobMemoryUsed;
    }
    #endregion
}
#endif
