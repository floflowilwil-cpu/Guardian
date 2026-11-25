using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Guardian.Contracts.Common;
using Guardian.Contracts.System;

namespace Guardian.Windows.Processes;

/// <summary>
/// Adaptateur en lecture seule utilisant les APIs Windows à privilège minimal pour inventorier les processus actifs.
/// </summary>
public sealed class WindowsProcessAdapter : IWindowsProcessAdapter
{
    private const uint Th32csSnapProcess = 0x00000002;
    private const uint ProcessQueryLimitedInformation = 0x1000;

    /// <inheritdoc />
    public Task<IReadOnlyList<ProcessInfoDto>> GetProcessesAsync(
        bool includeModules = false,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<ProcessInfoDto>>([]);
        }

        var list = EnumerateProcessesWindows(includeModules, cancellationToken);
        return Task.FromResult<IReadOnlyList<ProcessInfoDto>>(list);
    }

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<ProcessInfoDto> EnumerateProcessesWindows(
        bool includeModules,
        CancellationToken cancellationToken)
    {
        var parentMap = CaptureParentProcessMap();
        var processes = Process.GetProcesses();
        var results = new List<ProcessInfoDto>(processes.Length);

        try
        {
            foreach (var process in processes)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    var pid = process.Id;
                    var name = SafeGetProcessName(process);
                    var sessionId = SafeGetSessionId(process);
                    int? parentPid = parentMap.TryGetValue(pid, out var resolvedParent)
                        ? resolvedParent
                        : null;

                    var (executablePath, pathRestricted, pathNotes) = QueryExecutablePathSafe(pid);
                    var startTimeUtc = TryGetStartTimeUtc(process);

                    var accessStatus = pathRestricted
                        ? FeatureAvailabilityStatus.RequiresElevation
                        : FeatureAvailabilityStatus.Available;
                    var accessNotes = pathNotes;
                    IReadOnlyList<LoadedModuleDto> modules = [];

                    if (includeModules)
                    {
                        var (collectedModules, modStatus, modNote) = TryGetLoadedModules(process);
                        modules = collectedModules;
                        if (modStatus != FeatureAvailabilityStatus.Available && accessStatus == FeatureAvailabilityStatus.Available)
                        {
                            accessStatus = modStatus;
                            accessNotes = modNote;
                        }
                    }

                    results.Add(new ProcessInfoDto(
                        ProcessId: pid,
                        ParentProcessId: parentPid,
                        ProcessName: name,
                        ExecutablePath: executablePath,
                        SessionId: sessionId,
                        StartTimeUtc: startTimeUtc,
                        AccessStatus: accessStatus,
                        AccessNotes: accessNotes,
                        Modules: modules));
                }
                finally
                {
                    process.Dispose();
                }
            }
        }
        finally
        {
            foreach (var process in processes)
            {
                process.Dispose();
            }
        }

        return results;
    }

    [SupportedOSPlatform("windows")]
    private static Dictionary<int, int> CaptureParentProcessMap()
    {
        var map = new Dictionary<int, int>();
        var snapshot = CreateToolhelp32Snapshot(Th32csSnapProcess, 0);
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
        {
            return map;
        }

        try
        {
            var entry = new PROCESSENTRY32W
            {
                dwSize = checked((uint)Marshal.SizeOf<PROCESSENTRY32W>()),
                szExeFile = string.Empty
            };

            if (!Process32FirstW(snapshot, ref entry))
            {
                return map;
            }

            do
            {
                map[unchecked((int)entry.th32ProcessID)] = unchecked((int)entry.th32ParentProcessID);
            }
            while (Process32NextW(snapshot, ref entry));
        }
        finally
        {
            _ = CloseHandle(snapshot);
        }

        return map;
    }

    [SupportedOSPlatform("windows")]
    private static (string? ExecutablePath, bool AccessRestricted, string? Notes) QueryExecutablePathSafe(int processId)
    {
        if (processId is 0 or 4)
        {
            return (null, false, "System kernel or idle process.");
        }

        var handle = OpenProcess(ProcessQueryLimitedInformation, bInheritHandle: false, unchecked((uint)processId));
        if (handle == IntPtr.Zero)
        {
            var error = Marshal.GetLastWin32Error();
            return error == 5
                ? (null, true, "Access denied while querying process image path (elevation required).")
                : (null, false, null);
        }

        try
        {
            var capacity = 1024u;
            var buffer = Marshal.AllocHGlobal(checked((int)(capacity * 2)));
            try
            {
                if (QueryFullProcessImageNameW(handle, 0, buffer, ref capacity))
                {
                    var path = Marshal.PtrToStringUni(buffer, checked((int)capacity));
                    return (string.IsNullOrWhiteSpace(path) ? null : path, false, null);
                }

                return (null, false, null);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            _ = CloseHandle(handle);
        }
    }

    private static (IReadOnlyList<LoadedModuleDto> Modules, FeatureAvailabilityStatus Status, string? Note) TryGetLoadedModules(Process process)
    {
        try
        {
            var moduleCollection = process.Modules;
            var modules = new List<LoadedModuleDto>(moduleCollection.Count);
            foreach (ProcessModule module in moduleCollection)
            {
                modules.Add(new LoadedModuleDto(
                    ModuleName: module.ModuleName,
                    FilePath: module.FileName,
                    BaseAddress: module.BaseAddress.ToInt64(),
                    MemorySizeBytes: module.ModuleMemorySize,
                    IsSigned: null));
            }

            return (modules, FeatureAvailabilityStatus.Available, null);
        }
        catch (Win32Exception ex)
        {
            return ([], FeatureAvailabilityStatus.RequiresElevation, ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            return ([], FeatureAvailabilityStatus.Unavailable, ex.Message);
        }
    }

    private static string SafeGetProcessName(Process process)
    {
        try
        {
            return process.ProcessName;
        }
        catch
        {
            return "Unknown";
        }
    }

    private static int SafeGetSessionId(Process process)
    {
        try
        {
            return process.SessionId;
        }
        catch
        {
            return -1;
        }
    }

    private static DateTimeOffset? TryGetStartTimeUtc(Process process)
    {
        try
        {
            return new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero);
        }
        catch
        {
            return null;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags, IntPtr lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public UIntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }
}
