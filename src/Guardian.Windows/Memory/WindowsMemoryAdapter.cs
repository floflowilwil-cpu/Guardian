using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Guardian.Contracts.Common;
using Guardian.Contracts.Memory;

namespace Guardian.Windows.Memory;

/// <summary>
/// Adaptateur d'analyse défensive des métadonnées de protection mémoire (<c>VirtualQueryEx</c>) sous Windows.
/// </summary>
/// <remarks>
/// N'utilise jamais <c>PROCESS_VM_READ</c>, ne lit aucun contenu mémoire privé et exclut strictement
/// les processus critiques d'identifiants tels que <c>lsass</c>.
/// </remarks>
public sealed class WindowsMemoryAdapter : IWindowsMemoryAdapter
{
    private const uint ProcessQueryInformation = 0x0400;
    private const uint MemCommit = 0x1000;
    private const uint MemPrivate = 0x20000;
    private const uint PageExecute = 0x10;
    private const uint PageExecuteRead = 0x20;
    private const uint PageExecuteReadWrite = 0x40;
    private const uint PageExecuteWriteCopy = 0x80;
    private const int ErrorAccessDenied = 5;
    private const int MaxVirtualQueryIterations = 100_000;

    private static readonly HashSet<string> ProtectedProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "lsass",
        "csrss",
        "smss",
        "wininit",
        "services",
        "registry",
        "system",
        "idle",
        "memory compression"
    };

    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initialise l'adaptateur d'inspection des métadonnées mémoire.
    /// </summary>
    /// <param name="timeProvider">Fournisseur d'horloge optionnel (par défaut <see cref="TimeProvider.System"/>).</param>
    public WindowsMemoryAdapter(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Détermine si un nom de processus appartient à la liste d'exclusion absolue protégeant les identifiants système.
    /// </summary>
    /// <param name="processName">Nom du processus avec ou sans extension <c>.exe</c>.</param>
    /// <returns><see langword="true"/> si le processus doit être exclu de toute inspection mémoire.</returns>
    public static bool IsProtectedProcessName(string? processName)
    {
        if (string.IsNullOrWhiteSpace(processName))
        {
            return false;
        }

        var normalized = Path.GetFileName(processName.Trim());
        if (normalized.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[..^4];
        }

        return ProtectedProcessNames.Contains(normalized);
    }

    /// <summary>
    /// Classe les attributs bruts d'une région mémoire (<c>State</c>, <c>Type</c>, <c>Protect</c>) en signal défensif le cas échéant.
    /// </summary>
    /// <param name="state">État de la page mémoire (<c>MEM_COMMIT</c>, etc.).</param>
    /// <param name="type">Type d'allocation (<c>MEM_PRIVATE</c>, etc.).</param>
    /// <param name="protect">Indicateurs de protection de la plage mémoire.</param>
    /// <returns>Nature, gravité et description si la région privée est exécutable, sinon <see langword="null"/>.</returns>
    public static (MemorySignalKind Kind, EventSeverity Severity, string Description)? ClassifyRegionProtection(
        uint state,
        uint type,
        uint protect)
    {
        if (state != MemCommit || type != MemPrivate)
        {
            return null;
        }

        var baseProtect = protect & 0xFFu;
        return baseProtect switch
        {
            PageExecuteReadWrite => (
                MemorySignalKind.ReadWriteExecuteRegion,
                EventSeverity.High,
                "Private committed memory region has Read-Write-Execute (RWX) protection."),
            PageExecute or PageExecuteRead or PageExecuteWriteCopy => (
                MemorySignalKind.PrivateExecutableRegion,
                EventSeverity.Medium,
                "Private committed memory region has executable protection."),
            _ => null
        };
    }

    /// <inheritdoc />
    public Task<MemoryAnalysisReportDto> AnalyzeProcessAsync(int processId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var now = _timeProvider.GetUtcNow();

        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult(new MemoryAnalysisReportDto(
                ProcessId: processId,
                ProcessName: "Unknown",
                AnalyzedAtUtc: now,
                Availability: FeatureAvailabilityStatus.Unavailable,
                Summary: "Memory metadata inspection requires Windows.",
                Signals: []));
        }

        var report = AnalyzeProcessWindows(processId, now, cancellationToken);
        return Task.FromResult(report);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<MemoryAnalysisReportDto>> ScanAllAccessibleProcessesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        var processes = Process.GetProcesses();
        var reports = new List<MemoryAnalysisReportDto>(processes.Length);

        try
        {
            foreach (var process in processes)
            {
                cancellationToken.ThrowIfCancellationRequested();

                int pid;
                try
                {
                    pid = process.Id;
                }
                finally
                {
                    process.Dispose();
                }

                var report = await AnalyzeProcessAsync(pid, cancellationToken).ConfigureAwait(false);
                reports.Add(report);
            }
        }
        finally
        {
            foreach (var process in processes)
            {
                process.Dispose();
            }
        }

        return reports;
    }

    [SupportedOSPlatform("windows")]
    private static MemoryAnalysisReportDto AnalyzeProcessWindows(
        int processId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (processId <= 0)
        {
            return new MemoryAnalysisReportDto(
                ProcessId: processId,
                ProcessName: processId == 0 ? "Idle" : "Invalid",
                AnalyzedAtUtc: now,
                Availability: FeatureAvailabilityStatus.Unavailable,
                Summary: "Invalid or idle process identifier skipped.",
                Signals:
                [
                    new MemoryRegionSignalDto(
                        BaseAddress: 0,
                        RegionSizeBytes: 0,
                        Kind: MemorySignalKind.ProtectedProcessSkipped,
                        Severity: EventSeverity.Info,
                        Description: $"Process ID {processId} excluded from memory metadata inspection.")
                ]);
        }

        string processName;
        try
        {
            using var process = Process.GetProcessById(processId);
            processName = process.ProcessName;
        }
        catch (ArgumentException)
        {
            return new MemoryAnalysisReportDto(
                ProcessId: processId,
                ProcessName: "Exited",
                AnalyzedAtUtc: now,
                Availability: FeatureAvailabilityStatus.Unavailable,
                Summary: $"Process ID {processId} is no longer running.",
                Signals: []);
        }
        catch (InvalidOperationException)
        {
            return new MemoryAnalysisReportDto(
                ProcessId: processId,
                ProcessName: "Exited",
                AnalyzedAtUtc: now,
                Availability: FeatureAvailabilityStatus.Unavailable,
                Summary: $"Process ID {processId} has exited.",
                Signals: []);
        }

        if (IsProtectedProcessName(processName))
        {
            return new MemoryAnalysisReportDto(
                ProcessId: processId,
                ProcessName: processName,
                AnalyzedAtUtc: now,
                Availability: FeatureAvailabilityStatus.Unavailable,
                Summary: $"Process '{processName}' is strictly excluded from memory inspection by security and privacy policy.",
                Signals:
                [
                    new MemoryRegionSignalDto(
                        BaseAddress: 0,
                        RegionSizeBytes: 0,
                        Kind: MemorySignalKind.ProtectedProcessSkipped,
                        Severity: EventSeverity.Info,
                        Description: $"Protected credential/system process '{processName}' (PID {processId}) was skipped before OpenProcess.")
                ]);
        }

        if (!global::System.Environment.Is64BitProcess)
        {
            return new MemoryAnalysisReportDto(
                ProcessId: processId,
                ProcessName: processName,
                AnalyzedAtUtc: now,
                Availability: FeatureAvailabilityStatus.Unavailable,
                Summary: "Memory metadata query requires a 64-bit Guardian process.",
                Signals: []);
        }

        var handle = OpenProcess(ProcessQueryInformation, bInheritHandle: false, unchecked((uint)processId));
        if (handle == IntPtr.Zero)
        {
            var error = Marshal.GetLastWin32Error();
            var availability = error == ErrorAccessDenied
                ? FeatureAvailabilityStatus.RequiresElevation
                : FeatureAvailabilityStatus.Unavailable;

            return new MemoryAnalysisReportDto(
                ProcessId: processId,
                ProcessName: processName,
                AnalyzedAtUtc: now,
                Availability: availability,
                Summary: error == ErrorAccessDenied
                    ? $"Access denied querying memory metadata for '{processName}' (PID {processId})."
                    : $"Unable to open process '{processName}' (PID {processId}) for metadata query (Win32 error {error}).",
                Signals: []);
        }

        try
        {
            var signals = QueryMemoryMetadata64(handle, cancellationToken);
            var summary = signals.Count == 0
                ? $"Memory metadata inspection completed for '{processName}' with no suspicious private executable regions."
                : $"Memory metadata inspection completed for '{processName}': {signals.Count} signal(s) observed.";

            return new MemoryAnalysisReportDto(
                ProcessId: processId,
                ProcessName: processName,
                AnalyzedAtUtc: now,
                Availability: FeatureAvailabilityStatus.Available,
                Summary: summary,
                Signals: signals);
        }
        finally
        {
            _ = CloseHandle(handle);
        }
    }

    [SupportedOSPlatform("windows")]
    private static List<MemoryRegionSignalDto> QueryMemoryMetadata64(IntPtr processHandle, CancellationToken cancellationToken)
    {
        var signals = new List<MemoryRegionSignalDto>();
        var mbiSize = checked((UIntPtr)Marshal.SizeOf<MEMORY_BASIC_INFORMATION64>());
        ulong currentAddress = 0;

        for (var iteration = 0; iteration < MaxVirtualQueryIterations; iteration++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var queried = VirtualQueryEx64(
                processHandle,
                new UIntPtr(currentAddress),
                out var mbi,
                mbiSize);

            if (queried == UIntPtr.Zero)
            {
                break;
            }

            var classification = ClassifyRegionProtection(mbi.State, mbi.Type, mbi.Protect);
            if (classification.HasValue)
            {
                var baseAddress = unchecked((long)mbi.BaseAddress.ToUInt64());
                var regionSize = unchecked((long)mbi.RegionSize.ToUInt64());
                signals.Add(new MemoryRegionSignalDto(
                    BaseAddress: baseAddress,
                    RegionSizeBytes: regionSize,
                    Kind: classification.Value.Kind,
                    Severity: classification.Value.Severity,
                    Description: classification.Value.Description));
            }

            var step = mbi.RegionSize.ToUInt64();
            if (step == 0 || ulong.MaxValue - currentAddress < step)
            {
                break;
            }

            currentAddress += step;
            if (currentAddress >= 0x7FFFFFFFFFFFul)
            {
                break;
            }
        }

        return signals;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx", SetLastError = true)]
    private static extern UIntPtr VirtualQueryEx64(
        IntPtr hProcess,
        UIntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION64 lpBuffer,
        UIntPtr dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION64
    {
        public UIntPtr BaseAddress;
        public UIntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
}
