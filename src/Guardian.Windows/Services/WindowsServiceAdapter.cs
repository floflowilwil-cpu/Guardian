using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Guardian.Contracts.System;

namespace Guardian.Windows.Services;

/// <summary>
/// Adaptateur Win32 en lecture seule interrogeant le Service Control Manager (SCM) via <c>advapi32.dll</c>.
/// </summary>
public sealed class WindowsServiceAdapter : IWindowsServiceAdapter
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ScManagerEnumerateService = 0x0004;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const uint ServiceWin32 = 0x00000030;
    private const uint ServiceStateAll = 0x00000003;
    private const int ScEnumProcessInfo = 0;
    private const int ScStatusProcessInfo = 0;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorMoreData = 234;

    /// <inheritdoc />
    public Task<IReadOnlyList<WindowsServiceInfoDto>> GetServicesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<WindowsServiceInfoDto>>([]);
        }

        var services = EnumerateServicesWindows(cancellationToken);
        return Task.FromResult<IReadOnlyList<WindowsServiceInfoDto>>(services);
    }

    /// <inheritdoc />
    public Task<WindowsServiceInfoDto?> GetServiceByNameAsync(string serviceName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
        cancellationToken.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<WindowsServiceInfoDto?>(null);
        }

        var service = QuerySingleServiceWindows(serviceName);
        return Task.FromResult(service);
    }

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<WindowsServiceInfoDto> EnumerateServicesWindows(CancellationToken cancellationToken)
    {
        var scmHandle = OpenSCManagerW(null, null, ScManagerEnumerateService);
        if (scmHandle == IntPtr.Zero)
        {
            return [];
        }

        try
        {
            uint bytesNeeded = 0;
            uint servicesReturned = 0;
            uint resumeHandle = 0;

            _ = EnumServicesStatusExW(
                scmHandle,
                ScEnumProcessInfo,
                ServiceWin32,
                ServiceStateAll,
                IntPtr.Zero,
                0,
                out bytesNeeded,
                out servicesReturned,
                ref resumeHandle,
                null);

            var lastError = Marshal.GetLastWin32Error();
            if (lastError != ErrorMoreData || bytesNeeded == 0)
            {
                return [];
            }

            var bufferSize = bytesNeeded + 4096;
            for (var attempt = 0; attempt < 3; attempt++)
            {
                var buffer = Marshal.AllocHGlobal(checked((int)bufferSize));
                try
                {
                    resumeHandle = 0;
                    var ok = EnumServicesStatusExW(
                        scmHandle,
                        ScEnumProcessInfo,
                        ServiceWin32,
                        ServiceStateAll,
                        buffer,
                        bufferSize,
                        out bytesNeeded,
                        out servicesReturned,
                        ref resumeHandle,
                        null);

                    if (!ok)
                    {
                        var err = Marshal.GetLastWin32Error();
                        if (err == ErrorMoreData && bytesNeeded > bufferSize)
                        {
                            bufferSize = bytesNeeded + 4096;
                            continue;
                        }

                        return [];
                    }

                    var results = new List<WindowsServiceInfoDto>(checked((int)servicesReturned));
                    var entrySize = Marshal.SizeOf<ENUM_SERVICE_STATUS_PROCESSW>();
                    var currentPtr = buffer;

                    for (var i = 0; i < servicesReturned; i++)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var entry = Marshal.PtrToStructure<ENUM_SERVICE_STATUS_PROCESSW>(currentPtr);
                        var name = Marshal.PtrToStringUni(entry.lpServiceName) ?? string.Empty;
                        var displayName = Marshal.PtrToStringUni(entry.lpDisplayName) ?? name;

                        var (startMode, binaryPath, accountName, _) = QueryServiceConfigSafe(scmHandle, name);

                        results.Add(new WindowsServiceInfoDto(
                            ServiceName: name,
                            DisplayName: displayName,
                            State: MapServiceState(entry.ServiceStatusProcess.dwCurrentState),
                            StartMode: startMode,
                            BinaryPath: binaryPath,
                            AccountName: accountName,
                            ProcessId: entry.ServiceStatusProcess.dwProcessId > 0
                                ? unchecked((int)entry.ServiceStatusProcess.dwProcessId)
                                : null));

                        currentPtr = IntPtr.Add(currentPtr, entrySize);
                    }

                    return results;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            return [];
        }
        finally
        {
            CloseServiceHandle(scmHandle);
        }
    }

    [SupportedOSPlatform("windows")]
    private static WindowsServiceInfoDto? QuerySingleServiceWindows(string serviceName)
    {
        var scmHandle = OpenSCManagerW(null, null, ScManagerConnect);
        if (scmHandle == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var serviceHandle = OpenServiceW(scmHandle, serviceName, ServiceQueryStatus | ServiceQueryConfig);
            var canQueryConfig = true;
            if (serviceHandle == IntPtr.Zero)
            {
                serviceHandle = OpenServiceW(scmHandle, serviceName, ServiceQueryStatus);
                canQueryConfig = false;
                if (serviceHandle == IntPtr.Zero)
                {
                    return null;
                }
            }

            try
            {
                var status = QueryServiceStatusProcess(serviceHandle);
                var (startMode, binaryPath, accountName, displayName) = canQueryConfig
                    ? QueryServiceConfigFromHandle(serviceHandle)
                    : (WindowsServiceStartMode.Unknown, null, null, null);

                return new WindowsServiceInfoDto(
                    ServiceName: serviceName,
                    DisplayName: string.IsNullOrWhiteSpace(displayName) ? serviceName : displayName,
                    State: status.HasValue ? MapServiceState(status.Value.dwCurrentState) : WindowsServiceState.Unknown,
                    StartMode: startMode,
                    BinaryPath: binaryPath,
                    AccountName: accountName,
                    ProcessId: status is { dwProcessId: > 0 } s
                        ? unchecked((int)s.dwProcessId)
                        : null);
            }
            finally
            {
                CloseServiceHandle(serviceHandle);
            }
        }
        finally
        {
            CloseServiceHandle(scmHandle);
        }
    }

    [SupportedOSPlatform("windows")]
    private static (WindowsServiceStartMode StartMode, string? BinaryPath, string? AccountName, string? DisplayName) QueryServiceConfigSafe(
        IntPtr scmHandle,
        string serviceName)
    {
        if (string.IsNullOrWhiteSpace(serviceName))
        {
            return (WindowsServiceStartMode.Unknown, null, null, null);
        }

        var serviceHandle = OpenServiceW(scmHandle, serviceName, ServiceQueryConfig);
        if (serviceHandle == IntPtr.Zero)
        {
            return (WindowsServiceStartMode.Unknown, null, null, null);
        }

        try
        {
            return QueryServiceConfigFromHandle(serviceHandle);
        }
        finally
        {
            CloseServiceHandle(serviceHandle);
        }
    }

    [SupportedOSPlatform("windows")]
    private static (WindowsServiceStartMode StartMode, string? BinaryPath, string? AccountName, string? DisplayName) QueryServiceConfigFromHandle(
        IntPtr serviceHandle)
    {
        _ = QueryServiceConfigW(serviceHandle, IntPtr.Zero, 0, out var bytesNeeded);
        var lastError = Marshal.GetLastWin32Error();
        if (lastError != ErrorInsufficientBuffer || bytesNeeded == 0)
        {
            return (WindowsServiceStartMode.Unknown, null, null, null);
        }

        var buffer = Marshal.AllocHGlobal(checked((int)bytesNeeded));
        try
        {
            if (!QueryServiceConfigW(serviceHandle, buffer, bytesNeeded, out _))
            {
                return (WindowsServiceStartMode.Unknown, null, null, null);
            }

            var config = Marshal.PtrToStructure<QUERY_SERVICE_CONFIGW>(buffer);
            var startMode = MapStartMode(config.dwStartType);
            var binaryPath = Marshal.PtrToStringUni(config.lpBinaryPathName);
            var accountName = Marshal.PtrToStringUni(config.lpServiceStartName);
            var displayName = Marshal.PtrToStringUni(config.lpDisplayName);

            return (
                startMode,
                string.IsNullOrWhiteSpace(binaryPath) ? null : binaryPath,
                string.IsNullOrWhiteSpace(accountName) ? null : accountName,
                string.IsNullOrWhiteSpace(displayName) ? null : displayName);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [SupportedOSPlatform("windows")]
    private static SERVICE_STATUS_PROCESS? QueryServiceStatusProcess(IntPtr serviceHandle)
    {
        var structSize = checked((uint)Marshal.SizeOf<SERVICE_STATUS_PROCESS>());
        var buffer = Marshal.AllocHGlobal(checked((int)structSize));
        try
        {
            if (!QueryServiceStatusEx(serviceHandle, ScStatusProcessInfo, buffer, structSize, out _))
            {
                return null;
            }

            return Marshal.PtrToStructure<SERVICE_STATUS_PROCESS>(buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static WindowsServiceState MapServiceState(uint rawState)
    {
        return rawState switch
        {
            1 => WindowsServiceState.Stopped,
            2 => WindowsServiceState.StartPending,
            3 => WindowsServiceState.StopPending,
            4 => WindowsServiceState.Running,
            5 => WindowsServiceState.ContinuePending,
            6 => WindowsServiceState.PausePending,
            7 => WindowsServiceState.Paused,
            _ => WindowsServiceState.Unknown
        };
    }

    private static WindowsServiceStartMode MapStartMode(uint rawStartType)
    {
        return rawStartType switch
        {
            0 => WindowsServiceStartMode.Boot,
            1 => WindowsServiceStartMode.System,
            2 => WindowsServiceStartMode.Automatic,
            3 => WindowsServiceStartMode.Manual,
            4 => WindowsServiceStartMode.Disabled,
            _ => WindowsServiceStartMode.Unknown
        };
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManagerW(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumServicesStatusExW(
        IntPtr hSCManager,
        int infoLevel,
        uint dwServiceType,
        uint dwServiceState,
        IntPtr lpServices,
        uint cbBufSize,
        out uint pcbBytesNeeded,
        out uint lpServicesReturned,
        ref uint lpResumeHandle,
        string? pszGroupName);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenServiceW(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfigW(
        IntPtr hService,
        IntPtr lpServiceConfig,
        uint cbBufSize,
        out uint pcbBytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(
        IntPtr hService,
        int infoLevel,
        IntPtr lpBuffer,
        uint cbBufSize,
        out uint pcbBytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ENUM_SERVICE_STATUS_PROCESSW
    {
        public IntPtr lpServiceName;
        public IntPtr lpDisplayName;
        public SERVICE_STATUS_PROCESS ServiceStatusProcess;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
        public uint dwProcessId;
        public uint dwServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct QUERY_SERVICE_CONFIGW
    {
        public uint dwServiceType;
        public uint dwStartType;
        public uint dwErrorControl;
        public IntPtr lpBinaryPathName;
        public IntPtr lpLoadOrderGroup;
        public uint dwTagId;
        public IntPtr lpDependencies;
        public IntPtr lpServiceStartName;
        public IntPtr lpDisplayName;
    }
}
