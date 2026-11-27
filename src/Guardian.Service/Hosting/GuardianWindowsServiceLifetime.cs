using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Guardian.Service.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Guardian.Service.Hosting;

/// <summary>
/// Implémentation <see cref="IHostLifetime"/> reliant le cycle de vie de l'hôte .NET au Service Control Manager (SCM) Windows
/// via les APIs natives <c>advapi32.dll</c> sans dépendance externe supplémentaire.
/// </summary>
public sealed class GuardianWindowsServiceLifetime : IHostLifetime, IDisposable
{
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceStopped = 0x00000001;
    private const uint ServiceStartPending = 0x00000002;
    private const uint ServiceStopPending = 0x00000003;
    private const uint ServiceRunning = 0x00000004;
    private const uint ServiceAcceptStop = 0x00000001;
    private const uint ServiceAcceptShutdown = 0x00000004;
    private const uint ServiceControlStop = 0x00000001;
    private const uint ServiceControlShutdown = 0x00000005;
    private const uint ServiceControlInterrogate = 0x00000004;

    private readonly IHostApplicationLifetime _applicationLifetime;
    private readonly GuardianServiceOptions _options;
    private readonly ILogger<GuardianWindowsServiceLifetime> _logger;
    private readonly TaskCompletionSource _serviceStartedTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ManualResetEventSlim _dispatcherStoppedEvent = new(initialState: false);

    private readonly ServiceMainFunction? _serviceMainDelegate;
    private readonly ServiceControlHandlerEx? _controlHandlerDelegate;

    private IntPtr _serviceStatusHandle;
    private uint _currentState = ServiceStartPending;
    private uint _checkPoint;
    private CancellationTokenRegistration _startedRegistration;
    private CancellationTokenRegistration _stoppingRegistration;

    /// <summary>
    /// Initialise le gestionnaire de cycle de vie Windows Service.
    /// </summary>
    /// <param name="applicationLifetime">Contrat de cycle de vie applicatif de l'hôte.</param>
    /// <param name="options">Options validées du service Guardian.</param>
    /// <param name="logger">Journaliseur du cycle de vie SCM.</param>
    public GuardianWindowsServiceLifetime(
        IHostApplicationLifetime applicationLifetime,
        IOptions<GuardianServiceOptions> options,
        ILogger<GuardianWindowsServiceLifetime> logger)
    {
        _applicationLifetime = applicationLifetime ?? throw new ArgumentNullException(nameof(applicationLifetime));
        _options = (options ?? throw new ArgumentNullException(nameof(options))).Value;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        if (OperatingSystem.IsWindows())
        {
            _serviceMainDelegate = ServiceMain;
            _controlHandlerDelegate = HandleServiceControl;
        }
    }

    /// <summary>
    /// Détermine si le processus courant s'exécute comme service Windows non interactif en session 0.
    /// </summary>
    /// <returns><see langword="true"/> sous Windows en session non interactive, sinon <see langword="false"/>.</returns>
    [SupportedOSPlatformGuard("windows")]
    public static bool IsRunningAsWindowsService()
    {
        if (!OperatingSystem.IsWindows() || global::System.Environment.UserInteractive)
        {
            return false;
        }

        try
        {
            using var currentProcess = Process.GetCurrentProcess();
            return currentProcess.SessionId == 0;
        }
        catch
        {
            return false;
        }
    }

    /// <inheritdoc />
    public Task WaitForStartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!IsRunningAsWindowsService())
        {
            _dispatcherStoppedEvent.Set();
            return Task.CompletedTask;
        }

        return WaitForWindowsServiceStartAsync(cancellationToken);
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsWindows() && _serviceStatusHandle != IntPtr.Zero)
        {
            ReportServiceStatusWindows(ServiceStopped, exitCode: 0, waitHintMs: 0);
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _startedRegistration.Dispose();
        _stoppingRegistration.Dispose();
        _dispatcherStoppedEvent.Dispose();
    }

    [SupportedOSPlatform("windows")]
    private Task WaitForWindowsServiceStartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.Register(() => _serviceStartedTcs.TrySetCanceled(cancellationToken));

        _startedRegistration = _applicationLifetime.ApplicationStarted.Register(() =>
        {
            if (_serviceStatusHandle != IntPtr.Zero)
            {
                ReportServiceStatusWindows(ServiceRunning, exitCode: 0, waitHintMs: 0);
            }
        });

        _stoppingRegistration = _applicationLifetime.ApplicationStopping.Register(() =>
        {
            if (_serviceStatusHandle != IntPtr.Zero && _currentState != ServiceStopped)
            {
                ReportServiceStatusWindows(ServiceStopPending, exitCode: 0, waitHintMs: checked((uint)_options.ShutdownTimeoutSeconds * 1000));
            }
        });

        var dispatcherThread = new Thread(RunServiceDispatcher)
        {
            IsBackground = true,
            Name = "GuardianScmDispatcher"
        };
        dispatcherThread.Start();

        return _serviceStartedTcs.Task;
    }

    [SupportedOSPlatform("windows")]
    private void RunServiceDispatcher()
    {
        var serviceNamePtr = Marshal.StringToCoTaskMemUni(_options.ServiceName);
        try
        {
            var mainPtr = Marshal.GetFunctionPointerForDelegate(_serviceMainDelegate!);
            var table = new SERVICE_TABLE_ENTRYW[]
            {
                new() { lpServiceName = serviceNamePtr, lpServiceProc = mainPtr },
                new() { lpServiceName = IntPtr.Zero, lpServiceProc = IntPtr.Zero }
            };

            if (!StartServiceCtrlDispatcherW(table))
            {
                var error = Marshal.GetLastWin32Error();
                _logger.LogError("StartServiceCtrlDispatcherW failed with Win32 error {ErrorCode}.", error);
                _serviceStartedTcs.TrySetException(new InvalidOperationException($"Failed to connect to Windows SCM (Win32 error {error})."));
            }
        }
        finally
        {
            Marshal.FreeCoTaskMem(serviceNamePtr);
            _dispatcherStoppedEvent.Set();
        }
    }

    [SupportedOSPlatform("windows")]
    private void ServiceMain(uint argc, IntPtr argv)
    {
        _serviceStatusHandle = RegisterServiceCtrlHandlerExW(_options.ServiceName, _controlHandlerDelegate!, IntPtr.Zero);
        if (_serviceStatusHandle == IntPtr.Zero)
        {
            var error = Marshal.GetLastWin32Error();
            _logger.LogError("RegisterServiceCtrlHandlerExW failed with Win32 error {ErrorCode}.", error);
            _serviceStartedTcs.TrySetException(new InvalidOperationException($"Failed to register Windows service control handler (Win32 error {error})."));
            return;
        }

        ReportServiceStatusWindows(ServiceStartPending, exitCode: 0, waitHintMs: 10000);
        _serviceStartedTcs.TrySetResult();

        _applicationLifetime.ApplicationStopped.WaitHandle.WaitOne();
        ReportServiceStatusWindows(ServiceStopped, exitCode: 0, waitHintMs: 0);
    }

    [SupportedOSPlatform("windows")]
    private uint HandleServiceControl(uint control, uint eventType, IntPtr eventData, IntPtr context)
    {
        switch (control)
        {
            case ServiceControlStop:
            case ServiceControlShutdown:
                ReportServiceStatusWindows(ServiceStopPending, exitCode: 0, waitHintMs: checked((uint)_options.ShutdownTimeoutSeconds * 1000));
                _applicationLifetime.StopApplication();
                return 0;

            case ServiceControlInterrogate:
                ReportServiceStatusWindows(_currentState, exitCode: 0, waitHintMs: 0);
                return 0;

            default:
                return 0;
        }
    }

    [SupportedOSPlatform("windows")]
    private void ReportServiceStatusWindows(uint currentState, uint exitCode, uint waitHintMs)
    {
        if (_serviceStatusHandle == IntPtr.Zero)
        {
            return;
        }

        _currentState = currentState;
        _checkPoint = currentState is ServiceRunning or ServiceStopped ? 0u : _checkPoint + 1u;

        var status = new SERVICE_STATUS
        {
            dwServiceType = ServiceWin32OwnProcess,
            dwCurrentState = currentState,
            dwControlsAccepted = currentState == ServiceRunning ? ServiceAcceptStop | ServiceAcceptShutdown : 0u,
            dwWin32ExitCode = exitCode,
            dwServiceSpecificExitCode = 0,
            dwCheckPoint = _checkPoint,
            dwWaitHint = waitHintMs
        };

        _ = SetServiceStatus(_serviceStatusHandle, ref status);
    }

    private delegate void ServiceMainFunction(uint dwNumServicesArgs, IntPtr lpServiceArgVectors);

    private delegate uint ServiceControlHandlerEx(uint dwControl, uint dwEventType, IntPtr lpEventData, IntPtr lpContext);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartServiceCtrlDispatcherW([In] SERVICE_TABLE_ENTRYW[] lpServiceStartTable);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr RegisterServiceCtrlHandlerExW(
        string lpServiceName,
        ServiceControlHandlerEx lpHandlerProc,
        IntPtr lpContext);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetServiceStatus(IntPtr hServiceStatus, ref SERVICE_STATUS lpServiceStatus);

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_TABLE_ENTRYW
    {
        public IntPtr lpServiceName;
        public IntPtr lpServiceProc;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }
}
