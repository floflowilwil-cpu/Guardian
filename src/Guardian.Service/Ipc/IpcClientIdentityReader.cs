using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Principal;
using Guardian.Contracts.Ipc;

namespace Guardian.Service.Ipc;

/// <summary>
/// Extrait côté serveur l'identité Windows vérifiée et le PID d'un client connecté à un Named Pipe.
/// </summary>
public static class IpcClientIdentityReader
{
    /// <summary>
    /// Lit le contexte d'identité authentifié du client connecté au flux Named Pipe fourni.
    /// </summary>
    /// <param name="pipeStream">Flux serveur Named Pipe actuellement connecté.</param>
    /// <returns>Contexte client vérifié sans aucune donnée secrète.</returns>
    public static IpcClientContext ReadClientContext(NamedPipeServerStream pipeStream)
    {
        ArgumentNullException.ThrowIfNull(pipeStream);

        if (!OperatingSystem.IsWindows())
        {
            return new IpcClientContext(
                IdentityName: global::System.Environment.UserName,
                SecurityIdentifier: null,
                ClientProcessId: null,
                IsAdministrator: false);
        }

        return ReadClientContextWindows(pipeStream);
    }

    [SupportedOSPlatform("windows")]
    private static IpcClientContext ReadClientContextWindows(NamedPipeServerStream pipeStream)
    {
        int? clientPid = null;
        try
        {
            if (GetNamedPipeClientProcessId(pipeStream.SafePipeHandle, out var rawPid) && rawPid > 0)
            {
                clientPid = unchecked((int)rawPid);
            }
        }
        catch
        {
            // Certaines configurations peuvent restreindre la lecture du PID client sans empêcher l'impersonation.
        }

        var identityName = string.Empty;
        string? sid = null;
        var isAdministrator = false;

        try
        {
            pipeStream.RunAsClient(() =>
            {
                using var identity = WindowsIdentity.GetCurrent();
                identityName = identity.Name;
                sid = identity.User?.Value;

                var principal = new WindowsPrincipal(identity);
                isAdministrator = principal.IsInRole(WindowsBuiltInRole.Administrator);
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            identityName = pipeStream.GetImpersonationUserName();
        }

        if (string.IsNullOrWhiteSpace(identityName))
        {
            identityName = "Unknown";
        }

        return new IpcClientContext(
            IdentityName: identityName,
            SecurityIdentifier: sid,
            ClientProcessId: clientPid,
            IsAdministrator: isAdministrator);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafeHandle pipe, out uint clientProcessId);
}
