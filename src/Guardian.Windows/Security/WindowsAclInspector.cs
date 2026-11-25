using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Guardian.Contracts.Common;

namespace Guardian.Windows.Security;

/// <summary>
/// Implémentation Windows de l'inspection et du durcissement des ACL NTFS et Named Pipes.
/// </summary>
public sealed class WindowsAclInspector : IWindowsAclInspector
{
    /// <inheritdoc />
    public AclAuditResult AuditPathAcl(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (!OperatingSystem.IsWindows())
        {
            return new AclAuditResult(
                path,
                Exists: false,
                IsRestrictive: false,
                Availability: FeatureAvailabilityStatus.Unavailable,
                Findings: ["ACL inspection requires Windows."]);
        }

        return AuditPathAclWindows(path);
    }

    /// <inheritdoc />
    public void ApplyRestrictiveDirectoryAcl(string directoryPath, bool includeCurrentUser = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryPath);

        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Applying NTFS directory ACLs is only supported on Windows.");
        }

        ApplyRestrictiveDirectoryAclWindows(directoryPath, includeCurrentUser);
    }

    /// <inheritdoc />
    [SupportedOSPlatform("windows")]
    public PipeSecurity CreateRestrictedPipeSecurity(bool allowCurrentUser = true, bool allowAuthenticatedUsers = false)
    {
        var pipeSecurity = new PipeSecurity();

        var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var networkSid = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);

        pipeSecurity.AddAccessRule(new PipeAccessRule(systemSid, PipeAccessRights.FullControl, AccessControlType.Allow));
        pipeSecurity.AddAccessRule(new PipeAccessRule(adminsSid, PipeAccessRights.FullControl, AccessControlType.Allow));

        if (allowCurrentUser)
        {
            using var currentIdentity = WindowsIdentity.GetCurrent();
            if (currentIdentity.User is not null)
            {
                pipeSecurity.AddAccessRule(new PipeAccessRule(currentIdentity.User, PipeAccessRights.ReadWrite, AccessControlType.Allow));
            }
        }

        if (allowAuthenticatedUsers)
        {
            var authenticatedSid = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
            pipeSecurity.AddAccessRule(new PipeAccessRule(authenticatedSid, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        }

        pipeSecurity.AddAccessRule(new PipeAccessRule(networkSid, PipeAccessRights.FullControl, AccessControlType.Deny));

        return pipeSecurity;
    }

    [SupportedOSPlatform("windows")]
    private static AclAuditResult AuditPathAclWindows(string path)
    {
        const FileSystemRights dangerousWriteMask =
            FileSystemRights.Write |
            FileSystemRights.Modify |
            FileSystemRights.FullControl |
            FileSystemRights.CreateFiles |
            FileSystemRights.WriteData |
            FileSystemRights.AppendData |
            FileSystemRights.Delete |
            FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.ChangePermissions |
            FileSystemRights.TakeOwnership;

        var isDirectory = Directory.Exists(path);
        var isFile = !isDirectory && File.Exists(path);

        if (!isDirectory && !isFile)
        {
            return new AclAuditResult(
                path,
                Exists: false,
                IsRestrictive: false,
                Availability: FeatureAvailabilityStatus.Available,
                Findings: ["Target path does not exist."]);
        }

        try
        {
            FileSystemSecurity security = isDirectory
                ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access)
                : new FileInfo(path).GetAccessControl(AccessControlSections.Access);

            var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
            var findings = new List<string>();

            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.AccessControlType != AccessControlType.Allow)
                {
                    continue;
                }

                if (rule.IdentityReference is not SecurityIdentifier sid)
                {
                    continue;
                }

                var broadPrincipalName = GetBroadPrincipalLabel(sid);
                if (broadPrincipalName is null)
                {
                    continue;
                }

                var matchedRights = rule.FileSystemRights & dangerousWriteMask;
                if (matchedRights != 0)
                {
                    findings.Add($"{broadPrincipalName} has permissive rights ({matchedRights}) on '{path}'.");
                }
            }

            return new AclAuditResult(
                path,
                Exists: true,
                IsRestrictive: findings.Count == 0,
                Availability: FeatureAvailabilityStatus.Available,
                Findings: findings);
        }
        catch (UnauthorizedAccessException ex)
        {
            return new AclAuditResult(
                path,
                Exists: true,
                IsRestrictive: false,
                Availability: FeatureAvailabilityStatus.RequiresElevation,
                Findings: [ex.Message]);
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ApplyRestrictiveDirectoryAclWindows(string directoryPath, bool includeCurrentUser)
    {
        var fullPath = Path.GetFullPath(directoryPath);
        ValidateTargetDirectoryNotCritical(fullPath);

        Directory.CreateDirectory(fullPath);
        var directoryInfo = new DirectoryInfo(fullPath);
        var security = directoryInfo.GetAccessControl(AccessControlSections.Access);

        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        var existingRules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule existingRule in existingRules)
        {
            security.RemoveAccessRuleSpecific(existingRule);
        }

        var inheritanceFlags = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        security.AddAccessRule(new FileSystemAccessRule(
            systemSid,
            FileSystemRights.FullControl,
            inheritanceFlags,
            PropagationFlags.None,
            AccessControlType.Allow));

        security.AddAccessRule(new FileSystemAccessRule(
            adminsSid,
            FileSystemRights.FullControl,
            inheritanceFlags,
            PropagationFlags.None,
            AccessControlType.Allow));

        if (includeCurrentUser)
        {
            using var currentIdentity = WindowsIdentity.GetCurrent();
            if (currentIdentity.User is not null)
            {
                security.AddAccessRule(new FileSystemAccessRule(
                    currentIdentity.User,
                    FileSystemRights.FullControl,
                    inheritanceFlags,
                    PropagationFlags.None,
                    AccessControlType.Allow));
            }
        }

        directoryInfo.SetAccessControl(security);
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateTargetDirectoryNotCritical(string fullPath)
    {
        var normalized = NormalizeDirectoryPath(fullPath);
        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrWhiteSpace(normalized) ||
            (!string.IsNullOrWhiteSpace(root) && string.Equals(normalized, NormalizeDirectoryPath(root), StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"Refusing to modify ACLs on root or empty path '{fullPath}'.");
        }

        var windowsFolder = NormalizeDirectoryPath(global::System.Environment.GetFolderPath(global::System.Environment.SpecialFolder.Windows));
        if (!string.IsNullOrEmpty(windowsFolder) &&
            (string.Equals(normalized, windowsFolder, StringComparison.OrdinalIgnoreCase) ||
             normalized.StartsWith(windowsFolder + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"Refusing to modify ACLs on protected Windows system directory '{fullPath}'.");
        }

        var programFilesFolder = NormalizeDirectoryPath(global::System.Environment.GetFolderPath(global::System.Environment.SpecialFolder.ProgramFiles));
        if (!string.IsNullOrEmpty(programFilesFolder) &&
            string.Equals(normalized, programFilesFolder, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"Refusing to modify ACLs on root Program Files directory '{fullPath}'.");
        }
    }

    private static string NormalizeDirectoryPath(string path)
    {
        return path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    [SupportedOSPlatform("windows")]
    private static string? GetBroadPrincipalLabel(SecurityIdentifier sid)
    {
        if (sid.IsWellKnown(WellKnownSidType.WorldSid))
        {
            return "Everyone";
        }

        if (sid.IsWellKnown(WellKnownSidType.BuiltinUsersSid))
        {
            return @"BUILTIN\Users";
        }

        if (sid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid))
        {
            return "Authenticated Users";
        }

        return null;
    }
}
