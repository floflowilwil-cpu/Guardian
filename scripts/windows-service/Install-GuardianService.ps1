#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BinaryPath,

    [ValidatePattern('^[A-Za-z0-9_.-]{1,64}$')]
    [string]$ServiceName = 'GuardianService',

    [ValidateNotNullOrEmpty()]
    [string]$DisplayName = 'Guardian Endpoint Security Service',

    [ValidateNotNullOrEmpty()]
    [string]$Description = 'Service resident Guardian de surveillance systeme, analyse et protection endpoint.',

    [ValidateNotNullOrEmpty()]
    [string]$DataRoot = (Join-Path $env:ProgramData 'Guardian'),

    [switch]$StartService
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsUnsafeSystemRoot {
    param([string]$CandidatePath)

    $full = [System.IO.Path]::GetFullPath($CandidatePath).TrimEnd('\')
    $root = [System.IO.Path]::GetPathRoot($full).TrimEnd('\')
    if ([string]::Equals($full, $root, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    $forbiddenExact = @(
        $env:SystemRoot,
        (Join-Path $env:SystemRoot 'System32'),
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
        [System.IO.Path]::GetFullPath($_).TrimEnd('\')
    }

    foreach ($forbidden in $forbiddenExact) {
        if ([string]::Equals($full, $forbidden, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Invoke-ScChecked {
    param([string[]]$Arguments)

    $output = & sc.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe ($($Arguments -join ' ')) failed with exit code $LASTEXITCODE : $($output -join ' ')"
    }
}

$resolvedBinary = [System.IO.Path]::GetFullPath($BinaryPath)
if (-not (Test-Path -LiteralPath $resolvedBinary -PathType Leaf)) {
    throw "Service executable not found at '$resolvedBinary'."
}

if (-not $resolvedBinary.EndsWith('.exe', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Service binary must be a .exe executable: '$resolvedBinary'."
}

$resolvedDataRoot = [System.IO.Path]::GetFullPath($DataRoot).TrimEnd('\')
if (Test-IsUnsafeSystemRoot -CandidatePath $resolvedDataRoot) {
    throw "Refusing to apply restrictive ACLs to system directory '$resolvedDataRoot'."
}

$subDirectories = @('config', 'data', 'quarantine', 'signatures', 'models', 'logs', 'backup')

if ($PSCmdlet.ShouldProcess($resolvedDataRoot, 'Create Guardian data directories and apply restrictive ACLs')) {
    if (-not (Test-Path -LiteralPath $resolvedDataRoot)) {
        New-Item -ItemType Directory -Path $resolvedDataRoot -Force | Out-Null
    }

    foreach ($sub in $subDirectories) {
        $subPath = Join-Path $resolvedDataRoot $sub
        if (-not (Test-Path -LiteralPath $subPath)) {
            New-Item -ItemType Directory -Path $subPath -Force | Out-Null
        }
    }

    $dirSecurity = New-Object System.Security.AccessControl.DirectorySecurity
    $dirSecurity.SetAccessRuleProtection($true, $false)

    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None

    $systemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $adminsSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)

    $dirSecurity.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $systemSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritanceFlags,
        $propagationFlags,
        [System.Security.AccessControl.AccessControlType]::Allow)))

    $dirSecurity.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $adminsSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritanceFlags,
        $propagationFlags,
        [System.Security.AccessControl.AccessControlType]::Allow)))

    Set-Acl -LiteralPath $resolvedDataRoot -AclObject $dirSecurity
}

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$quotedBinPath = "`"$resolvedBinary`""

if ($null -eq $existingService) {
    if ($PSCmdlet.ShouldProcess($ServiceName, "Create Windows Service '$DisplayName'")) {
        Invoke-ScChecked -Arguments @('create', $ServiceName, 'binPath=', $quotedBinPath, 'DisplayName=', $DisplayName, 'start=', 'delayed-auto')
    }
}
else {
    if ($PSCmdlet.ShouldProcess($ServiceName, "Update existing Windows Service '$DisplayName'")) {
        Invoke-ScChecked -Arguments @('config', $ServiceName, 'binPath=', $quotedBinPath, 'DisplayName=', $DisplayName, 'start=', 'delayed-auto')
    }
}

if ($PSCmdlet.ShouldProcess($ServiceName, 'Configure service description and bounded crash recovery policy')) {
    Invoke-ScChecked -Arguments @('description', $ServiceName, $Description)
    Invoke-ScChecked -Arguments @('failure', $ServiceName, 'reset=', '600', 'actions=', 'restart/5000/restart/15000/restart/30000')
    Invoke-ScChecked -Arguments @('failureflag', $ServiceName, '1')
}

if ($StartService) {
    if ($PSCmdlet.ShouldProcess($ServiceName, 'Start Guardian Windows Service')) {
        Start-Service -Name $ServiceName
    }
}

Write-Output "Guardian Windows Service '$ServiceName' configured cleanly for binary '$resolvedBinary'."
