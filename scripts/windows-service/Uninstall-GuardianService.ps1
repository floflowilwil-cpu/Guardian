#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidatePattern('^[A-Za-z0-9_.-]{1,64}$')]
    [string]$ServiceName = 'GuardianService',

    [ValidateNotNullOrEmpty()]
    [string]$DataRoot = (Join-Path $env:ProgramData 'Guardian'),

    [ValidateRange(5, 120)]
    [int]$StopTimeoutSeconds = 20,

    [switch]$PurgeData
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

$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $existingService) {
    if ($existingService.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        if ($PSCmdlet.ShouldProcess($ServiceName, 'Stop Guardian Windows Service cleanly')) {
            Stop-Service -Name $ServiceName -Force
            $existingService.WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Stopped,
                [TimeSpan]::FromSeconds($StopTimeoutSeconds))
        }
    }

    if ($PSCmdlet.ShouldProcess($ServiceName, 'Unregister Guardian Windows Service from SCM')) {
        $deleteOut = & sc.exe delete $ServiceName 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "sc.exe delete '$ServiceName' failed with exit code $LASTEXITCODE : $($deleteOut -join ' ')"
        }
    }

    Write-Output "Service '$ServiceName' stopped and unregistered cleanly."
}
else {
    Write-Output "Service '$ServiceName' is not currently registered."
}

if ($PurgeData) {
    $resolvedDataRoot = [System.IO.Path]::GetFullPath($DataRoot).TrimEnd('\')
    if (Test-IsUnsafeSystemRoot -CandidatePath $resolvedDataRoot) {
        throw "Refusing to delete unsafe system directory '$resolvedDataRoot'."
    }

    if (Test-Path -LiteralPath $resolvedDataRoot) {
        if ($PSCmdlet.ShouldProcess($resolvedDataRoot, 'Delete Guardian data directory permanently')) {
            Remove-Item -LiteralPath $resolvedDataRoot -Recurse -Force
            Write-Output "Removed Guardian data directory '$resolvedDataRoot'."
        }
    }
}
