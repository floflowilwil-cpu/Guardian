[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9_.-]{1,64}$')]
    [string]$ServiceName = 'GuardianService',

    [ValidateNotNullOrEmpty()]
    [string]$PipeName = 'Guardian.Service.Ipc.v1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$pipePath = "\\.\pipe\$PipeName"
$pipeListening = $false

try {
    $matchingPipes = [System.IO.Directory]::GetFiles('\\.\pipe\') |
        Where-Object { [string]::Equals($_, $pipePath, [System.StringComparison]::OrdinalIgnoreCase) }
    $pipeListening = $null -ne $matchingPipes
}
catch {
    $pipeListening = $false
}

$failurePolicy = $null
if ($null -ne $service) {
    $qfailure = & sc.exe qfailure $ServiceName 2>&1
    if ($LASTEXITCODE -eq 0) {
        $failurePolicy = ($qfailure | Out-String).Trim()
    }
}

[pscustomobject]@{
    ServiceName      = $ServiceName
    Installed        = ($null -ne $service)
    ServiceStatus    = if ($null -ne $service) { $service.Status.ToString() } else { 'NotInstalled' }
    StartType        = if ($null -ne $service) { $service.StartType.ToString() } else { 'Unknown' }
    ExpectedIpcPipe  = $pipePath
    IpcPipeListening = $pipeListening
    FailurePolicy    = $failurePolicy
}
