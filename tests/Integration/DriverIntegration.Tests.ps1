[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CollectorPath,
    [Parameter(Mandatory=$true)][string]$NegativeClientPath,
    [string]$DriverPath,
    [switch]$AllowTestSigned,
    [switch]$ExerciseOverflow
)

$ErrorActionPreference = 'Stop'

function Assert-ExitCode([int]$Expected, [string[]]$Arguments) {
    & $CollectorPath @Arguments
    if ($LASTEXITCODE -ne $Expected) {
        throw "Collector exit code $LASTEXITCODE; expected $Expected for: $Arguments"
    }
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run optional integration tests from an elevated isolated VM.'
}

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$installedByScript = $false
try {
    if ($DriverPath) {
        & "$repositoryRoot\tools\install-driver.ps1" -DriverPath $DriverPath `
            -AllowTestSigned:$AllowTestSigned -Confirm:$false
        $installedByScript = $true
    }

    Assert-ExitCode 0 @('status')
    1..20 | ForEach-Object { Assert-ExitCode 0 @('status') }
    $negativeArguments = @()
    if ($ExerciseOverflow) { $negativeArguments += '--overflow' }
    & $NegativeClientPath @negativeArguments
    if ($LASTEXITCODE -ne 0) { throw 'Protocol negative integration tests failed.' }

    Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" `
        -ArgumentList '/c exit 0' -Wait
    Assert-ExitCode 0 @('export', '--output', "$env:TEMP\kernelscope-integration.jsonl")

    $monitor = Start-Process -FilePath $CollectorPath -ArgumentList @(
        'monitor', '--output', "$env:TEMP\kernelscope-cancel.jsonl") -PassThru
    Start-Sleep -Seconds 2
    Stop-Process -Id $monitor.Id

    Write-Host 'Integration checks passed.'
} finally {
    if ($installedByScript) {
        & "$repositoryRoot\tools\uninstall-driver.ps1" -Confirm:$false
    }
}
