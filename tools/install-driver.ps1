[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)][string]$DriverPath,
    [switch]$AllowTestSigned
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session in an isolated VM.'
}

$resolved = (Resolve-Path -LiteralPath $DriverPath).Path
if ([IO.Path]::GetExtension($resolved) -ne '.sys') { throw 'DriverPath must name a .sys file.' }
$signature = Get-AuthenticodeSignature -LiteralPath $resolved
if ($signature.Status -ne 'Valid') {
    throw "Driver signature status is $($signature.Status). Trust the test certificate inside the isolated VM; this script never permits an invalid or absent signature."
}
if ($AllowTestSigned) {
    Write-Warning 'Test-signed driver installation is for a disposable isolated VM only.'
}

if ($PSCmdlet.ShouldProcess($resolved, 'Create and start the KernelScopeDriver kernel service')) {
    & sc.exe create KernelScopeDriver type= kernel start= demand error= normal binPath= $resolved
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed: $LASTEXITCODE. Remove any existing service and verify its configuration before retrying." }
    & sc.exe start KernelScopeDriver
    if ($LASTEXITCODE -ne 0) { throw "sc.exe start failed: $LASTEXITCODE" }
}
