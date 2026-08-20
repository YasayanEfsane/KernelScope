[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param()

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}
if ($PSCmdlet.ShouldProcess('KernelScopeDriver', 'Stop and delete kernel service')) {
    & sc.exe stop KernelScopeDriver
    if ($LASTEXITCODE -notin 0,1060,1062) { throw "sc.exe stop failed: $LASTEXITCODE" }
    & sc.exe delete KernelScopeDriver
    if ($LASTEXITCODE -notin 0,1060) { throw "sc.exe delete failed: $LASTEXITCODE" }
}

