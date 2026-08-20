[CmdletBinding()]
param(
    [ValidateSet('Debug','Release')][string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
& msbuild "$root\tests\KernelScopeTests.vcxproj" /m /p:Configuration=$Configuration /p:Platform=x64
if ($LASTEXITCODE -ne 0) { throw 'The offline test build failed.' }
& "$root\tests\x64\$Configuration\KernelScopeTests.exe"
if ($LASTEXITCODE -ne 0) { throw 'One or more offline tests failed.' }

