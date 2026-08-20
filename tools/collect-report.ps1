[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CollectorPath,
    [string]$Output = '.\kernelscope-events.jsonl',
    [ValidateRange(1,4096)][int]$MaximumSizeMiB = 64
)

$ErrorActionPreference = 'Stop'
& $CollectorPath monitor --output $Output --max-size-mb $MaximumSizeMiB
exit $LASTEXITCODE

