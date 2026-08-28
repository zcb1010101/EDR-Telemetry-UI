#Requires -Version 5.1
<#
.SYNOPSIS
读取离线比对请求文件并调用原有 Comparator。
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RequestPath
)

$ErrorActionPreference = 'Stop'
try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $OutputEncoding = New-Object System.Text.UTF8Encoding($false)
}
catch { }
$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $projectRoot 'core\EdrTelemetry.Common.ps1')
. (Join-Path $projectRoot 'core\EdrTelemetry.Comparator.ps1')

$request = Read-EdrJson -Path $RequestPath
$params = @{
    LocalLogPath = [string]$request.localLogPath
    CloudPaths = @($request.cloudPaths | ForEach-Object { [string]$_ })
    VendorId = [string]$request.vendorId
    OutputPath = [string]$request.outputPath
}

if ($request.baselineDirectory) {
    $params.BaselineDirectory = [string]$request.baselineDirectory
}
if ($request.cloudManifest) {
    $params.CloudManifestPath = [string]$request.cloudManifest
}
if ($request.strongCorrelationTimeMs -gt 0) {
    $params.StrongCorrelationTimeMs = [int]$request.strongCorrelationTimeMs
}
if ($request.candidateTimeLimitMs -gt 0) {
    $params.CandidateTimeLimitMs = [int]$request.candidateTimeLimitMs
}

Compare-EdrOfflineLogs @params | Out-Null
exit 0