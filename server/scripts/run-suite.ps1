#Requires -Version 5.1
<#
.SYNOPSIS
从 Web API 读取运行请求并调用原有 EDR 串行执行器。
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
. (Join-Path $projectRoot 'core\EdrTelemetry.SerialRunner.ps1')

$request = Read-EdrJson -Path $RequestPath
$params = @{
    RunId = [string]$request.runId
    OutputLog = [string]$request.outputLog
    IntervalSeconds = [int]$request.intervalSeconds
}

if ($request.mode -eq 'all') {
    $params.All = $true
}
elseif ($request.mode -eq 'category') {
    $params.Categories = @($request.categories | ForEach-Object { [string]$_ })
}
else {
    $params.ScenarioIds = @($request.scenarioIds | ForEach-Object { [string]$_ })
}

if ($request.skipCleanup) {
    $params.SkipCleanup = $true
}
if ($request.stopOnFailure) {
    $params.StopOnFailure = $true
}
if ($request.threatLevel) {
    $params.ThreatLevel = [string]$request.threatLevel
}
if ($request.serviceName) {
    $params.ServiceName = [string]$request.serviceName
}
if ($request.usbWaitSeconds -gt 0) {
    $params.UsbWaitSeconds = [int]$request.usbWaitSeconds
}
if ($request.confirmManual) {
    $params.ConfirmManual = $true
}

Start-EdrTelemetrySuite @params | Out-Null
exit 0