#Requires -Version 5.1
<#
.SYNOPSIS
命令行串行执行一个或多个 EDR 遥测场景。
.DESCRIPTION
复用场景目录中 53 个独立脚本，按顺序逐个执行并写入统一 JSONL 事件日志。
.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\Start-TelemetrySuite.ps1 -ScenarioIds win.file.create,win.registry.create
powershell -ExecutionPolicy Bypass -File .\Start-TelemetrySuite.ps1 -Categories "Process Activity" -IntervalSeconds 5
#>
[CmdletBinding()]
param(
    [string[]]$ScenarioIds,
    [string[]]$Categories,
    [switch]$All,
    [string]$RunId,
    [int]$IntervalSeconds = -1,
    [ValidateSet('LV0', 'LV1', 'LV2', 'LV3')]
    [string]$ThreatLevel,
    [string]$OutputLog,
    [switch]$SkipCleanup,
    [switch]$StopOnFailure,
    [string]$ServiceName,
    [int]$UsbWaitSeconds = 0,
    [switch]$ConfirmManual
)
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $projectRoot 'core\EdrTelemetry.Common.ps1')
. (Join-Path $projectRoot 'core\EdrTelemetry.SerialRunner.ps1')
$normalizedScenarioIds = @($ScenarioIds | Where-Object { $_ } | ForEach-Object { $_.Split(',') } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$normalizedCategories = @($Categories | Where-Object { $_ } | ForEach-Object { $_.Split(',') } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$suiteParameters = @{
    ScenarioIds = $normalizedScenarioIds
    Categories = $normalizedCategories
    All = $All
    RunId = $RunId
    IntervalSeconds = $IntervalSeconds
    OutputLog = $OutputLog
    SkipCleanup = $SkipCleanup
    StopOnFailure = $StopOnFailure
    ServiceName = $ServiceName
    UsbWaitSeconds = $UsbWaitSeconds
    ConfirmManual = $ConfirmManual
}
if ($ThreatLevel) { $suiteParameters.ThreatLevel = $ThreatLevel }
Start-EdrTelemetrySuite @suiteParameters
