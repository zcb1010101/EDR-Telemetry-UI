#Requires -Version 5.1
<#
.SYNOPSIS
Imphash 遥测采集与真伪校验脚本
.DESCRIPTION
类别：Hash Algorithms
场景 ID：win.hash.imphash
默认威胁等级：LV0
需要管理员：false
行为类型：hash.imphash
.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\Invoke-Imphash.ps1
#>
[CmdletBinding()]
param(
    [string]$RunId,
    [string]$Nonce,
    [string]$OutputLog,
    [ValidateSet('LV0', 'LV1', 'LV2', 'LV3')]
    [string]$ThreatLevel,
    [int]$IntervalSeconds = -1,
    [switch]$SkipCleanup,
    [string]$ServiceName,
    [int]$UsbWaitSeconds = 0,
    [switch]$ConfirmManual
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $projectRoot 'core\EdrTelemetry.Common.ps1')
. (Join-Path $projectRoot 'core\EdrTelemetry.Behaviors.ps1')

$scenario = Get-EdrScenario -ScenarioId 'win.hash.imphash'
if (-not $RunId) { $RunId = New-EdrRunId }
if (-not $Nonce) { $Nonce = New-EdrNonce }
if (-not $OutputLog) { $OutputLog = Get-EdrDefaultOutputLog -RunId $RunId }
$config = Get-EdrConfig
if ($IntervalSeconds -lt 0) { $IntervalSeconds = [int]$config.default_interval_seconds }

$event = Invoke-EdrTelemetryScenario -Scenario $scenario -RunId $RunId -Nonce $Nonce `
    -ThreatLevel $ThreatLevel -SkipCleanup:$SkipCleanup -ServiceName $ServiceName `
    -UsbWaitSeconds $UsbWaitSeconds -ConfirmManual:$ConfirmManual
Write-EdrEventLog -Event $event -OutputLog $OutputLog

$color = switch ($event.status) {
    'SUCCESS' { 'Green' }
    'SKIPPED' { 'Yellow' }
    default { 'Red' }
}
Write-EdrConsole -Message ("[$($event.status)] $($event.scenario_id) | $($event.operation) | " + (Get-EdrThreatLevelLabel $event.threat_level) + " | " + $event.detail) -Color $color
Write-EdrConsole -Message ("日志: " + $OutputLog) -Color 'DarkGray'

if ($IntervalSeconds -gt 0) { Start-Sleep -Seconds $IntervalSeconds }
$event | Select-Object run_id, nonce, scenario_id, operation, status, success, verification, threat_level, triggered_at_utc, observed_at_utc, detail