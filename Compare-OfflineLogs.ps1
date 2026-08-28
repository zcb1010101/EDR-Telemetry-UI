#Requires -Version 5.1
<#
.SYNOPSIS
执行本地事件日志与厂商日志的离线比对。
.DESCRIPTION
使用厂商映射与基线规则执行离线比较：字段规范化、确定性关联键匹配、断言评估、汇总判定。
不包含项目 1 的锚点评分；-StrongCorrelationTimeMs 与 -CandidateTimeLimitMs 仅为兼容旧调用保留。
.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\Compare-OfflineLogs.ps1 -LocalLog runs\20260816\abc\events.jsonl -Cloud vendor.json -VendorId tencent -OutputPath reports\result.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$LocalLog,
    [Parameter(Mandatory = $true)][string[]]$Cloud,
    [string]$VendorId,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [string]$BaselineDirectory,
    [string]$CloudManifest,
    [int]$StrongCorrelationTimeMs = 0,
    [int]$CandidateTimeLimitMs = 0
)
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $projectRoot 'core\EdrTelemetry.Common.ps1')
. (Join-Path $projectRoot 'core\EdrTelemetry.Comparator.ps1')
$result = Compare-EdrOfflineLogs -LocalLogPath $LocalLog -CloudPaths $Cloud -VendorId $VendorId `
    -OutputPath $OutputPath -BaselineDirectory $BaselineDirectory -CloudManifestPath $CloudManifest `
    -StrongCorrelationTimeMs $StrongCorrelationTimeMs -CandidateTimeLimitMs $CandidateTimeLimitMs
Write-Host "比对完成：PASS=$($result.summary.pass) PARTIAL=$($result.summary.partial) FAIL=$($result.summary.fail) INCONCLUSIVE=$($result.summary.inconclusive) NOT_COMPARED=$($result.summary.not_compared)"
Write-Host "结果：$OutputPath"
