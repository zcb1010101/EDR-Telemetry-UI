#Requires -Version 5.1
<#
.SYNOPSIS
初始化、查看、导入与校验安全基线。
.DESCRIPTION
-Show 显示指定场景基线；-ImportPath 导入自定义基线；-Validate 校验场景覆盖；无参数时重新生成并列出基线。
.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\Initialize-SecurityBaseline.ps1
powershell -ExecutionPolicy Bypass -File .\Initialize-SecurityBaseline.ps1 -Show win.process.create
powershell -ExecutionPolicy Bypass -File .\Initialize-SecurityBaseline.ps1 -ImportPath custom.json
#>
[CmdletBinding()]
param(
    [string]$Show,
    [string]$ImportPath,
    [switch]$Validate,
    [switch]$List
)
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $projectRoot 'core\EdrTelemetry.Common.ps1')
. (Join-Path $projectRoot 'core\EdrTelemetry.Baseline.ps1')

if ($Show) {
    $baseline = Get-EdrBaselineForScenario -ScenarioId $Show
    if (-not $baseline) {
        Write-Host "未找到场景 $Show 的基线。" -ForegroundColor Red
        exit 1
    }
    Export-EdrJson -Path (Join-Path (Get-Location).Path "$Show.baseline.json") -Value $baseline
    Write-Host "已导出基线：$(Join-Path (Get-Location).Path "$Show.baseline.json")" -ForegroundColor Green
    exit 0
}

if ($ImportPath) {
    if (-not (Test-Path -LiteralPath $ImportPath)) {
        Write-Host "找不到自定义基线：$ImportPath" -ForegroundColor Red
        exit 1
    }
    $custom = Read-EdrJson -Path $ImportPath
    $customDir = Join-Path $projectRoot 'baselines\custom'
    New-Item -ItemType Directory -Path $customDir -Force | Out-Null
    $name = [System.IO.Path]::GetFileNameWithoutExtension($ImportPath)
    $target = Join-Path $customDir "$name.baseline.json"
    Copy-Item -LiteralPath $ImportPath -Destination $target -Force
    Import-EdrBaselines -BaselineDirectory (Join-Path $projectRoot 'baselines') | Out-Null
    Write-Host "已导入自定义基线：$target" -ForegroundColor Green
    exit 0
}

if ($Validate -or $List) {
    $baselines = Import-EdrBaselines -BaselineDirectory (Join-Path $projectRoot 'baselines')
    $catalog = Get-EdrScenarioCatalog
    $missing = @()
    foreach ($scenario in $catalog) {
        if (-not (Get-EdrBaselineForScenario -ScenarioId $scenario.ScenarioId)) { $missing += $scenario.ScenarioId }
    }
    Write-Host "基线总数：$($baselines.Count)；场景总数：$($catalog.Count)；缺少基线：$($missing.Count)"
    if ($missing.Count -gt 0) { Write-Host "缺少：$($missing -join '、')" -ForegroundColor Red }
    exit $(if ($missing.Count -eq 0) { 0 } else { 1 })
}

& (Join-Path $projectRoot 'tools\Generate-ScenarioScripts.ps1')
$baselines = Import-EdrBaselines -BaselineDirectory (Join-Path $projectRoot 'baselines')
Write-Host ''
Write-Host '已初始化安全基线：' -ForegroundColor Cyan
foreach ($baseline in $baselines) {
    Write-Host ("  " + $baseline.capability.id.PadRight(34) + " v" + $baseline.version + "  云端期望 " + @($baseline.cloud_expectations[0].assertions).Count + " 项断言") -ForegroundColor DarkGray
}
