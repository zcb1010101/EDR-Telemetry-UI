#Requires -Version 5.1
<#
.SYNOPSIS
EDR 遥测离线验证平台主入口（纯 PowerShell 终端交互）。
.DESCRIPTION
提供能力目录浏览、单场景执行、分类执行、全部串行执行、厂商日志导入、离线比对与基线管理。
.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\Run-EDRTelemetry.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $projectRoot 'core\EdrTelemetry.Common.ps1')
. (Join-Path $projectRoot 'core\EdrTelemetry.SerialRunner.ps1')
. (Join-Path $projectRoot 'core\EdrTelemetry.Normalizer.ps1')
. (Join-Path $projectRoot 'core\EdrTelemetry.Baseline.ps1')
. (Join-Path $projectRoot 'core\EdrTelemetry.Comparator.ps1')

function Show-EdrBanner {
    Write-Host ''
    Write-Host '  =====================================================' -ForegroundColor Cyan
    Write-Host '    EDR 遥测离线验证平台' -ForegroundColor White
    Write-Host '    纯 PowerShell 终端 · 串行采集 · 离线比对' -ForegroundColor DarkCyan
    Write-Host '  =====================================================' -ForegroundColor Cyan
    Write-Host ''
}

function Show-EdrCategories {
    $catalog = Get-EdrScenarioCatalog
    $groups = $catalog | Group-Object Category
    $index = 0
    foreach ($group in $groups) {
        $index++
        Write-Host ("  " + $index.ToString().PadLeft(2) + ". " + $group.Name.PadRight(30) + " " + $group.Count.ToString().PadLeft(2) + " 项") -ForegroundColor White
    }
    Write-Host ''
    Write-Host "  全部场景共 $($catalog.Count) 项" -ForegroundColor DarkCyan
}

function Show-EdrCatalog {
    $catalog = Get-EdrScenarioCatalog
    Write-Host ''
    Write-Host '  -------------------- 能力目录 --------------------' -ForegroundColor Cyan
    $currentCategory = ''
    foreach ($scenario in $catalog) {
        if ($scenario.Category -ne $currentCategory) {
            $currentCategory = $scenario.Category
            Write-Host ''
            Write-Host ("  [" + $currentCategory + "]") -ForegroundColor Magenta
        }
        $levelColor = switch ($scenario.ThreatLevel) {
            'LV0' { 'Green' }
            'LV1' { 'Yellow' }
            'LV2' { 'Magenta' }
            default { 'Red' }
        }
        $admin = if ($scenario.RequiresAdmin -eq 'true') { ' [管理员]' } else { '' }
        Write-Host ("    " + $scenario.ScenarioId.PadRight(34) + " " + $scenario.ThreatLevel.PadRight(8) + " " + $scenario.ScenarioName + $admin) -ForegroundColor $levelColor
    }
    Write-Host ''
}

function Invoke-EdrSingleScenario {
    Write-Host '  请输入场景 ID（例如 win.file.create）：' -ForegroundColor White -NoNewline
    $scenarioId = Read-Host
    if (-not $scenarioId) { return }
    try {
        $scenario = Get-EdrScenario -ScenarioId $scenarioId
    }
    catch {
        Write-Host "  未知场景：$scenarioId" -ForegroundColor Red
        return
    }
    $scriptPath = Get-EdrScenarioScriptPath -Scenario $scenario
    if (-not (Test-Path -LiteralPath $scriptPath)) {
        Write-Host "  缺少场景脚本：$scriptPath" -ForegroundColor Red
        return
    }
    Write-Host '  输出日志路径（留空使用默认 runs 目录）：' -ForegroundColor White -NoNewline
    $outputLog = Read-Host
    & $scriptPath -OutputLog $outputLog
}

function Invoke-EdrCategoryRun {
    $catalog = Get-EdrScenarioCatalog
    $categories = @($catalog | Select-Object -ExpandProperty Category -Unique)
    Show-EdrCategories
    Write-Host '  请输入分类编号或分类名称：' -ForegroundColor White -NoNewline
    $input = Read-Host
    if (-not $input) { return }
    $category = $null
    $number = 0
    if ([int]::TryParse($input, [ref]$number) -and $number -ge 1 -and $number -le $categories.Count) {
        $category = $categories[$number - 1]
    }
    else {
        $category = $categories | Where-Object { $_ -eq $input } | Select-Object -First 1
    }
    if (-not $category) {
        Write-Host "  未知分类：$input" -ForegroundColor Red
        return
    }
    Start-EdrTelemetrySuite -Categories @($category)
}

function Invoke-EdrAllRun {
    Write-Host '  确认执行全部 53 个场景？高风险场景仅建议在隔离测试机执行。' -ForegroundColor Yellow
    Write-Host '  输入 yes 继续：' -ForegroundColor White -NoNewline
    $confirm = Read-Host
    if ($confirm -ne 'yes') {
        Write-Host '  已取消。' -ForegroundColor DarkGray
        return
    }
    Start-EdrTelemetrySuite -All
}

function Invoke-EdrBatchRun {
    $catalog = Get-EdrScenarioCatalog
    Write-Host '  场景编号列表（输入编号或场景 ID 均可）：' -ForegroundColor White
    for ($i = 0; $i -lt $catalog.Count; $i++) {
        Write-Host ("    " + ($i + 1).ToString().PadLeft(2) + ". " + $catalog[$i].ScenarioId) -ForegroundColor DarkGray
    }
    Write-Host '  请输入逗号分隔的场景 ID 或编号列表：' -ForegroundColor White -NoNewline
    $input = Read-Host
    if (-not $input) { return }
    $ids = @($input.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    Start-EdrTelemetrySuite -ScenarioIds $ids
}

function Invoke-EdrVendorConversion {
    Write-Host ("  可用厂商: " + (Get-EdrVendorIds -join '、')) -ForegroundColor DarkCyan
    Write-Host '  厂商 ID（默认 tencent）：' -ForegroundColor White -NoNewline
    $vendorId = Read-Host
    if (-not $vendorId) { $vendorId = (Get-EdrConfig).default_vendor }
    Write-Host '  厂商日志路径：' -ForegroundColor White -NoNewline
    $inputPath = Read-Host
    if (-not $inputPath) { return }
    Write-Host '  标准化输出路径：' -ForegroundColor White -NoNewline
    $outputPath = Read-Host
    if (-not $outputPath) {
        $outputPath = Join-Path (Join-Path (Get-EdrProjectRoot) 'import') "normalized-$(Get-Date -Format 'yyyyMMddHHmmss').json"
    }
    $result = ConvertFrom-EdrVendorLog -InputPath $inputPath -VendorId $vendorId
    Export-EdrJson -Path $outputPath -Value $result.events
    Write-Host "  已转换 $($result.events.Count) 条事件：$outputPath" -ForegroundColor Green
}

function Invoke-EdrOfflineCompare {
    Write-Host '  本地事件日志路径（events.jsonl）：' -ForegroundColor White -NoNewline
    $localLog = Read-Host
    if (-not $localLog) { return }
    Write-Host '  厂商日志路径（JSON 数组或 JSONL，多个用逗号分隔）：' -ForegroundColor White -NoNewline
    $cloudInput = Read-Host
    if (-not $cloudInput) { return }
    $cloudPaths = @($cloudInput.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    Write-Host ("  厂商 ID（默认 " + (Get-EdrConfig).default_vendor + "）: ") -ForegroundColor White -NoNewline
    $vendorId = Read-Host
    if (-not $vendorId) { $vendorId = (Get-EdrConfig).default_vendor }
    Write-Host '  输出结果路径（默认 reports/validation-result.json）：' -ForegroundColor White -NoNewline
    $outputPath = Read-Host
    if (-not $outputPath) {
        $reportDir = Join-Path (Get-EdrProjectRoot) (Get-EdrConfig).default_report_dir
        $outputPath = Join-Path $reportDir "validation-result-$(Get-Date -Format 'yyyyMMddHHmmss').json"
    }
    $result = Compare-EdrOfflineLogs -LocalLogPath $localLog -CloudPaths $cloudPaths -VendorId $vendorId -OutputPath $outputPath
    Write-Host "  比对完成：PASS=$($result.summary.pass) PARTIAL=$($result.summary.partial) FAIL=$($result.summary.fail) INCONCLUSIVE=$($result.summary.inconclusive)" -ForegroundColor Green
    Write-Host "  结果：$outputPath" -ForegroundColor DarkGray
}

function Show-EdrBaselineMenu {
    $baselines = Import-EdrBaselines
    Write-Host ''
    Write-Host '  -------------------- 安全基线 --------------------' -ForegroundColor Cyan
    Write-Host "  基线数量：$($baselines.Count)"
    foreach ($baseline in $baselines) {
        $assertions = @($baseline.cloud_expectations[0].assertions).Count
        Write-Host ("    " + $baseline.capability.id.PadRight(34) + " v" + $baseline.version + "  云端期望 " + $assertions + " 项断言") -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Host '  1. 初始化/重新生成全部基线' -ForegroundColor White
    Write-Host '  2. 导入自定义基线 JSON' -ForegroundColor White
    Write-Host '  3. 校验场景覆盖完整性' -ForegroundColor White
    Write-Host '  0. 返回主菜单' -ForegroundColor DarkGray
    Write-Host '  请选择：' -ForegroundColor White -NoNewline
    $choice = Read-Host
    switch ($choice) {
        '1' {
            & (Join-Path $projectRoot 'tools\Generate-ScenarioScripts.ps1')
            Write-Host '  基线已重新生成。' -ForegroundColor Green
        }
        '2' {
            Write-Host '  自定义基线 JSON 路径：' -ForegroundColor White -NoNewline
            $importPath = Read-Host
            if ($importPath) {
                & (Join-Path $projectRoot 'Initialize-SecurityBaseline.ps1') -ImportPath $importPath
            }
        }
        '3' {
            $catalog = Get-EdrScenarioCatalog
            $missing = @()
            foreach ($scenario in $catalog) {
                if (-not (Get-EdrBaselineForScenario -ScenarioId $scenario.ScenarioId)) { $missing += $scenario.ScenarioId }
            }
            if ($missing.Count -eq 0) {
                Write-Host '  全部场景均有安全基线。' -ForegroundColor Green
            }
            else {
                Write-Host "  缺少基线：$($missing -join '、')" -ForegroundColor Red
            }
        }
        default { }
    }
}

Show-EdrBanner
:mainMenu while ($true) {
    Write-Host '  -------------------- 主菜单 --------------------' -ForegroundColor Cyan
    Write-Host '   1. 查看能力目录' -ForegroundColor White
    Write-Host '   2. 运行单个场景' -ForegroundColor White
    Write-Host '   3. 按分类运行' -ForegroundColor White
    Write-Host '   4. 运行全部场景（串行）' -ForegroundColor White
    Write-Host '   5. 批量运行指定场景' -ForegroundColor White
    Write-Host '   6. 导入厂商日志并标准化' -ForegroundColor White
    Write-Host '   7. 本地与厂商日志离线比对' -ForegroundColor White
    Write-Host '   8. 安全基线管理' -ForegroundColor White
    Write-Host '   0. 退出' -ForegroundColor DarkGray
    Write-Host '  -------------------------------------------------' -ForegroundColor Cyan
    Write-Host '  请选择：' -ForegroundColor White -NoNewline
    $choice = Read-Host
    switch ($choice) {
        '1' { Show-EdrCatalog }
        '2' { Invoke-EdrSingleScenario }
        '3' { Invoke-EdrCategoryRun }
        '4' { Invoke-EdrAllRun }
        '5' { Invoke-EdrBatchRun }
        '6' { Invoke-EdrVendorConversion }
        '7' { Invoke-EdrOfflineCompare }
        '8' { Show-EdrBaselineMenu }
        '0' {
            Write-Host '  已退出。' -ForegroundColor Green
            break mainMenu
        }
        default {
            Write-Host '  无效选择。' -ForegroundColor Red
        }
    }
}
