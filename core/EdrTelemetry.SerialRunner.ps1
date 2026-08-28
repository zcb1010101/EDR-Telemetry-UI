#Requires -Version 5.1
Set-StrictMode -Version 2.0

if (-not (Get-Command 'Initialize-EdrContext' -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'EdrTelemetry.Common.ps1')
}

function Start-EdrTelemetrySuite {
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
    $catalog = Get-EdrScenarioCatalog
    $selected = @()
    if ($All) {
        $selected = @($catalog)
    }
    elseif ($ScenarioIds -and $ScenarioIds.Count -gt 0) {
        foreach ($id in $ScenarioIds) {
            $match = @($catalog | Where-Object { $_.ScenarioId -eq $id })
            if ($match.Count -eq 0) {
                $num = 0
                if ([int]::TryParse($id, [ref]$num) -and $num -ge 1 -and $num -le $catalog.Count) {
                    $match = @($catalog[$num - 1])
                }
            }
            if ($match.Count -eq 0) { throw "未知场景 ID：$id" }
            $selected += $match[0]
        }
    }
    elseif ($Categories -and $Categories.Count -gt 0) {
        foreach ($category in $Categories) {
            $matches = @($catalog | Where-Object { $_.Category -eq $category })
            if ($matches.Count -eq 0) { throw "未知分类：$category" }
            $selected += $matches
        }
    }
    else {
        throw '请提供 -ScenarioIds、-Categories 或 -All。'
    }
    $selected = @($selected | Sort-Object -Property Category, ScenarioName -Unique)

    $config = Get-EdrConfig
    if (-not $RunId) { $RunId = New-EdrRunId }
    if ($IntervalSeconds -lt 0) { $IntervalSeconds = [int]$config.default_interval_seconds }
    if (-not $OutputLog) { $OutputLog = Get-EdrDefaultOutputLog -RunId $RunId }

    Write-EdrConsole -Message "============================================" -Color Cyan
    Write-EdrConsole -Message "  EDR 遥测串行执行器"
    Write-EdrConsole -Message "  Run ID：$RunId"
    Write-EdrConsole -Message "  场景数：$($selected.Count)"
    Write-EdrConsole -Message "  间隔：$IntervalSeconds 秒"
    Write-EdrConsole -Message "============================================" -Color Cyan

    $results = New-Object System.Collections.Generic.List[object]
    $aborted = $false
    for ($index = 0; $index -lt $selected.Count; $index++) {
        if ($aborted) { break }
        $scenario = $selected[$index]
        $scriptPath = Get-EdrScenarioScriptPath -Scenario $scenario
        if (-not (Test-Path -LiteralPath $scriptPath)) {
            Write-EdrConsole -Message "[$($index + 1)/$($selected.Count)] 缺少场景脚本：$scriptPath" -Color Red
            continue
        }
        $nonce = New-EdrNonce
        $parameters = @{
            RunId = $RunId
            Nonce = $nonce
            OutputLog = $OutputLog
            IntervalSeconds = $IntervalSeconds
        }
        if ($ThreatLevel) { $parameters.ThreatLevel = $ThreatLevel }
        if ($SkipCleanup) { $parameters.SkipCleanup = $true }
        if ($ServiceName) { $parameters.ServiceName = $ServiceName }
        if ($UsbWaitSeconds -gt 0) { $parameters.UsbWaitSeconds = $UsbWaitSeconds }
        if ($ConfirmManual) { $parameters.ConfirmManual = $true }

        Write-EdrConsole -Message "[$($index + 1)/$($selected.Count)] 开始：$($scenario.ScenarioName)（$($scenario.ScenarioId)）" -Color Magenta
        $event = $null
        try {
            $output = & $scriptPath @parameters
            $event = @($output | Select-Object -Last 1)[0]
        }
        catch {
            $event = New-EdrEvent -Scenario $scenario -RunId $RunId -Nonce $nonce -Operation $scenario.Operation `
                -Status 'FAILED' -Success $false -Verification 'error' -ThreatLevel $ThreatLevel `
                -Detail "串行执行异常：$($_.Exception.Message)" -Errors @($_.Exception.Message) `
                -Cleanup (Get-EdrCleanupResult -Status 'failed' -Detail 'Runner 捕获异常。')
            $event.observed_at_utc = Get-EdrUtcTimestamp
            Write-EdrEventLog -Event $event -OutputLog $OutputLog
        }
        $results.Add($event)
        if ($event) {
            $color = switch ($event.status) {
                'SUCCESS' { 'Green' }
                'SKIPPED' { 'Yellow' }
                default { 'Red' }
            }
            Write-EdrConsole -Message "  结果：$($event.status) | $($event.detail)" -Color $color
            if ($event.status -eq 'CLEANUP_ERROR' -or ($StopOnFailure -and $event.status -eq 'FAILED')) {
                Write-EdrConsole -Message "  按策略停止后续场景。" -Color Yellow
                $aborted = $true
            }
        }
        if (-not $aborted -and $index -lt $selected.Count - 1 -and $IntervalSeconds -gt 0) {
            Write-EdrConsole -Message "  等待 $IntervalSeconds 秒后执行下一场景..." -Color DarkGray
            Start-Sleep -Seconds $IntervalSeconds
        }
    }

    $completed = @($results | Where-Object { $_.status -eq 'SUCCESS' }).Count
    $skipped = @($results | Where-Object { $_.status -eq 'SKIPPED' }).Count
    $failed = @($results | Where-Object { $_.status -ne 'SUCCESS' -and $_.status -ne 'SKIPPED' }).Count
    $summary = [pscustomobject]@{
        schema_version = '1.0'
        run_id = $RunId
        started_at_utc = $(if ($results.Count -gt 0) { $results[0].triggered_at_utc } else { Get-EdrUtcTimestamp })
        ended_at_utc = Get-EdrUtcTimestamp
        total = $selected.Count
        completed = $completed
        skipped = $skipped
        failed = $failed
        aborted = $aborted
        output_log = $OutputLog
        scenarios = $results.ToArray()
    }
    $summaryPath = $OutputLog -replace 'events\.jsonl$', 'suite-summary.json'
    Export-EdrJson -Path $summaryPath -Value $summary
    Write-EdrConsole -Message "============================================" -Color Cyan
    Write-EdrConsole -Message "  串行执行完成：成功 $completed / 跳过 $skipped / 失败 $failed"
    Write-EdrConsole -Message "  事件日志：$OutputLog"
    Write-EdrConsole -Message "  轮次摘要：$summaryPath"
    Write-EdrConsole -Message "============================================" -Color Cyan
    return $summary
}
