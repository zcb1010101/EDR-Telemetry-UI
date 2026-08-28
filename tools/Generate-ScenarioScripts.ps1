#Requires -Version 5.1
<#
.SYNOPSIS
从场景目录与基线模板生成 53 个独立场景脚本和 16 个安全基线文件。
.DESCRIPTION
基线采用确定性 correlation.keys 关联，不包含项目 1 的锚点评分。
.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\tools\Generate-ScenarioScripts.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$csvPath = Join-Path $projectRoot 'config\scenario-catalog.csv'
$templatePath = Join-Path $projectRoot 'config\baseline-templates.json'
$scenarioRoot = Join-Path $projectRoot 'scenarios'
$baselineRoot = Join-Path $projectRoot 'baselines'

$catalog = @(Get-Content -LiteralPath $csvPath -Raw -Encoding UTF8 | ConvertFrom-Csv)
$templates = Get-Content -LiteralPath $templatePath -Raw -Encoding UTF8 | ConvertFrom-Json

function Get-EventTypeFromOperation {
    param([Parameter(Mandatory = $true)][string]$Operation)
    return ($Operation -split '\.')[0]
}

function Get-EventActionFromOperation {
    param([Parameter(Mandatory = $true)][string]$Operation)
    $parts = @($Operation -split '\.', 2)
    return $(if ($parts.Count -gt 1) { $parts[1] } else { $Operation })
}

function ConvertTo-StringArray {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return @() }
    return @($Value | ForEach-Object { [string]$_ })
}

function New-NormalizedKey {
    param($Key)
    $norm = @()
    if ($Key.PSObject.Properties['normalizers']) { $norm = @($Key.normalizers | Where-Object { $_ }) }
    $operator = 'equals'
    if ($Key.PSObject.Properties['operator'] -and $Key.operator) { $operator = $Key.operator }
    return [pscustomobject]@{
        local_field = $Key.local_field
        cloud_field = $Key.cloud_field
        operator = $operator
        normalizers = $norm
    }
}

function New-NormalizedAssertion {
    param($Assertion)
    $norm = @()
    if ($Assertion.PSObject.Properties['normalizers']) { $norm = @($Assertion.normalizers | Where-Object { $_ }) }
    $expected = $null
    if ($Assertion.PSObject.Properties['expected']) { $expected = $Assertion.expected }
    $expectedFromLocal = $null
    if ($Assertion.PSObject.Properties['expected_from_local']) { $expectedFromLocal = $Assertion.expected_from_local }
    $accepted = $null
    if ($Assertion.PSObject.Properties['accepted_values'] -and @($Assertion.accepted_values).Count -gt 0) { $accepted = @($Assertion.accepted_values) }
    return [pscustomobject]@{
        field = $Assertion.field
        operator = $Assertion.operator
        expected = $expected
        expected_from_local = $expectedFromLocal
        accepted_values = $accepted
        severity = $Assertion.severity
        normalizers = $norm
    }
}

function New-ScenarioScript {
    param($Scenario)
    $categoryFolder = $Scenario.CategoryFolder
    $scriptName = "Invoke-$($Scenario.ScenarioName).ps1"
    $directory = Join-Path $scenarioRoot $categoryFolder
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $content = @"
#Requires -Version 5.1
<#
.SYNOPSIS
$($Scenario.ScenarioName) 遥测采集与真伪校验脚本
.DESCRIPTION
类别：$($Scenario.Category)
场景 ID：$($Scenario.ScenarioId)
默认威胁等级：$($Scenario.ThreatLevel)
需要管理员：$($Scenario.RequiresAdmin)
行为类型：$($Scenario.BehaviorKind)
.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\Invoke-$($Scenario.ScenarioName).ps1
#>
[CmdletBinding()]
param(
    [string]`$RunId,
    [string]`$Nonce,
    [string]`$OutputLog,
    [ValidateSet('LV0', 'LV1', 'LV2', 'LV3')]
    [string]`$ThreatLevel,
    [int]`$IntervalSeconds = -1,
    [switch]`$SkipCleanup,
    [string]`$ServiceName,
    [int]`$UsbWaitSeconds = 0,
    [switch]`$ConfirmManual
)

`$ErrorActionPreference = 'Stop'
`$projectRoot = Split-Path -Parent (Split-Path -Parent `$PSScriptRoot)
. (Join-Path `$projectRoot 'core\EdrTelemetry.Common.ps1')
. (Join-Path `$projectRoot 'core\EdrTelemetry.Behaviors.ps1')

`$scenario = Get-EdrScenario -ScenarioId '$($Scenario.ScenarioId)'
if (-not `$RunId) { `$RunId = New-EdrRunId }
if (-not `$Nonce) { `$Nonce = New-EdrNonce }
if (-not `$OutputLog) { `$OutputLog = Get-EdrDefaultOutputLog -RunId `$RunId }
`$config = Get-EdrConfig
if (`$IntervalSeconds -lt 0) { `$IntervalSeconds = [int]`$config.default_interval_seconds }

`$event = Invoke-EdrTelemetryScenario -Scenario `$scenario -RunId `$RunId -Nonce `$Nonce ``
    -ThreatLevel `$ThreatLevel -SkipCleanup:`$SkipCleanup -ServiceName `$ServiceName ``
    -UsbWaitSeconds `$UsbWaitSeconds -ConfirmManual:`$ConfirmManual
Write-EdrEventLog -Event `$event -OutputLog `$OutputLog

`$color = switch (`$event.status) {
    'SUCCESS' { 'Green' }
    'SKIPPED' { 'Yellow' }
    default { 'Red' }
}
Write-EdrConsole -Message ("[`$(`$event.status)] `$(`$event.scenario_id) | `$(`$event.operation) | " + (Get-EdrThreatLevelLabel `$event.threat_level) + " | " + `$event.detail) -Color `$color
Write-EdrConsole -Message ("日志: " + `$OutputLog) -Color 'DarkGray'

if (`$IntervalSeconds -gt 0) { Start-Sleep -Seconds `$IntervalSeconds }
`$event | Select-Object run_id, nonce, scenario_id, operation, status, success, verification, threat_level, triggered_at_utc, observed_at_utc, detail
"@
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText((Join-Path $directory $scriptName), $content, $utf8NoBom)
}

function New-BaselineFile {
    param(
        [string]$Category,
        [object[]]$Scenarios,
        $Domain
    )
    $categoryFolder = $Scenarios[0].CategoryFolder
    $baselines = @()
    foreach ($scenario in $Scenarios) {
        $override = $null
        if ($templates.overrides.PSObject.Properties[$scenario.ScenarioId]) {
            $override = $templates.overrides.($scenario.ScenarioId)
        }

        $localRequirements = @(
            [pscustomobject]@{ field = 'operation'; operator = 'equals'; expected = $scenario.Operation; severity = 'required' },
            [pscustomobject]@{ field = 'status'; operator = 'equals'; expected = 'SUCCESS'; severity = 'required' }
        )
        if ($override -and $override.PSObject.Properties['local_requirements'] -and @($override.local_requirements).Count -gt 0) {
            $localRequirements = @($override.local_requirements | ForEach-Object { New-NormalizedAssertion -Assertion $_ })
        }

        $eventType = if ($override -and $override.PSObject.Properties['event_type']) { $override.event_type }
        elseif ($Domain.PSObject.Properties['event_type']) { $Domain.event_type }
        else { Get-EventTypeFromOperation -Operation $scenario.Operation }

        $eventActions = if ($override -and $override.PSObject.Properties['event_actions']) {
            @($override.event_actions | ForEach-Object { [string]$_ })
        }
        else {
            @(Get-EventActionFromOperation -Operation $scenario.Operation)
        }

        $keys = if ($override -and $override.PSObject.Properties['keys'] -and @($override.keys).Count -gt 0) {
            @($override.keys | ForEach-Object { New-NormalizedKey -Key $_ })
        }
        else {
            @($Domain.keys | ForEach-Object { New-NormalizedKey -Key $_ })
        }

        $assertions = if ($override -and $override.PSObject.Properties['assertions'] -and @($override.assertions).Count -gt 0) {
            @($override.assertions | ForEach-Object { New-NormalizedAssertion -Assertion $_ })
        }
        else {
            @($Domain.assertions | ForEach-Object { New-NormalizedAssertion -Assertion $_ })
        }

        $methodSelection = 'best'
        if ($override -and $override.PSObject.Properties['method_selection']) { $methodSelection = $override.method_selection }
        elseif ($Domain.PSObject.Properties['method_selection']) { $methodSelection = $Domain.method_selection }

        $expectations = @()
        if ($override -and $override.PSObject.Properties['expectations'] -and @($override.expectations).Count -gt 0) {
            foreach ($expectation in @($override.expectations)) {
                $rawExpectationKeys = @()
                if ($expectation.PSObject.Properties['correlation'] -and $expectation.correlation.PSObject.Properties['keys']) {
                    $rawExpectationKeys = @($expectation.correlation.keys)
                }
                elseif ($expectation.PSObject.Properties['keys']) {
                    $rawExpectationKeys = @($expectation.keys)
                }
                $expectationKeys = @($rawExpectationKeys | ForEach-Object { New-NormalizedKey -Key $_ })
                $expectationAssertions = @($expectation.assertions | ForEach-Object { New-NormalizedAssertion -Assertion $_ })
                $method = $null
                if ($expectation.PSObject.Properties['method']) { $method = $expectation.method }
                $stage = $null
                if ($expectation.PSObject.Properties['stage']) { $stage = $expectation.stage }
                $expectationTimeFromLocal = $null
                if ($expectation.PSObject.Properties['correlation'] -and $expectation.correlation.PSObject.Properties['time_from_local']) {
                    $expectationTimeFromLocal = $expectation.correlation.time_from_local
                }
                $expectationMaxTime = $Domain.max_time_difference_ms
                if ($expectation.PSObject.Properties['correlation'] -and $expectation.correlation.PSObject.Properties['max_time_difference_ms']) {
                    $expectationMaxTime = $expectation.correlation.max_time_difference_ms
                }
                elseif ($expectation.PSObject.Properties['max_time_difference_ms']) {
                    $expectationMaxTime = $expectation.max_time_difference_ms
                }
                $expectationCorrelation = [pscustomobject]@{
                    time_from_local = $expectationTimeFromLocal
                    max_time_difference_ms = $expectationMaxTime
                    keys = $expectationKeys
                }
                $expectations += [pscustomobject]@{
                    id = $expectation.id
                    method = $method
                    stage = $stage
                    event_type = $expectation.event_type
                    event_actions = @($expectation.event_actions | ForEach-Object { [string]$_ })
                    cardinality = $expectation.cardinality
                    correlation = $expectationCorrelation
                    assertions = $expectationAssertions
                }
            }
        }
        else {
            $expectations += [pscustomobject]@{
                id = "$($scenario.ScenarioId)-event"
                event_type = $eventType
                event_actions = $eventActions
                cardinality = [pscustomobject]@{ min = 1; max = 3 }
                assertions = $assertions
            }
        }

        $baselines += [pscustomobject]@{
            schema_version = '2.0'
            baseline_id = $scenario.ScenarioId
            version = '2.0.0'
            title = "$($scenario.ScenarioName) 遥测基线"
            description = "验证 $($scenario.Operation) 本地行为成立，并按确定性字段键关联云端事件。"
            platform = [pscustomobject]@{
                os = 'windows'
                versions = @('windows-10', 'windows-11', 'windows-server-2019', 'windows-server-2022')
                architectures = @('x64')
            }
            risk_level = $scenario.ThreatLevel
            capability = [pscustomobject]@{
                id = $scenario.ScenarioId
                version = '2.0.0'
            }
            local_requirements = $localRequirements
            correlation = [pscustomobject]@{
                time_before_seconds = $Domain.time_before_seconds
                time_after_seconds = $Domain.time_after_seconds
                max_time_difference_ms = $Domain.max_time_difference_ms
                keys = $keys
            }
            method_selection = [pscustomobject]@{ strategy = $methodSelection }
            cloud_expectations = $expectations
            scoring = [pscustomobject]@{
                weight = 1.0
                required_field_weight = 1.0
                recommended_field_weight = 0.25
            }
            metadata = [pscustomobject]@{
                owner = 'edr-validation-team'
                status = 'active'
                change_reason = '采用确定性关联键，移除锚点评分。'
            }
        }
    }
    $root = [pscustomobject]@{
        schema_version = '2.0'
        baseline_id = $Scenarios[0].Category
        title = "$Category 遥测基线"
        baselines = $baselines
    }
    $fileName = "$categoryFolder.baseline.json"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $json = ConvertTo-Json -InputObject $root -Depth 100
    [System.IO.File]::WriteAllText((Join-Path $baselineRoot $fileName), $json, $utf8NoBom)
}

foreach ($scenario in $catalog) {
    New-ScenarioScript -Scenario $scenario
}

$groups = $catalog | Group-Object Category
foreach ($group in $groups) {
    $domain = $templates.domains.($group.Name)
    if (-not $domain) {
        Write-Warning "未找到模板：$($group.Name)"
        continue
    }
    New-BaselineFile -Category $group.Name -Scenarios @($group.Group) -Domain $domain
}

Write-Host "已生成 $($catalog.Count) 个场景脚本和 $($groups.Count) 个基线文件。"
