#Requires -Version 5.1
Set-StrictMode -Version 2.0

if (-not (Get-Command 'Initialize-EdrContext' -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'EdrTelemetry.Common.ps1')
}
if (-not (Get-Command 'ConvertFrom-EdrVendorLog' -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'EdrTelemetry.Normalizer.ps1')
}
if (-not (Get-Command 'Import-EdrBaselines' -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'EdrTelemetry.Baseline.ps1')
}

function Get-EdrLocalEvents {
    param([Parameter(Mandatory = $true)][string]$LocalLogPath)
    if (-not (Test-Path -LiteralPath $LocalLogPath)) { throw "找不到本地日志：$LocalLogPath" }
    $events = @()
    foreach ($line in Get-Content -LiteralPath $LocalLogPath -Encoding UTF8) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $events += ConvertFrom-Json -InputObject $line
    }
    return $events
}

function ConvertTo-EdrDateTime {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetimeoffset]) {
        return $Value.ToUniversalTime()
    }
    if ($Value -is [datetime]) {
        return [DateTimeOffset]::new($Value).ToUniversalTime()
    }
    $parsed = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse(([string]$Value), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
        return $parsed.ToUniversalTime()
    }
    return $null
}

function Get-EdrWorseStatus {
    param(
        [Parameter(Mandatory = $true)][string]$Current,
        [Parameter(Mandatory = $true)][string]$Candidate
    )
    $rank = @{
        'PASS' = 0
        'PARTIAL' = 1
        'INCONCLUSIVE' = 2
        'FAIL' = 3
        'NOT_COMPARED' = 4
    }
    if ($rank[$Candidate] -gt $rank[$Current]) { return $Candidate }
    return $Current
}

function Get-EdrStatusRank {
    param([Parameter(Mandatory = $true)][string]$Status)
    $rank = @{
        'PASS' = 0
        'PARTIAL' = 1
        'INCONCLUSIVE' = 2
        'FAIL' = 3
        'NOT_COMPARED' = 4
    }
    return $rank[$Status]
}

function Get-EdrBetterStatus {
    param(
        [Parameter(Mandatory = $true)][string]$Current,
        [Parameter(Mandatory = $true)][string]$Candidate
    )
    if ((Get-EdrStatusRank -Status $Candidate) -lt (Get-EdrStatusRank -Status $Current)) {
        return $Candidate
    }
    return $Current
}

function Test-EdrCorrelationKey {
    param(
        [Parameter(Mandatory = $true)]$LocalEvent,
        [Parameter(Mandatory = $true)]$CloudEvent,
        [Parameter(Mandatory = $true)]$Key
    )
    $normalizers = @()
    if ($Key.PSObject.Properties['normalizers']) { $normalizers = @($Key.normalizers) }
    $local = Resolve-EdrLocalValue -LocalEvent $LocalEvent -Field $Key.local_field
    $local = Normalize-EdrValue -Value $local -Normalizers $normalizers
    if ($null -eq $local -or [string]$local -eq '') {
        return [pscustomobject]@{
            local_field = $Key.local_field
            cloud_field = $Key.cloud_field
            matched = $false
            local_value = $null
            cloud_value = $null
            reason = 'local_missing'
        }
    }
    $cloud = $CloudEvent.fields[$Key.cloud_field]
    $cloud = Normalize-EdrValue -Value $cloud -Normalizers $normalizers
    $operator = if ($Key.PSObject.Properties['operator']) { [string]$Key.operator } else { 'equals' }
    $matched = if ($operator -eq 'contains') {
        $null -ne $cloud -and ([string]$cloud).IndexOf([string]$local, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
    }
    else {
        Test-EdrEquivalent -Left $local -Right $cloud
    }
    return [pscustomobject]@{
        local_field = $Key.local_field
        cloud_field = $Key.cloud_field
        matched = $matched
        local_value = $local
        cloud_value = $cloud
        reason = $(if ($matched) { 'matched' } else { 'value_mismatch' })
    }
}

function Get-EdrCorrelationConfig {
    param(
        [Parameter(Mandatory = $true)]$Expectation,
        [Parameter(Mandatory = $true)]$Baseline
    )
    $base = $Baseline.correlation
    $override = $null
    if ($Expectation.PSObject.Properties['correlation'] -and $null -ne $Expectation.correlation) {
        $override = $Expectation.correlation
    }
    $keys = @()
    if ($override -and $override.PSObject.Properties['keys'] -and @($override.keys).Count -gt 0) {
        $keys = @($override.keys)
    }
    elseif ($base.PSObject.Properties['keys'] -and @($base.keys).Count -gt 0) {
        $keys = @($base.keys)
    }
    $maxTime = [int]$base.max_time_difference_ms
    if ($override -and $override.PSObject.Properties['max_time_difference_ms']) {
        $maxTime = [int]$override.max_time_difference_ms
    }
    $timeFromLocal = $null
    if ($override -and $override.PSObject.Properties['time_from_local']) {
        $timeFromLocal = [string]$override.time_from_local
    }
    return [pscustomobject]@{
        time_before_seconds = [int]$base.time_before_seconds
        time_after_seconds = [int]$base.time_after_seconds
        max_time_difference_ms = $maxTime
        keys = @($keys)
        time_from_local = $timeFromLocal
    }
}

function New-EdrCandidateMatch {
    param(
        [Parameter(Mandatory = $true)]$CanonicalEvent,
        [Parameter(Mandatory = $true)]$Expectation,
        [Parameter(Mandatory = $true)]$Correlation,
        [Parameter(Mandatory = $true)]$LocalEvent,
        [Parameter(Mandatory = $true)][DateTimeOffset]$CorrelationTime
    )
    $typeMatched = Test-EdrEquivalent -Left $CanonicalEvent.fields['event.type'] -Right $Expectation.event_type
    $actionMatched = $false
    foreach ($action in @($Expectation.event_actions)) {
        if (Test-EdrEquivalent -Left $CanonicalEvent.fields['event.action'] -Right $action) {
            $actionMatched = $true
            break
        }
    }
    $keyResults = @()
    $allKeysMatched = $true
    foreach ($key in @($Correlation.keys)) {
        $result = Test-EdrCorrelationKey -LocalEvent $LocalEvent -CloudEvent $CanonicalEvent -Key $key
        $keyResults += $result
        if (-not $result.matched) { $allKeysMatched = $false }
    }
    $eventTime = ConvertTo-EdrDateTime -Value $CanonicalEvent.event_time
    $timeDistanceMs = $null
    $withinMaxTime = $false
    if ($eventTime) {
        $timeDistanceMs = [long][Math]::Abs(($eventTime - $CorrelationTime).TotalMilliseconds)
        $withinMaxTime = $timeDistanceMs -le $Correlation.max_time_difference_ms
    }
    $matchedKeys = @($keyResults | Where-Object { $_.matched } | ForEach-Object { "$($_.local_field)=$($_.cloud_field)" })
    $qualified = $typeMatched -and $actionMatched -and $allKeysMatched -and $withinMaxTime
    $reason = if (-not $typeMatched) {
        '事件类型不匹配'
    }
    elseif (-not $actionMatched) {
        '事件动作不匹配'
    }
    elseif (-not $allKeysMatched) {
        '确定性关联键未全部命中'
    }
    elseif (-not $withinMaxTime) {
        '事件时间超过最大时间差'
    }
    else {
        '关联键、事件类型与时间均匹配'
    }
    return [pscustomobject]@{
        canonical_event = $CanonicalEvent
        matched_keys = $matchedKeys
        key_results = $keyResults
        matched_key_count = $matchedKeys.Count
        required_key_count = $keyResults.Count
        time_distance_ms = $timeDistanceMs
        type_matched = $typeMatched
        action_matched = $actionMatched
        qualified = $qualified
        qualification_reason = $reason
    }
}

function Get-EdrExportCoverage {
    param(
        [Parameter(Mandatory = $true)]$LocalEvent,
        [AllowNull()]$CloudEvents,
        [AllowNull()]$CloudManifestPath
    )
    if ($CloudManifestPath) {
        return 'verified'
    }
    $start = ConvertTo-EdrDateTime -Value $LocalEvent.triggered_at_utc
    $end = ConvertTo-EdrDateTime -Value $LocalEvent.observed_at_utc
    if (-not $start) { $start = ConvertTo-EdrDateTime -Value $LocalEvent.observed_at_utc }
    $times = @()
    foreach ($event in @($CloudEvents)) {
        $time = ConvertTo-EdrDateTime -Value $event.event_time
        if ($time) { $times += $time }
    }
    if ($times.Count -gt 0 -and $start) {
        $min = $times[0]
        $max = $times[0]
        foreach ($time in $times) {
            if ($time -lt $min) { $min = $time }
            if ($time -gt $max) { $max = $time }
        }
        $end = if ($end) { $end } else { $start }
        if ($min -le $start -and $max -ge $end) { return 'inferred' }
    }
    return 'insufficient'
}

function Get-EdrExpectationResult {
    param(
        [Parameter(Mandatory = $true)]$Expectation,
        [Parameter(Mandatory = $true)]$Baseline,
        [Parameter(Mandatory = $true)]$LocalEvent,
        [Parameter(Mandatory = $true)]$CloudEvents,
        [Parameter(Mandatory = $true)][string]$ExportCoverage,
        [Parameter(Mandatory = $true)][int]$MaxDisplayedCandidates,
        [Parameter(Mandatory = $true)][DateTimeOffset]$DefaultCorrelationTime
    )
    $correlation = Get-EdrCorrelationConfig -Expectation $Expectation -Baseline $Baseline
    $correlationTime = $DefaultCorrelationTime
    if ($correlation.time_from_local) {
        $localTime = Resolve-EdrLocalValue -LocalEvent $LocalEvent -Field $correlation.time_from_local
        $parsedTime = ConvertTo-EdrDateTime -Value $localTime
        if ($parsedTime) { $correlationTime = $parsedTime }
    }
    $windowStart = $correlationTime.AddSeconds(-$correlation.time_before_seconds)
    $windowEnd = $correlationTime.AddSeconds($correlation.time_after_seconds)

    $candidates = @()
    foreach ($cloudEvent in @($CloudEvents)) {
        $eventTime = ConvertTo-EdrDateTime -Value $cloudEvent.event_time
        if (-not $eventTime) { continue }
        if ($eventTime -lt $windowStart -or $eventTime -gt $windowEnd) { continue }
        $candidate = New-EdrCandidateMatch -CanonicalEvent $cloudEvent -Expectation $Expectation `
            -Correlation $correlation -LocalEvent $LocalEvent -CorrelationTime $correlationTime
        $candidates += $candidate
    }

    $sorted = @($candidates | Sort-Object -Property `
        @{ Expression = { $_.qualified }; Descending = $true },
        @{ Expression = { $_.time_distance_ms }; Ascending = $true },
        @{ Expression = { $_.canonical_event.raw_ref }; Ascending = $true })
    $deduplicated = @($sorted | Group-Object -Property { $_.canonical_event.raw_ref } | ForEach-Object { $_.Group[0] })
    $displayed = @($deduplicated | Select-Object -First $MaxDisplayedCandidates)
    $qualifiedCandidates = @($displayed | Where-Object { $_.qualified })

    $cardinality = $Expectation.cardinality
    $min = [int]$cardinality.min
    $max = if ($cardinality.PSObject.Properties['max']) { [int]$cardinality.max } else { [int]::MaxValue }
    $cardinalityStatus = if ($qualifiedCandidates.Count -lt $min) {
        if ($ExportCoverage -in @('verified', 'inferred')) { 'failed' } else { 'not_evaluated' }
    }
    elseif ($qualifiedCandidates.Count -gt $max) {
        'not_evaluated'
    }
    else {
        'passed'
    }

    $status = 'PASS'
    $requirements = @()
    $requirements += [pscustomobject]@{
        requirement_id = "$($Expectation.id)-cardinality"
        scope = 'cloud'
        title_zh = "必须找到 $min 至 $max 条 $($Expectation.event_type) 事件"
        expectation_id = $Expectation.id
        field = 'event.count'
        operator = 'range'
        severity = 'required'
        status = $cardinalityStatus
        expected = [pscustomobject]@{ min = $min; max = $max }
        actual = $qualifiedCandidates.Count
        message = $cardinalityStatus
    }
    if ($cardinalityStatus -eq 'failed') {
        $status = 'FAIL'
    }
    elseif ($cardinalityStatus -eq 'not_evaluated') {
        $status = 'INCONCLUSIVE'
    }

    $assertions = @()
    $selected = $qualifiedCandidates | Select-Object -First 1
    $warnings = @()
    if (-not $selected -and $displayed.Count -gt 0) {
        $warnings += '存在低置信候选，但因关联键未全部命中，仅展示不参与判定。'
    }

    if ($selected) {
        $eventTime = ConvertTo-EdrDateTime -Value $selected.canonical_event.event_time
        $timeDistance = if ($eventTime) { [long][Math]::Abs(($eventTime - $correlationTime).TotalMilliseconds) } else { $null }
        $timeStatus = if ($null -eq $timeDistance) { 'not_evaluated' } elseif ($timeDistance -le $correlation.max_time_difference_ms) { 'passed' } else { 'failed' }
        $requirements += [pscustomobject]@{
            requirement_id = "$($Expectation.id)-time-difference"
            scope = 'cloud'
            title_zh = "EDR 事件与本地行为时间差必须不超过 $($correlation.max_time_difference_ms) ms"
            expectation_id = $Expectation.id
            field = 'event.time_difference_ms'
            operator = 'range'
            severity = 'required'
            status = $timeStatus
            expected = [pscustomobject]@{ min = 0; max = $correlation.max_time_difference_ms }
            actual = $timeDistance
            message = $timeStatus
        }
        if ($timeStatus -eq 'failed') {
            $status = Get-EdrWorseStatus -Current $status -Candidate 'FAIL'
        }
        elseif ($timeStatus -eq 'not_evaluated') {
            $status = Get-EdrWorseStatus -Current $status -Candidate 'INCONCLUSIVE'
        }

        foreach ($assertion in @($Expectation.assertions)) {
            $actual = $selected.canonical_event.fields[$assertion.field]
            $evaluation = Test-EdrAssertion -Assertion $assertion -Actual $actual -LocalEvent $LocalEvent
            $assertions += $evaluation
            $requirements += [pscustomobject]@{
                requirement_id = "$($Expectation.id)-assertion"
                scope = 'cloud'
                expectation_id = $Expectation.id
                field = $evaluation.field
                operator = $evaluation.operator
                severity = $evaluation.severity
                status = $evaluation.status
                expected = $evaluation.expected
                actual = $evaluation.actual
                message = $evaluation.message
            }
            if ($evaluation.status -eq 'failed' -and $evaluation.severity -eq 'required') {
                $status = Get-EdrWorseStatus -Current $status -Candidate 'FAIL'
            }
            elseif ($evaluation.status -eq 'failed' -and $evaluation.severity -eq 'recommended') {
                $status = Get-EdrWorseStatus -Current $status -Candidate 'PARTIAL'
            }
            elseif ($evaluation.status -eq 'not_evaluated' -and $evaluation.severity -eq 'required') {
                $status = Get-EdrWorseStatus -Current $status -Candidate 'INCONCLUSIVE'
            }
        }
    }

    $candidateEntries = @()
    for ($index = 0; $index -lt $displayed.Count; $index++) {
        $candidate = $displayed[$index]
        $candidateMatches = @()
        foreach ($assertion in @($Expectation.assertions)) {
            $actual = $candidate.canonical_event.fields[$assertion.field]
            $candidateMatches += Test-EdrAssertion -Assertion $assertion -Actual $actual -LocalEvent $LocalEvent
        }
        $candidateEntries += [pscustomobject]@{
            rank = $index + 1
            expectation_id = $Expectation.id
            eligible_for_validation = $candidate.qualified
            matched_keys = @($candidate.matched_keys)
            matched_key_count = $candidate.matched_key_count
            required_key_count = $candidate.required_key_count
            time_distance_ms = $candidate.time_distance_ms
            qualification_reason = $candidate.qualification_reason
            raw_ref = $candidate.canonical_event.raw_ref
            mapping_route_id = $candidate.canonical_event.mapping_route_id
            canonical_event = $candidate.canonical_event.fields
            raw_event = $candidate.canonical_event.raw
            baseline_matches = $candidateMatches
        }
    }

    $correlationChecks = @()
    if ($displayed.Count -gt 0) {
        $diagnosticCandidate = if ($selected) { $selected } else { $displayed[0] }
        $correlationChecks = @($diagnosticCandidate.key_results)
    }

    $methodId = if ($Expectation.PSObject.Properties['method'] -and $Expectation.method.PSObject.Properties['id']) { [string]$Expectation.method.id } else { $null }
    $methodTitle = if ($Expectation.PSObject.Properties['method'] -and $Expectation.method.PSObject.Properties['title']) { [string]$Expectation.method.title } else { $null }
    return [pscustomobject]@{
        expectation_id = $Expectation.id
        method_id = $methodId
        method_title = $methodTitle
        event_type = $Expectation.event_type
        event_actions = @($Expectation.event_actions)
        status = $status
        cardinality_status = $cardinalityStatus
        cardinality_expected = [pscustomobject]@{ min = $min; max = $max }
        cardinality_actual = $qualifiedCandidates.Count
        time_difference_ms = $(if ($selected) { $selected.time_distance_ms } else { $null })
        time_status = $(if ($selected) { $timeStatus } else { 'not_evaluated' })
        matched_candidate_raw_ref = $(if ($selected) { $selected.canonical_event.raw_ref } else { $null })
        assertions = $assertions
        requirements = $requirements
        candidates = $candidateEntries
        correlation_checks = $correlationChecks
        warnings = @($warnings)
    }
}

function Compare-EdrOfflineLogs {
    param(
        [Parameter(Mandatory = $true)][string]$LocalLogPath,
        [Parameter(Mandatory = $true)][string[]]$CloudPaths,
        [string]$VendorId,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [string]$BaselineDirectory,
        [string]$CloudManifestPath,
        [int]$StrongCorrelationTimeMs = 0,
        [int]$CandidateTimeLimitMs = 0
    )
    $config = Get-EdrConfig
    if (-not $VendorId) { $VendorId = $config.default_vendor }
    # StrongCorrelationTimeMs / CandidateTimeLimitMs are kept for CLI compatibility but no longer used.
    $maxCandidates = [int]$config.max_displayed_candidates
    $localEvents = Get-EdrLocalEvents -LocalLogPath $LocalLogPath
    $baselines = Import-EdrBaselines -BaselineDirectory $BaselineDirectory

    $cloudEvents = New-Object System.Collections.Generic.List[object]
    foreach ($cloudPath in $CloudPaths) {
        $result = ConvertFrom-EdrVendorLog -InputPath $cloudPath -VendorId $VendorId
        foreach ($event in @($result.events)) { $cloudEvents.Add($event) }
    }
    $cloudEventsArray = $cloudEvents.ToArray()
    $capabilityResults = New-Object System.Collections.Generic.List[object]

    foreach ($localEvent in $localEvents) {
        $scenarioId = $localEvent.scenario_id
        $baseline = Get-EdrBaselineForScenario -ScenarioId $scenarioId
        $warnings = @()
        if (-not $baseline) {
            $capabilityResults.Add([pscustomobject]@{
                case_run_id = "$($localEvent.run_id):$scenarioId"
                capability_id = $scenarioId
                display_name_zh = $localEvent.scenario
                local_status = $localEvent.status
                validation_status = 'NOT_COMPARED'
                export_coverage = 'insufficient'
                candidate_count = 0
                local_export_block = $localEvent
                local_baseline_matches = @()
                expectations = @()
                baseline_requirements = @()
                assertions = @()
                edr_candidates = @()
                warnings = @('没有匹配的 BASELINE。')
            })
            continue
        }

        $overallStatus = 'PASS'
        $requirements = @()
        $localMatches = @()
        foreach ($requirement in @($baseline.local_requirements)) {
            $evaluation = Test-EdrLocalRequirement -Requirement $requirement -LocalEvent $localEvent
            $localMatches += $evaluation
            $requirements += [pscustomobject]@{
                requirement_id = "local-$(@($baseline.local_requirements).IndexOf($requirement) + 1)"
                scope = 'local'
                field = $evaluation.field
                operator = $evaluation.operator
                severity = $evaluation.severity
                status = $evaluation.status
                expected = $evaluation.expected
                actual = $evaluation.actual
                message = $evaluation.message
            }
            if ($evaluation.status -eq 'failed') {
                $warnings += "本地前置断言未通过：$($evaluation.field)"
                $overallStatus = Get-EdrWorseStatus -Current $overallStatus -Candidate 'INCONCLUSIVE'
            }
        }
        if ($localEvent.status -ne 'SUCCESS') {
            $warnings += '本地能力未达到 SUCCESS；最终结论至少为无法判定。'
            $overallStatus = Get-EdrWorseStatus -Current $overallStatus -Candidate 'INCONCLUSIVE'
        }

        $defaultCorrelationTime = ConvertTo-EdrDateTime -Value $localEvent.triggered_at_utc
        if (-not $defaultCorrelationTime) { $defaultCorrelationTime = ConvertTo-EdrDateTime -Value $localEvent.observed_at_utc }
        if (-not $defaultCorrelationTime) { $defaultCorrelationTime = [DateTimeOffset]::UtcNow }
        $coverage = Get-EdrExportCoverage -LocalEvent $localEvent -CloudEvents $cloudEventsArray -CloudManifestPath $CloudManifestPath

        $expectationResults = @()
        foreach ($expectation in @($baseline.cloud_expectations)) {
            $expectationResults += Get-EdrExpectationResult -Expectation $expectation -Baseline $baseline `
                -LocalEvent $localEvent -CloudEvents $cloudEventsArray -ExportCoverage $coverage `
                -MaxDisplayedCandidates $maxCandidates -DefaultCorrelationTime $defaultCorrelationTime
        }

        $strategy = if ($baseline.PSObject.Properties['method_selection'] -and $baseline.method_selection.strategy) {
            [string]$baseline.method_selection.strategy
        }
        else {
            'best'
        }
        if ($strategy -eq 'all') {
            $combined = 'PASS'
            foreach ($result in @($expectationResults)) {
                $combined = Get-EdrWorseStatus -Current $combined -Candidate $result.status
            }
            $overallStatus = Get-EdrWorseStatus -Current $overallStatus -Candidate $combined
        }
        else {
            $best = $null
            foreach ($result in @($expectationResults)) {
                if (-not $best) {
                    $best = $result
                    continue
                }
                if ((Get-EdrStatusRank -Status $result.status) -lt (Get-EdrStatusRank -Status $best.status)) {
                    $best = $result
                }
                elseif ((Get-EdrStatusRank -Status $result.status) -eq (Get-EdrStatusRank -Status $best.status) -and
                    $result.time_difference_ms -and $best.time_difference_ms -and
                    $result.time_difference_ms -lt $best.time_difference_ms) {
                    $best = $result
                }
            }
            if ($best) {
                $overallStatus = Get-EdrWorseStatus -Current $overallStatus -Candidate $best.status
            }
            else {
                $overallStatus = Get-EdrWorseStatus -Current $overallStatus -Candidate 'INCONCLUSIVE'
            }
        }

        $allAssertions = @()
        $allRequirements = @($requirements)
        $allCandidates = @()
        foreach ($result in @($expectationResults)) {
            $allAssertions += @($result.assertions)
            $allRequirements += @($result.requirements)
            $allCandidates += @($result.candidates)
        }
        $allCandidates = @($allCandidates | Sort-Object -Property `
            @{ Expression = { $_.eligible_for_validation }; Descending = $true },
            @{ Expression = { $_.time_distance_ms }; Ascending = $true },
            @{ Expression = { $_.raw_ref }; Ascending = $true })

        $capabilityResults.Add([pscustomobject]@{
            case_run_id = "$($localEvent.run_id):$scenarioId"
            capability_id = $scenarioId
            display_name_zh = $localEvent.scenario
            local_status = $localEvent.status
            validation_status = $overallStatus
            export_coverage = $coverage
            candidate_count = $allCandidates.Count
            local_export_block = $localEvent
            local_baseline_matches = $localMatches
            expectations = $expectationResults
            assertions = $allAssertions
            baseline_requirements = $allRequirements
            edr_candidates = $allCandidates
            warnings = $warnings
        })
    }

    $statuses = @($capabilityResults | ForEach-Object { $_.validation_status })
    $pass = @($statuses | Where-Object { $_ -eq 'PASS' }).Count
    $partial = @($statuses | Where-Object { $_ -eq 'PARTIAL' }).Count
    $fail = @($statuses | Where-Object { $_ -eq 'FAIL' }).Count
    $inconclusive = @($statuses | Where-Object { $_ -eq 'INCONCLUSIVE' }).Count
    $notCompared = @($statuses | Where-Object { $_ -eq 'NOT_COMPARED' }).Count
    $compared = $pass + $partial + $fail + $inconclusive
    $total = $compared + $notCompared
    $verdict = if ($fail -gt 0) {
        'FAIL'
    }
    elseif ($inconclusive -gt 0 -or $notCompared -gt 0 -or $compared -eq 0) {
        'INCONCLUSIVE'
    }
    elseif ($partial -gt 0) {
        'PARTIAL'
    }
    else {
        'PASS'
    }
    $label = switch ($verdict) {
        'PASS' { '全部能力满足验证基准' }
        'PARTIAL' { '部分能力仅满足部分基准' }
        'FAIL' { '发现 EDR 遥测能力缺口' }
        default { '当前证据不足以形成完整结论' }
    }
    $statement = "本轮共纳入 $total 项本地能力，其中 $compared 项完成比较：$pass 项通过、$partial 项部分通过、$fail 项失败、$inconclusive 项无法判定；另有 $notCompared 项未比较。总体结论：$label。"

    $allAssertions = @($capabilityResults | ForEach-Object { $_.assertions })
    $passedAssertions = @($allAssertions | Where-Object { $_.status -eq 'passed' }).Count
    $evaluatedAssertions = @($allAssertions | Where-Object { $_.status -in @('passed', 'failed') }).Count
    $summary = [pscustomobject]@{
        pass = $pass
        partial = $partial
        fail = $fail
        inconclusive = $inconclusive
        not_compared = $notCompared
        event_coverage = if ($compared -gt 0) { [Math]::Round((($pass + $partial) / $compared), 4) } else { $null }
        field_completeness = if ($evaluatedAssertions -gt 0) { [Math]::Round(($passedAssertions / $evaluatedAssertions), 4) } else { $null }
        determinacy = if ($compared -gt 0) { [Math]::Round((($pass + $partial + $fail) / $compared), 4) } else { $null }
    }
    $conclusion = [pscustomobject]@{
        verdict = $verdict
        label_zh = $label
        statement_zh = $statement
        total_capabilities = $total
        compared_capabilities = $compared
        pass_rate = if ($compared -gt 0) { [Math]::Round(($pass / $compared), 4) } else { $null }
        passed_capability_ids = @($capabilityResults | Where-Object { $_.validation_status -eq 'PASS' } | ForEach-Object { $_.capability_id })
        gap_capability_ids = @($capabilityResults | Where-Object { $_.validation_status -eq 'FAIL' } | ForEach-Object { $_.capability_id })
        uncertain_capability_ids = @($capabilityResults | Where-Object { $_.validation_status -in @('PARTIAL', 'INCONCLUSIVE', 'NOT_COMPARED') } | ForEach-Object { $_.capability_id })
    }
    $root = [pscustomobject]@{
        schema_version = '2.0'
        comparison_id = New-EdrRunId
        compared_at_utc = Get-EdrUtcTimestamp
        inputs = [pscustomobject]@{
            local_log = [System.IO.Path]::GetFullPath($LocalLogPath)
            cloud_exports = @($CloudPaths | ForEach-Object { [System.IO.Path]::GetFullPath($_) })
            vendor_id = $VendorId
            baseline_directory = [System.IO.Path]::GetFullPath($(if ($BaselineDirectory) { $BaselineDirectory } else { Join-Path (Get-EdrProjectRoot) 'baselines' }))
            correlation_mode = 'deterministic_keys'
        }
        summary = $summary
        conclusion = $conclusion
        capabilities = $capabilityResults.ToArray()
    }
    Export-EdrJson -Path $OutputPath -Value $root
    $conclusionPath = $OutputPath -replace '\.json$', '-conclusion.md'
    $markdown = New-EdrConclusionMarkdown -Result $root
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($conclusionPath, $markdown, $utf8NoBom)
    return $root
}

function New-EdrConclusionMarkdown {
    param([Parameter(Mandatory = $true)]$Result)
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.AppendLine('# EDR 遥测离线比对结论')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine("- 比较编号：``$($Result.comparison_id)``")
    [void]$builder.AppendLine("- 比较时间（北京时间 +08:00）：``$($Result.compared_at_utc)``")
    [void]$builder.AppendLine("- 关联模式：确定性字段键匹配（无锚点评分）")
    [void]$builder.AppendLine("- 总体判定：**$($Result.conclusion.label_zh)（$($Result.conclusion.verdict)）**")
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('## 总体结论')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine($Result.conclusion.statement_zh)
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('## 汇总')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('| 通过 | 部分通过 | 失败 | 无法判定 | 未比较 |')
    [void]$builder.AppendLine('| ---: | ---: | ---: | ---: | ---: |')
    [void]$builder.AppendLine("| $($Result.summary.pass) | $($Result.summary.partial) | $($Result.summary.fail) | $($Result.summary.inconclusive) | $($Result.summary.not_compared) |")
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('## 能力明细')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('| 能力 | 本地执行 | EDR 验证 | 导出覆盖 | 判定说明 |')
    [void]$builder.AppendLine('| --- | --- | --- | --- | --- |')
    foreach ($capability in @($Result.capabilities)) {
        $statusLabel = switch ($capability.validation_status) {
            'PASS' { '通过' }
            'PARTIAL' { '部分通过' }
            'FAIL' { '失败' }
            'INCONCLUSIVE' { '无法判定' }
            default { '未比较' }
        }
        $coverageLabel = switch ($capability.export_coverage) {
            'verified' { '已由清单验证' }
            'inferred' { '由日志时间推断' }
            'insufficient' { '证据不足' }
            default { $capability.export_coverage }
        }
        $detail = if (@($capability.warnings).Count -gt 0) {
            (@($capability.warnings) -join '；')
        }
        elseif ($capability.validation_status -eq 'PASS') {
            '满足该能力检验基准。'
        }
        else {
            '未满足全部检验基准。'
        }
        [void]$builder.AppendLine("| $($capability.display_name_zh) | $($capability.local_status) | $statusLabel | $coverageLabel | $detail |")
    }
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('## 验证明细')
    [void]$builder.AppendLine()
    foreach ($capability in @($Result.capabilities)) {
        [void]$builder.AppendLine("### $($capability.display_name_zh)")
        [void]$builder.AppendLine()
        if (@($capability.local_baseline_matches).Count -gt 0) {
            [void]$builder.AppendLine('**本地前置断言**')
            [void]$builder.AppendLine()
            foreach ($localMatch in @($capability.local_baseline_matches)) {
                $localStatusLabel = switch ($localMatch.status) {
                    'passed' { '通过' }
                    'failed' { '不通过' }
                    default { '未评估' }
                }
                [void]$builder.AppendLine("- ``$($localMatch.field)`` ``$($localMatch.operator)`` [$($localMatch.severity)]：$localStatusLabel；期望 ``$($localMatch.expected)``，实际 ``$($localMatch.actual)``")
            }
            [void]$builder.AppendLine()
        }
        if (@($capability.expectations).Count -eq 0) {
            [void]$builder.AppendLine('- 未匹配到云端期望。')
            [void]$builder.AppendLine()
            continue
        }
        foreach ($expectation in @($capability.expectations)) {
            $label = if ($expectation.method_title) { $expectation.method_title } else { $expectation.expectation_id }
            $matched = if ($expectation.matched_candidate_raw_ref) { "命中：``$($expectation.matched_candidate_raw_ref)``" } else { '未命中候选事件' }
            [void]$builder.AppendLine("- $label（$($expectation.event_type)/$($expectation.event_actions -join ',')）：$($expectation.status)；$matched")
            foreach ($check in @($expectation.correlation_checks)) {
                if ($check.matched) { continue }
                $checkLocal = if ($null -eq $check.local_value) { '空' } else { [string]$check.local_value }
                $checkCloud = if ($null -eq $check.cloud_value) { '空' } else { [string]$check.cloud_value }
                if ($checkLocal.Length -gt 120) { $checkLocal = $checkLocal.Substring(0, 117) + '...' }
                if ($checkCloud.Length -gt 120) { $checkCloud = $checkCloud.Substring(0, 117) + '...' }
                [void]$builder.AppendLine("  - 关联键未匹配：``$($check.local_field)`` -> ``$($check.cloud_field)``；本地 ``$checkLocal``，云端 ``$checkCloud``")
            }
            foreach ($assertion in @($expectation.assertions)) {
                $assertStatusLabel = switch ($assertion.status) {
                    'passed' { '通过' }
                    'failed' { '不通过' }
                    default { '未评估' }
                }
                $expectedText = if ($null -eq $assertion.expected) { '空' } else { [string]$assertion.expected }
                $actualText = if ($null -eq $assertion.actual) { '空' } else { [string]$assertion.actual }
                if ($expectedText.Length -gt 180) { $expectedText = $expectedText.Substring(0, 177) + '...' }
                if ($actualText.Length -gt 180) { $actualText = $actualText.Substring(0, 177) + '...' }
                [void]$builder.AppendLine("  - ``$($assertion.field)`` ``$($assertion.operator)`` [$($assertion.severity)]：$assertStatusLabel；期望 ``$expectedText``，实际 ``$actualText``")
            }
        }
        [void]$builder.AppendLine()
    }
    [void]$builder.AppendLine('> 结论仅适用于本次本地运行窗口、用户导入的 EDR 日志范围以及当前基线与映射配置。')
    return $builder.ToString()
}
