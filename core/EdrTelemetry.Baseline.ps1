#Requires -Version 5.1
Set-StrictMode -Version 2.0

if (-not (Get-Command 'Initialize-EdrContext' -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'EdrTelemetry.Common.ps1')
}

$script:EdrBaselines = $null

function Import-EdrBaselines {
    param(
        [string]$BaselineDirectory
    )
    if (-not $BaselineDirectory) {
        $BaselineDirectory = Join-Path (Get-EdrProjectRoot) 'baselines'
    }
    $files = @(Get-ChildItem -LiteralPath $BaselineDirectory -Filter '*.baseline.json' -Recurse -ErrorAction SilentlyContinue)
    $baselines = @()
    foreach ($file in $files) {
        $root = Read-EdrJson -Path $file.FullName
        foreach ($entry in @($root.baselines)) {
            if ($entry) { $baselines += $entry }
        }
    }
    $script:EdrBaselines = @($baselines)
    return $script:EdrBaselines
}

function Get-EdrBaselineDefinitions {
    if (-not $script:EdrBaselines) {
        Import-EdrBaselines
    }
    return $script:EdrBaselines
}

function Get-EdrBaselineForScenario {
    param([Parameter(Mandatory = $true)][string]$ScenarioId)
    $match = Get-EdrBaselineDefinitions | Where-Object { $_.capability.id -eq $ScenarioId }
    if (@($match).Count -gt 1) { throw "场景 $ScenarioId 存在多份基线。" }
    return @($match)[0]
}

function Resolve-EdrLocalValue {
    param(
        [Parameter(Mandatory = $true)]$LocalEvent,
        [Parameter(Mandatory = $true)][string]$Field
    )
    if ($Field -eq 'nonce') { return $LocalEvent.nonce }
    if ($Field -eq 'operation') { return $LocalEvent.operation }
    if ($Field -eq 'status') { return $LocalEvent.status }
    if ($Field -eq 'event_type') { return $LocalEvent.event_type }
    if ($Field -eq 'event_action') { return $LocalEvent.event_action }
    if ($Field -eq 'triggered_at_utc') { return $LocalEvent.triggered_at_utc }
    if ($Field -eq 'observed_at_utc') { return $LocalEvent.observed_at_utc }
    if ($Field -eq 'threat_level') { return $LocalEvent.threat_level }
    if ($Field.StartsWith('data.')) {
        return Get-EdrJsonValue -Object $LocalEvent.data -Path $Field.Substring(5)
    }
    if ($Field.StartsWith('process.')) {
        return Get-EdrJsonValue -Object $LocalEvent.process -Path $Field.Substring(8)
    }
    return Get-EdrJsonValue -Object $LocalEvent -Path $Field
}

function Normalize-EdrValue {
    param(
        [AllowNull()]$Value,
        [string[]]$Normalizers = @()
    )
    foreach ($normalizer in $Normalizers) {
        if ($null -eq $Value) { break }
        $Value = switch ($normalizer) {
            'lowercase' { ([string]$Value).ToLowerInvariant() }
            'trim' { ([string]$Value).Trim() }
            'windows_path' {
                ([string]$Value).Trim().Replace('/', '\').TrimEnd('\').ToLowerInvariant()
            }
            'registry_hive_path' {
                $text = ([string]$Value).Trim().Replace('/', '\').TrimEnd('\').ToLowerInvariant()
                $text = $text -replace '^hkcu:\\', 'hkey_current_user\'
                $text = $text -replace '^hklm:\\', 'hkey_local_machine\'
                $text = $text -replace '^hkcr:\\', 'hkey_classes_root\'
                $text = $text -replace '^hkcc:\\', 'hkey_current_config\'
                $text = $text -replace '^hkey_current_user\\', 'hkey_current_user\'
                $text = $text -replace '^hkey_local_machine\\', 'hkey_local_machine\'
                $text = $text -replace '^hkey_classes_root\\', 'hkey_classes_root\'
                $text = $text -replace '^hkey_current_config\\', 'hkey_current_config\'
                $text = $text -replace '^\\registry\\machine\\', 'hkey_local_machine\'
                $text = $text -replace '^\\registry\\user\\', 'hkey_current_user\'
                $text = $text -replace '^hkey_users\\s-1-5-21-(?:\d+-){3}\d+\\', 'hkey_current_user\'
                $text = $text -replace '^hkcu\\', 'hkey_current_user\'
                $text = $text -replace '^hklm\\', 'hkey_local_machine\'
                $text = $text -replace '^hkcr\\', 'hkey_classes_root\'
                $text = $text -replace '^hkcc\\', 'hkey_current_config\'
                $text
            }
            'named_pipe_path' {
                $text = ([string]$Value).Trim().Replace('/', '\').TrimEnd('\').ToLowerInvariant()
                if ($text -eq '\' -or $text -eq '\\.\pipe\') { $null } else { $text }
            }
            'sid' { ([string]$Value).Trim().ToUpperInvariant() }
            'ip' { ([string]$Value).Trim().ToLowerInvariant() }
            'timestamp_utc' {
                $parsed = [DateTimeOffset]::MinValue
                if ([DateTimeOffset]::TryParse(([string]$Value), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
                    $parsed.ToUniversalTime().ToString('o')
                }
                else { $Value }
            }
            default { $Value }
        }
    }
    return $Value
}

function Test-EdrEquivalent {
    param(
        [AllowNull()]$Left,
        [AllowNull()]$Right
    )
    if ($null -eq $Left -or $null -eq $Right) { return $null -eq $Left -and $null -eq $Right }
    $leftText = [string]$Left
    $rightText = [string]$Right
    $leftNumber = [decimal]0
    $rightNumber = [decimal]0
    if ([decimal]::TryParse($leftText, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$leftNumber) -and
        [decimal]::TryParse($rightText, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$rightNumber)) {
        return $leftNumber -eq $rightNumber
    }
    return [string]::Equals($leftText, $rightText, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-EdrOperator {
    param(
        [Parameter(Mandatory = $true)][string]$Operator,
        [AllowNull()]$Actual,
        [AllowNull()]$Expected
    )
    switch ($Operator) {
        'present' {
            return $null -ne $Actual -and -not ([string]$Actual -eq '')
        }
        'absent' {
            return $null -eq $Actual -or ([string]$Actual -eq '')
        }
        'equals' {
            return Test-EdrEquivalent -Left $Actual -Right $Expected
        }
        'not_equals' {
            return -not (Test-EdrEquivalent -Left $Actual -Right $Expected)
        }
        'ref_equals' {
            return Test-EdrEquivalent -Left $Actual -Right $Expected
        }
        'contains' {
            if ($null -eq $Actual -or $null -eq $Expected) { return $false }
            return ([string]$Actual).IndexOf([string]$Expected, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
        }
        'regex' {
            if ($null -eq $Actual -or $null -eq $Expected) { return $null }
            try {
                return [regex]::IsMatch([string]$Actual, [string]$Expected, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            }
            catch {
                return $null
            }
        }
        'one_of' {
            if ($null -eq $Expected) { return $false }
            $values = @($Expected)
            foreach ($value in $values) {
                if (Test-EdrEquivalent -Left $Actual -Right $value) { return $true }
            }
            return $false
        }
        'range' {
            if ($null -eq $Actual -or $null -eq $Expected) { return $null }
            $actualNumber = [decimal]0
            if (-not [decimal]::TryParse(([string]$Actual), [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$actualNumber)) { return $null }
            $min = $Expected.min
            $max = $Expected.max
            $minNumber = [decimal]0
            $maxNumber = [decimal]0
            if ($null -eq $min -or $null -eq $max) { return $null }
            [void][decimal]::TryParse(([string]$min), [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$minNumber)
            [void][decimal]::TryParse(([string]$max), [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$maxNumber)
            return $actualNumber -ge $minNumber -and $actualNumber -le $maxNumber
        }
        'cidr' {
            if ($null -eq $Actual -or $null -eq $Expected) { return $null }
            $addressText = [string]$Actual
            $cidr = [string]$Expected
            $address = [System.Net.IPAddress]::MinValue
            if (-not [System.Net.IPAddress]::TryParse($addressText, [ref]$address)) { return $null }
            $parts = $cidr.Split('/')
            if ($parts.Count -ne 2) { return $null }
            $network = [System.Net.IPAddress]::MinValue
            $prefix = 0
            if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$network)) { return $null }
            if (-not [int]::TryParse($parts[1], [ref]$prefix)) { return $null }
            $addressBytes = $address.GetAddressBytes()
            $networkBytes = $network.GetAddressBytes()
            if ($addressBytes.Length -ne $networkBytes.Length -or $prefix -lt 0 -or $prefix -gt $addressBytes.Length * 8) { return $false }
            for ($i = 0; $i -lt $addressBytes.Length; $i++) {
                $bits = [Math]::Max(0, [Math]::Min(8, $prefix - $i * 8))
                if ($bits -eq 0) { break }
                $mask = [byte](0xFF -shl (8 - $bits))
                if (($addressBytes[$i] -band $mask) -ne ($networkBytes[$i] -band $mask)) { return $false }
            }
            return $true
        }
        'timestamp_between' {
            if ($null -eq $Actual -or $null -eq $Expected) { return $null }
            $timestamp = [DateTimeOffset]::MinValue
            if (-not [DateTimeOffset]::TryParse(([string]$Actual), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$timestamp)) { return $null }
            $start = [DateTimeOffset]::MinValue
            $end = [DateTimeOffset]::MinValue
            if (-not [DateTimeOffset]::TryParse(([string]$Expected.start), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$start)) { return $null }
            if (-not [DateTimeOffset]::TryParse(([string]$Expected.end), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$end)) { return $null }
            return $timestamp -ge $start -and $timestamp -le $end
        }
        default {
            return $null
        }
    }
}

function Test-EdrAssertion {
    param(
        [Parameter(Mandatory = $true)]$Assertion,
        [AllowNull()]$Actual,
        [Parameter(Mandatory = $true)]$LocalEvent
    )
    $expected = $Assertion.expected
    if ($Assertion.PSObject.Properties['expected_from_local'] -and -not [string]::IsNullOrWhiteSpace([string]$Assertion.expected_from_local)) {
        $expected = Resolve-EdrLocalValue -LocalEvent $LocalEvent -Field $Assertion.expected_from_local
        if ($null -eq $expected) {
            return [pscustomobject]@{
                field = $Assertion.field
                operator = $Assertion.operator
                severity = $Assertion.severity
                status = 'not_evaluated'
                expected = $null
                actual = $Actual
                message = "本地未采集 $($Assertion.expected_from_local)，无法形成期望值。"
            }
        }
    }
    if ($expected -is [string]) {
        if ([string]::IsNullOrWhiteSpace($expected)) {
            $expected = $null
        }
        else {
            $expected = Expand-EdrTemplate -Template $expected -Nonce $LocalEvent.nonce
        }
    }
    $normalizers = @()
    if ($Assertion.PSObject.Properties['normalizers']) { $normalizers = @($Assertion.normalizers) }
    $normalizedActual = Normalize-EdrValue -Value $Actual -Normalizers $normalizers
    $normalizedExpected = Normalize-EdrValue -Value $expected -Normalizers $normalizers
    $passed = Test-EdrOperator -Operator $Assertion.operator -Actual $normalizedActual -Expected $normalizedExpected
    if (-not $passed -and $Assertion.PSObject.Properties['accepted_values'] -and $null -ne $Assertion.accepted_values -and @($Assertion.accepted_values).Count -gt 0) {
        $acceptedMatched = $false
        foreach ($accepted in @($Assertion.accepted_values)) {
            $normalizedAccepted = Normalize-EdrValue -Value $accepted.value -Normalizers $normalizers
            if (Test-EdrEquivalent -Left $normalizedActual -Right $normalizedAccepted) {
                $acceptedMatched = $true
                break
            }
        }
        if ($acceptedMatched) { $passed = $true }
    }
    $status = if ($null -eq $passed) { 'not_evaluated' } elseif ($passed) { 'passed' } else { 'failed' }
    $message = if ($status -eq 'passed') { '满足断言。' } else { "断言未满足：$($Assertion.field) $($Assertion.operator)" }
    return [pscustomobject]@{
        field = $Assertion.field
        operator = $Assertion.operator
        severity = $Assertion.severity
        status = $status
        expected = $expected
        actual = $Actual
        message = $message
    }
}

function Test-EdrLocalRequirement {
    param(
        [Parameter(Mandatory = $true)]$Requirement,
        [Parameter(Mandatory = $true)]$LocalEvent
    )
    $actual = Resolve-EdrLocalValue -LocalEvent $LocalEvent -Field $Requirement.field
    return Test-EdrAssertion -Assertion $Requirement -Actual $actual -LocalEvent $LocalEvent
}
