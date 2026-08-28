#Requires -Version 5.1
Set-StrictMode -Version 2.0

if (-not (Get-Command 'Initialize-EdrContext' -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'EdrTelemetry.Common.ps1')
}

$script:EdrVendorMappings = $null

function Get-EdrVendorMappings {
    if (-not $script:EdrVendorMappings) {
        $path = Join-Path (Get-EdrProjectRoot) 'config\vendors.json'
        $script:EdrVendorMappings = Read-EdrJson -Path $path
    }
    return $script:EdrVendorMappings
}

function Get-EdrVendorMapping {
    param([Parameter(Mandatory = $true)][string]$VendorId)
    $mappings = Get-EdrVendorMappings
    $vendor = $mappings.vendors.($VendorId)
    if (-not $vendor) { throw "未知厂商：$VendorId。可用厂商：$($mappings.vendors.PSObject.Properties.Name -join '、')" }
    return $vendor
}

function Get-EdrVendorIds {
    return @((Get-EdrVendorMappings).vendors.PSObject.Properties.Name)
}

function ConvertFrom-EdrVendorValue {
    param(
        [AllowNull()]$Value,
        [string[]]$Transforms = @()
    )
    foreach ($transform in $Transforms) {
        if ($null -eq $Value) { break }
        if ($transform -eq 'lowercase') {
            $Value = ([string]$Value).ToLowerInvariant()
        }
        elseif ($transform -eq 'trim') {
            $Value = ([string]$Value).Trim()
        }
        elseif ($transform -eq 'windows_path') {
            $text = ([string]$Value).Trim().Replace('/', '\').TrimEnd('\')
            $Value = $text.ToLowerInvariant()
        }
        elseif ($transform -eq 'registry_hive_path') {
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
            $Value = $text
        }
        elseif ($transform -eq 'named_pipe_path') {
            $text = ([string]$Value).Trim().Replace('/', '\').TrimEnd('\').ToLowerInvariant()
            if ($text -eq '\' -or $text -eq '\\.\pipe\') { $Value = $null }
            else { $Value = $text }
        }
        elseif ($transform -eq 'http_method') {
            $text = ([string]$Value).Trim().ToUpperInvariant()
            if ($text -match '\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\b') {
                $Value = $Matches[1]
            }
            else {
                $Value = $text
            }
        }
        elseif ($transform -eq 'signed_int64_to_hex') {
            $number = [long]0
            if ([long]::TryParse(([string]$Value), [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$number)) {
                $Value = '0x{0:X}' -f ([long]$number)
            }
        }
        elseif ($transform -eq 'network_direction') {
            $lower = ([string]$Value).Trim().ToLowerInvariant()
            if ($lower -in @('出站', 'outbound', 'egress')) {
                $Value = 'outbound'
            }
            elseif ($lower -in @('入站', 'inbound', 'ingress')) {
                $Value = 'inbound'
            }
            else {
                $Value = $lower
            }
        }
        elseif ($transform -eq 'unix_ms_to_utc') {
            $ms = [long]0
            if ([long]::TryParse(([string]$Value), [ref]$ms)) {
                $Value = ([DateTimeOffset]::FromUnixTimeMilliseconds($ms)).ToString('o')
            }
        }
        elseif ($transform -eq 'unix_s_to_utc') {
            $seconds = [long]0
            if ([long]::TryParse(([string]$Value), [ref]$seconds)) {
                $Value = ([DateTimeOffset]::FromUnixTimeSeconds($seconds)).ToString('o')
            }
        }
        elseif ($transform -eq 'parse_datetime_to_utc') {
            if ($Value -is [datetimeoffset]) {
                $Value = $Value.ToUniversalTime().ToString('o')
            }
            elseif ($Value -is [datetime]) {
                $Value = [DateTimeOffset]::new($Value).ToUniversalTime().ToString('o')
            }
            else {
                $parsed = [DateTimeOffset]::MinValue
                if ([DateTimeOffset]::TryParse(([string]$Value), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
                    $Value = $parsed.ToUniversalTime().ToString('o')
                }
            }
        }
    }
    return $Value
}

function Get-EdrRawFieldValue {
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Record,
        [Parameter(Mandatory = $true)][string]$Field
    )
    if ($null -eq $Record) { return $null }
    if ($Record.PSObject.Properties[$Field]) {
        return $Record.($Field)
    }
    $current = $Record
    foreach ($segment in $Field.Split('.')) {
        if ($null -eq $current) { return $null }
        if ($current -is [System.Management.Automation.PSCustomObject]) {
            $property = $current.PSObject.Properties[$segment]
            if (-not $property) { return $null }
            $current = $property.Value
        }
        elseif ($current -is [System.Collections.IDictionary]) {
            if (-not $current.Contains($segment)) { return $null }
            $current = $current[$segment]
        }
        else { return $null }
    }
    return $current
}

function Test-EdrConditionValue {
    param(
        [AllowNull()]$Actual,
        [AllowNull()]$Expected
    )
    if ($Expected -is [System.Management.Automation.PSCustomObject] -and $Expected.PSObject.Properties['any']) {
        return $true
    }
    if ($Expected -is [System.Array]) {
        foreach ($candidate in $Expected) {
            if (Test-EdrConditionValue -Actual $Actual -Expected $candidate) { return $true }
        }
        return $false
    }
    if ($null -eq $Actual -or $null -eq $Expected) {
        return $null -eq $Actual -and $null -eq $Expected
    }
    return [string]::Equals([string]$Actual, [string]$Expected, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-EdrRecordSelector {
    param(
        [Parameter(Mandatory = $true)]$Record,
        $Selector
    )
    if ($null -eq $Selector -or $null -eq $Selector.PSObject.Properties['all']) { return $true }
    foreach ($property in $Selector.all.PSObject.Properties) {
        $actual = Get-EdrRawFieldValue -Record $Record -Field $property.Name
        if (-not (Test-EdrConditionValue -Actual $actual -Expected $property.Value)) { return $false }
    }
    return $true
}

function ConvertFrom-EdrVendorRecord {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)][string]$RawRef,
        [Parameter(Mandatory = $true)]$Mapping,
        [AllowNull()]$InputDefinition
    )
    if (-not (Test-EdrRecordSelector -Record $Record -Selector $InputDefinition.record_selector)) {
        return $null
    }
    $fields = @{}
    $sourceFields = @{}
    $matchedRoute = $null
    foreach ($route in $Mapping.routes) {
        $routeMatched = $true
        foreach ($property in $route.when.PSObject.Properties) {
            $actual = Get-EdrRawFieldValue -Record $Record -Field $property.Name
            if (-not (Test-EdrConditionValue -Actual $actual -Expected $property.Value)) {
                $routeMatched = $false
                break
            }
        }
        if ($routeMatched) {
            $matchedRoute = $route
            break
        }
    }
    if (-not $matchedRoute) { return $null }

    foreach ($property in $matchedRoute.canonical.PSObject.Properties) {
        $rule = $property.Value
        $value = $null
        $selectedSource = $null
        try {
            if ($rule.PSObject.Properties['constant']) {
                $value = $rule.constant
            }
            else {
                $sources = @()
                if ($rule.PSObject.Properties['sources']) { $sources = @($rule.sources) }
                elseif ($rule.PSObject.Properties['source']) { $sources = @($rule.source) }
                foreach ($source in $sources) {
                    $candidate = Get-EdrRawFieldValue -Record $Record -Field $source
                    if ($null -ne $candidate -and [string]$candidate -ne '') {
                        $value = $candidate
                        $selectedSource = $source
                        break
                    }
                }
            }
            if ($rule.PSObject.Properties['on_empty'] -and ($null -eq $value -or [string]$value -eq '')) {
                $value = $rule.on_empty
            }
            if ($rule.PSObject.Properties['on_zero'] -and $null -ne $value -and ([string]$value) -eq '0') {
                $value = $rule.on_zero
            }
            $transforms = @()
            if ($rule.PSObject.Properties['transform']) { $transforms = @($rule.transform) }
            $value = ConvertFrom-EdrVendorValue -Value $value -Transforms $transforms
        }
        catch {
            if ($rule.PSObject.Properties['on_error']) { $value = $rule.on_error }
        }
        $fields[$property.Name] = $value
        $sourceFields[$property.Name] = $selectedSource
    }

    $eventTime = $null
    if ($InputDefinition.event_time) {
        $rawTime = Get-EdrRawFieldValue -Record $Record -Field $InputDefinition.event_time.field
        $format = [string]$InputDefinition.event_time.format
        if ($format -eq 'unix_ms') {
            $ms = [long]0
            if ([long]::TryParse(([string]$rawTime), [ref]$ms)) {
                $eventTime = [DateTimeOffset]::FromUnixTimeMilliseconds($ms)
            }
        }
        elseif ($format -eq 'unix_s') {
            $seconds = [long]0
            if ([long]::TryParse(([string]$rawTime), [ref]$seconds)) {
                $eventTime = [DateTimeOffset]::FromUnixTimeSeconds($seconds)
            }
        }
        elseif ($format -eq 'iso8601') {
            if ($rawTime -is [datetime]) {
                $eventTime = [DateTimeOffset]::new($rawTime).ToUniversalTime()
            }
            else {
                $parsed = [DateTimeOffset]::MinValue
                if ([DateTimeOffset]::TryParse(([string]$rawTime), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
                    $eventTime = $parsed
                }
            }
        }
    }
    $eventId = Get-EdrRawFieldValue -Record $Record -Field $InputDefinition.event_id_field
    $hostId = Get-EdrRawFieldValue -Record $Record -Field $InputDefinition.host_id_field
    $hostName = Get-EdrRawFieldValue -Record $Record -Field $InputDefinition.host_name_field
    return [pscustomobject]@{
        raw_ref = $RawRef
        fields = $fields
        source_fields = $sourceFields
        raw = $Record
        mapping_route_id = $matchedRoute.route_id
        event_time = $eventTime
        event_id = $(if ($null -ne $eventId) { [string]$eventId } else { $null })
        host_id = $(if ($null -ne $hostId) { [string]$hostId } else { $null })
        host_name = $(if ($null -ne $hostName) { [string]$hostName } else { $null })
    }
}

function ConvertFrom-EdrVendorLog {
    param(
        [Parameter(Mandatory = $true)][string]$InputPath,
        [Parameter(Mandatory = $true)][string]$VendorId,
        [AllowNull()]$Mapping
    )
    if (-not (Test-Path -LiteralPath $InputPath)) { throw "找不到厂商日志：$InputPath" }
    if (-not $Mapping) { $Mapping = Get-EdrVendorMapping -VendorId $VendorId }
    $inputDefinition = $Mapping.input
    $events = New-Object System.Collections.Generic.List[object]
    $text = Get-Content -LiteralPath $InputPath -Raw -Encoding UTF8
    $trimmed = $text.TrimStart()
    if ($trimmed.StartsWith('[')) {
        $array = ConvertFrom-Json -InputObject $text
        for ($index = 0; $index -lt @($array).Count; $index++) {
            $record = @($array)[$index]
            if ($null -eq $record -or $record -isnot [System.Management.Automation.PSCustomObject]) { continue }
            $canonical = ConvertFrom-EdrVendorRecord -Record $record -RawRef "$InputPath#/$index" -Mapping $Mapping -InputDefinition $inputDefinition
            if ($canonical) { $events.Add($canonical) }
        }
    }
    else {
        $index = 0
        foreach ($line in (Get-Content -LiteralPath $InputPath -Encoding UTF8)) {
            if ([string]::IsNullOrWhiteSpace($line)) { $index++; continue }
            $record = ConvertFrom-Json -InputObject $line
            if ($record -is [System.Management.Automation.PSCustomObject]) {
                $canonical = ConvertFrom-EdrVendorRecord -Record $record -RawRef "$InputPath#/$index" -Mapping $Mapping -InputDefinition $inputDefinition
                if ($canonical) { $events.Add($canonical) }
            }
            $index++
        }
    }
    return [pscustomobject]@{
        vendor_id = $VendorId
        input_path = $InputPath
        events = $events.ToArray()
    }
}
