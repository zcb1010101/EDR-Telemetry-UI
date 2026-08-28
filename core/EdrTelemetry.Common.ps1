#Requires -Version 5.1
Set-StrictMode -Version 2.0

$script:EdrProjectRoot = $null
$script:EdrConfig = $null
$script:EdrCatalog = $null
$script:EdrThreatLevels = $null

function Initialize-EdrContext {
    param(
        [string]$ProjectRoot
    )
    if (-not $ProjectRoot) {
        $ProjectRoot = Split-Path -Parent $PSScriptRoot
        if (-not $ProjectRoot) { $ProjectRoot = (Get-Location).Path }
    }
    $script:EdrProjectRoot = [System.IO.Path]::GetFullPath($ProjectRoot)
    $script:EdrConfig = Read-EdrJson (Join-Path $script:EdrProjectRoot 'config\project.json')
    $script:EdrThreatLevels = Read-EdrJson (Join-Path $script:EdrProjectRoot 'config\threat-levels.json')
}

function Get-EdrProjectRoot {
    if (-not $script:EdrProjectRoot) { Initialize-EdrContext }
    return $script:EdrProjectRoot
}

function Get-EdrConfig {
    if (-not $script:EdrConfig) { Initialize-EdrContext }
    return $script:EdrConfig
}

function Read-EdrJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "找不到文件：$Path"
    }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    return ConvertFrom-Json -InputObject $raw
}

function ConvertTo-EdrJson {
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Value,
        [switch]$Compress
    )
    if ($Compress) {
        return ConvertTo-Json -InputObject $Value -Depth 100 -Compress
    }
    return ConvertTo-Json -InputObject $Value -Depth 100
}

function Export-EdrJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowNull()]$Value,
        [switch]$Compress
    )
    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $json = ConvertTo-EdrJson -Value $Value -Compress:$Compress
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
}

function New-EdrRunId {
    return [guid]::NewGuid().ToString('D')
}

function New-EdrNonce {
    $bytes = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    $builder = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) { [void]$builder.Append($b.ToString('x2')) }
    return $builder.ToString()
}

function Get-EdrUtcTimestamp {
    return [DateTimeOffset]::UtcNow.ToOffset([TimeSpan]::FromHours(8)).ToString('o')
}

function Convert-EdrToIso8601 {
    param(
        [Parameter(Mandatory = $true)][DateTime]$Value
    )
    return [DateTimeOffset]::new($Value.ToUniversalTime()).ToString('o')
}

function Test-EdrAdministrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    finally {
        $identity.Dispose()
    }
}

function Get-EdrCurrentProcessInfo {
    $process = Get-Process -Id $PID
    return [pscustomobject]@{
        pid = $PID
        executable = $process.Path
        name = $process.ProcessName
        command_line = (Get-CimInstance Win32_Process -Filter "ProcessId = $PID" -ErrorAction SilentlyContinue).CommandLine
        session_id = $process.SessionId
        start_time = $(if ($process.StartTime) { $process.StartTime.ToUniversalTime().ToString('o') } else { $null })
        user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
}

function New-EdrTempDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$ScenarioId,
        [string]$Nonce
    )
    $root = Join-Path (Get-EdrProjectRoot) 'temp_file'
    $runDir = Join-Path $root $RunId
    $scenarioDir = Join-Path $runDir $ScenarioId
    if ($Nonce) { $scenarioDir = Join-Path $scenarioDir $Nonce }
    New-Item -ItemType Directory -Path $scenarioDir -Force | Out-Null
    return $scenarioDir
}

function Remove-EdrTempDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )
    $full = [System.IO.Path]::GetFullPath($Path)
    $allowedRoot = [System.IO.Path]::GetFullPath((Join-Path (Get-EdrProjectRoot) 'temp_file'))
    if (-not $full.StartsWith($allowedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "拒绝清理非项目临时目录：$full"
    }
    if (Test-Path -LiteralPath $full) {
        Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Write-EdrConsole {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$Color = 'Gray',
        [switch]$NoNewline
    )
    if ($NoNewline) {
        Write-Host -NoNewline $Message -ForegroundColor $Color
    }
    else {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Get-EdrThreatLevelDefinitions {
    if (-not $script:EdrThreatLevels) { Initialize-EdrContext }
    return $script:EdrThreatLevels.levels
}

function Get-EdrThreatLevelLabel {
    param([Parameter(Mandatory = $true)][string]$Level)
    $levels = Get-EdrThreatLevelDefinitions
    if ($null -eq $levels -or -not $levels.PSObject.Properties[$Level]) { return $Level }
    $definition = $levels.($Level)
    return "$Level-$($definition.label_zh)"
}

function Get-EdrScenarioCatalog {
    if (-not $script:EdrCatalog) {
        $csvPath = Join-Path (Get-EdrProjectRoot) 'config\scenario-catalog.csv'
        $raw = Get-Content -LiteralPath $csvPath -Raw -Encoding UTF8
        $script:EdrCatalog = @($raw | ConvertFrom-Csv)
    }
    return $script:EdrCatalog
}

function Get-EdrScenario {
    param(
        [Parameter(Mandatory = $true)][string]$ScenarioId
    )
    $match = Get-EdrScenarioCatalog | Where-Object { $_.ScenarioId -eq $ScenarioId }
    if (-not $match) { throw "未知场景：$ScenarioId" }
    return $match
}

function Get-EdrScenarioCategories {
    return @(Get-EdrScenarioCatalog | Select-Object -ExpandProperty Category -Unique)
}

function Get-EdrScenarioScriptPath {
    param(
        [Parameter(Mandatory = $true)]$Scenario
    )
    $file = "Invoke-$($Scenario.ScenarioName).ps1"
    return Join-Path (Join-Path (Join-Path (Get-EdrProjectRoot) 'scenarios') $Scenario.CategoryFolder) $file
}

function New-EdrEvent {
    param(
        [Parameter(Mandatory = $true)]$Scenario,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$Operation,
        [string]$Status = 'SUCCESS',
        [bool]$Success = $true,
        [string]$Verification = 'independent',
        [string]$ThreatLevel,
        [string]$Detail = '',
        [AllowNull()]$Data,
        [string[]]$Errors = @(),
        [AllowNull()]$Cleanup
    )
    $config = Get-EdrConfig
    $processInfo = Get-EdrCurrentProcessInfo
    $eventType = ($Operation -split '\.')[0]
    $eventAction = (($Operation -split '\.', 2) | Select-Object -Last 1)
    return [pscustomobject]@{
        schema_version = '1.0'
        run_id = $RunId
        nonce = $Nonce
        category = $Scenario.Category
        scenario = $Scenario.ScenarioName
        scenario_id = $Scenario.ScenarioId
        operation = $Operation
        event_type = $eventType
        event_action = $eventAction
        status = $Status
        success = $Success
        verification = $Verification
        threat_level = $(if ($ThreatLevel) { $ThreatLevel } else { $Scenario.ThreatLevel })
        requires_admin = $Scenario.RequiresAdmin -eq 'true'
        triggered_at_utc = (Get-EdrUtcTimestamp)
        observed_at_utc = $null
        source = 'powershell'
        process = $processInfo
        data = $Data
        detail = $Detail
        errors = @($Errors)
        cleanup = $Cleanup
    }
}

function Write-EdrEventLog {
    param(
        [Parameter(Mandatory = $true)]$Event,
        [Parameter(Mandatory = $true)][string]$OutputLog
    )
    $directory = Split-Path -Parent $OutputLog
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $line = ConvertTo-EdrJson -Value $Event -Compress
    Add-Content -LiteralPath $OutputLog -Value $line -Encoding UTF8
}

function Get-EdrDefaultOutputLog {
    param(
        [Parameter(Mandatory = $true)][string]$RunId
    )
    $config = Get-EdrConfig
    $runRoot = Join-Path (Get-EdrProjectRoot) $config.default_run_dir
    $dateDir = Get-Date -Format 'yyyyMMdd'
    return Join-Path (Join-Path (Join-Path $runRoot $dateDir) $RunId) 'events.jsonl'
}

function Get-EdrJsonValue {
    param(
        [Parameter(Mandatory = $true)][AllowNull()]$Object,
        [Parameter(Mandatory = $true)][string]$Path
    )
    if ($null -eq $Object) { return $null }
    $current = $Object
    foreach ($segment in $Path.Split('.')) {
        if ($null -eq $current) { return $null }
        if ($current -is [System.Management.Automation.PSCustomObject]) {
            $property = $current.PSObject.Properties[$segment]
            if ($null -eq $property) { return $null }
            $current = $property.Value
        }
        elseif ($current -is [System.Collections.IDictionary]) {
            if (-not $current.Contains($segment)) { return $null }
            $current = $current[$segment]
        }
        else {
            return $null
        }
    }
    return $current
}

function Expand-EdrTemplate {
    param(
        [Parameter(Mandatory = $true)][string]$Template,
        [string]$Nonce = ''
    )
    return $Template.Replace('${nonce}', $Nonce)
}

function Get-EdrFileSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-EdrCleanupResult {
    param(
        [string]$Status = 'succeeded',
        [string]$Detail = ''
    )
    return [pscustomobject]@{
        status = $Status
        detail = $Detail
        cleaned_at_utc = (Get-EdrUtcTimestamp)
    }
}

function Get-EdrOperationParts {
    param([Parameter(Mandatory = $true)][string]$Operation)
    $parts = @($Operation -split '\.', 2)
    return [pscustomobject]@{
        event_type = $parts[0]
        event_action = $(if ($parts.Count -gt 1) { $parts[1] } else { $Operation })
    }
}

function Test-EdrPathInside {
    param(
        [Parameter(Mandatory = $true)][string]$Child,
        [Parameter(Mandatory = $true)][string]$Parent
    )
    $childFull = [System.IO.Path]::GetFullPath($Child)
    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\')
    return $childFull.StartsWith($parentFull + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-EdrStringEquals {
    param(
        [AllowNull()]$Left,
        [AllowNull()]$Right
    )
    if ($null -eq $Left -and $null -eq $Right) { return $true }
    if ($null -eq $Left -or $null -eq $Right) { return $false }
    return [string]::Equals([string]$Left, [string]$Right, [System.StringComparison]::OrdinalIgnoreCase)
}
