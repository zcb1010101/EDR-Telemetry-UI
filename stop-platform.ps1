#Requires -Version 5.1
<#
.SYNOPSIS
EDR 遥测离线验证平台一键停止脚本。
.DESCRIPTION
终止平台进程树、清理端口占用与临时 PID 文件，并在结束时校验端口是否真正释放。
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot
$platformDir = Join-Path $projectRoot '.platform'
$serverDir = Join-Path $projectRoot 'server'

function Write-Step {
    param([string]$Message, [string]$Color = 'White')
    Write-Host "[EDR-PLATFORM] $Message" -ForegroundColor $Color
}

function Test-IsAdministrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    finally {
        $identity.Dispose()
    }
}

function Stop-ProcessTree {
    param([int]$TargetProcessId)

    if ($TargetProcessId -le 0) { return }

    $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $TargetProcessId" -ErrorAction SilentlyContinue)
    foreach ($child in $children) {
        if ($child.ProcessId -gt 0 -and $child.ProcessId -ne $TargetProcessId) {
            Stop-ProcessTree -TargetProcessId ([int]$child.ProcessId)
        }
    }

    if (Get-Process -Id $TargetProcessId -ErrorAction SilentlyContinue) {
        Stop-Process -Id $TargetProcessId -Force -ErrorAction SilentlyContinue
    }
}

function Get-PortOwner {
    param([int]$PortNumber)
    $listener = @(Get-NetTCPConnection -LocalPort $PortNumber -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1)
    if (-not $listener) { return 0 }
    return [int]$listener[0].OwningProcess
}

function Test-PlatformCommandLine {
    param([int]$ProcessId)
    $owner = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
    if (-not $owner) { return $false }
    $commandLine = [string]$owner.CommandLine
    return ($commandLine -like '*EDR-Telemetry-UI*' -or $commandLine -like '*server.js*')
}

Write-Step '开始停止 EDR 遥测离线验证平台。' -ForegroundColor Cyan

$pidFiles = @(
    (Join-Path $platformDir 'server.pid'),
    (Join-Path $serverDir 'server.pid')
)
$portFiles = @(
    (Join-Path $platformDir 'server.port'),
    (Join-Path $serverDir 'server.port')
)

$knownPids = New-Object System.Collections.Generic.HashSet[int]
foreach ($file in $pidFiles) {
    if (Test-Path -LiteralPath $file) {
        $raw = Get-Content -LiteralPath $file -Raw -Encoding UTF8
        $raw = $raw.Trim()
        $pidNumber = 0
        if ($raw -and [int]::TryParse($raw, [ref]$pidNumber) -and $pidNumber -gt 0) {
            [void]$knownPids.Add($pidNumber)
        }
    }
}

$needsElevation = $false
foreach ($pidNumber in $knownPids) {
    if (Get-Process -Id $pidNumber -ErrorAction SilentlyContinue) {
        Stop-ProcessTree -TargetProcessId $pidNumber
        Start-Sleep -Milliseconds 450
        if (Get-Process -Id $pidNumber -ErrorAction SilentlyContinue) {
            $needsElevation = $true
            Write-Step "主 PID $pidNumber 仍存在，可能缺少权限。" -ForegroundColor Yellow
        }
        else {
            Write-Step "已终止后端服务进程树，主 PID：$pidNumber" -ForegroundColor Green
        }
    }
    else {
        Write-Step "主 PID $pidNumber 已不存在。" -ForegroundColor DarkGray
    }
}

if ($needsElevation -and -not (Test-IsAdministrator)) {
    Write-Step '检测到进程可能需要管理员权限才能终止，正在请求管理员权限重试。' -ForegroundColor Yellow
    $argumentList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argumentList
    exit 0
}

$knownPorts = New-Object System.Collections.Generic.HashSet[int]
foreach ($file in $portFiles) {
    if (Test-Path -LiteralPath $file) {
        $raw = Get-Content -LiteralPath $file -Raw -Encoding UTF8
        $raw = $raw.Trim()
        $portNumber = 0
        if ($raw -and [int]::TryParse($raw, [ref]$portNumber) -and $portNumber -gt 0) {
            [void]$knownPorts.Add($portNumber)
        }
    }
}

foreach ($portNumber in $knownPorts) {
    $ownerPid = Get-PortOwner -PortNumber $portNumber
    for ($attempt = 0; $attempt -lt 20 -and $ownerPid -gt 0; $attempt++) {
        Start-Sleep -Milliseconds 250
        $ownerPid = Get-PortOwner -PortNumber $portNumber
    }
    if ($ownerPid -gt 0) {
        if (Test-PlatformCommandLine -ProcessId $ownerPid) {
            Stop-ProcessTree -TargetProcessId $ownerPid
            Start-Sleep -Milliseconds 500
            $ownerPid = Get-PortOwner -PortNumber $portNumber
            if ($ownerPid -eq 0) {
                Write-Step "已释放端口 $portNumber 上残留的平台进程。" -ForegroundColor Green
            }
            else {
                Write-Step "端口 $portNumber 仍被 PID $ownerPid 占用。" -ForegroundColor Yellow
            }
        }
        else {
            Write-Step "端口 $portNumber 被其他进程 PID $ownerPid 占用，未强制终止。" -ForegroundColor Yellow
        }
    }
    else {
        Write-Step "端口 $portNumber 已释放。" -ForegroundColor Green
    }
}

foreach ($file in $pidFiles + $portFiles) {
    Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
}
Remove-Item -LiteralPath (Join-Path $platformDir 'server.out.log') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $platformDir 'server.err.log') -Force -ErrorAction SilentlyContinue
Write-Step '临时 PID、端口与日志文件已清理。' -ForegroundColor Green

$stillListening = @()
foreach ($portNumber in $knownPorts) {
    if ((Get-PortOwner -PortNumber $portNumber) -gt 0) {
        $stillListening += $portNumber
    }
}
if ($stillListening.Count -gt 0) {
    Write-Step "仍有端口未释放：$($stillListening -join '、')" -ForegroundColor Yellow
}
else {
    Write-Step '平台已安全退出。' -ForegroundColor Cyan
}