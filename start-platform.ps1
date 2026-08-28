#Requires -Version 5.1
<#
.SYNOPSIS
EDR 遥测离线验证平台一键启动脚本。
.DESCRIPTION
自动完成环境自检、端口选择、后端服务启动和浏览器打开。
兼容 PowerShell 与 CMD 调用；使用 -NoBrowser 可仅启动服务。
.EXAMPLE
.\start-platform.ps1
.\start-platform.ps1 -NoBrowser
#>
[CmdletBinding()]
param(
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot
$platformDir = Join-Path $projectRoot '.platform'
$null = [System.IO.Directory]::CreateDirectory($platformDir)

function Write-Step {
    param([string]$Message, [string]$Color = 'White')
    Write-Host "[EDR-PLATFORM] $Message" -ForegroundColor $Color
}

function Test-RequiredCommand {
    param([string]$Name, [string]$Command)
    $commandInfo = Get-Command $Command -ErrorAction SilentlyContinue
    if (-not $commandInfo) {
        throw "缺少运行环境：$Name，请先安装并加入 PATH。"
    }
    Write-Step "$Name：$($commandInfo.Source)" -ForegroundColor Green
}

function Test-RequiredFile {
    param([string]$RelativePath)
    $fullPath = Join-Path $projectRoot $RelativePath
    if (-not (Test-Path -LiteralPath $fullPath)) {
        throw "缺少核心文件：$RelativePath"
    }
}

function Get-FreePort {
    $ports = @(8787, 8788, 8789, 8790)
    foreach ($port in $ports) {
        $listener = $null
        try {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
            $listener.Start()
            $listener.Stop()
            return $port
        }
        catch {
            continue
        }
        finally {
            if ($listener) { $listener.Stop() }
        }
    }
    throw '常用端口 8787-8790 均被占用，请先释放端口。'
}

Write-Step '开始 EDR 遥测离线验证平台环境自检。' -ForegroundColor Cyan
Write-Step '项目目录：' -ForegroundColor White
Write-Host "  $projectRoot" -ForegroundColor DarkGray

$powerShellVersion = $PSVersionTable.PSVersion
if ($powerShellVersion.Major -lt 5 -or ($powerShellVersion.Major -eq 5 -and $powerShellVersion.Minor -lt 1)) {
    throw "需要 Windows PowerShell 5.1 或更高版本，当前为 $powerShellVersion。"
}
Write-Step "Windows PowerShell：$powerShellVersion" -ForegroundColor Green

Test-RequiredCommand -Name 'Node.js' -Command 'node.exe'
Test-RequiredCommand -Name 'npm' -Command 'npm.cmd'

$python = Get-Command 'python.exe' -ErrorAction SilentlyContinue
if ($python) {
    Write-Step "Python：$($python.Source)" -ForegroundColor Green
}
else {
    Write-Step '未检测到 Python，IMPHASH 场景运行时会被跳过；其余场景不受影响。' -ForegroundColor Yellow
}

$coreFiles = @(
    'core\EdrTelemetry.Common.ps1',
    'core\EdrTelemetry.Behaviors.ps1',
    'core\EdrTelemetry.SerialRunner.ps1',
    'core\EdrTelemetry.Normalizer.ps1',
    'core\EdrTelemetry.Baseline.ps1',
    'core\EdrTelemetry.Comparator.ps1',
    'config\project.json',
    'config\scenario-catalog.csv',
    'config\threat-levels.json',
    'config\vendors.json',
    'server\server.js',
    'web\index.html',
    'web\styles.css',
    'web\app.js'
)
foreach ($relativePath in $coreFiles) {
    Test-RequiredFile -RelativePath $relativePath
}
Write-Step '核心脚本、配置与 Web 文件完整性校验通过。' -ForegroundColor Green
Write-Step '核心模块会在运行时自动加载所需系统 DLL，无需额外配置。' -ForegroundColor DarkGray

$port = Get-FreePort
Write-Step "后端端口：$port" -ForegroundColor Cyan
$env:EDR_WEB_PORT = [string]$port
$stdoutLog = Join-Path $platformDir 'server.out.log'
$stderrLog = Join-Path $platformDir 'server.err.log'

$node = (Get-Command 'node.exe').Source
$arguments = @('server\server.js', "--port=$port")
$process = Start-Process -FilePath $node -ArgumentList $arguments -WorkingDirectory $projectRoot `
    -WindowStyle Hidden -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru

$pidFile = Join-Path $platformDir 'server.pid'
$portFile = Join-Path $platformDir 'server.port'
[System.IO.File]::WriteAllText($pidFile, [string]$process.Id, (New-Object System.Text.UTF8Encoding($false)))
[System.IO.File]::WriteAllText($portFile, [string]$port, (New-Object System.Text.UTF8Encoding($false)))

$ready = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    if ($process.HasExited) {
        $errText = if (Test-Path -LiteralPath $stderrLog) { Get-Content -LiteralPath $stderrLog -Raw -Encoding UTF8 } else { '' }
        throw "后端服务启动失败：$errText"
    }
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect('127.0.0.1', $port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne(300, $false) -and $client.Connected) {
            $ready = $true
            break
        }
    }
    catch { }
    finally {
        if ($client) { $client.Close() }
    }
    Start-Sleep -Milliseconds 350
}

if (-not $ready) {
    throw "后端服务未在预期时间内就绪，请查看：$stdoutLog 与 $stderrLog"
}

Write-Step '后端服务已启动。' -ForegroundColor Green
Write-Step '前端页面已由后端统一提供。' -ForegroundColor Green
Write-Step "访问地址：http://127.0.0.1:$port" -ForegroundColor Cyan
Write-Step "运行日志：$stdoutLog" -ForegroundColor DarkGray
Write-Step '提示：停止平台请运行 .\stop-platform.ps1。' -ForegroundColor DarkGray

if (-not $NoBrowser) {
    Start-Process "http://127.0.0.1:$port"
}