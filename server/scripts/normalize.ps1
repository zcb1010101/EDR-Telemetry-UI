#Requires -Version 5.1
<#
.SYNOPSIS
读取标准化请求文件并调用原有厂商日志 Normalizer。
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RequestPath
)

$ErrorActionPreference = 'Stop'
try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $OutputEncoding = New-Object System.Text.UTF8Encoding($false)
}
catch { }
$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $projectRoot 'core\EdrTelemetry.Common.ps1')
. (Join-Path $projectRoot 'core\EdrTelemetry.Normalizer.ps1')

$request = Read-EdrJson -Path $RequestPath
$result = ConvertFrom-EdrVendorLog -InputPath ([string]$request.inputPath) -VendorId ([string]$request.vendorId)
Export-EdrJson -Path ([string]$request.outputPath) -Value $result.events
Write-Output "已标准化 $($result.events.Count) 条事件：$($request.outputPath)"
exit 0