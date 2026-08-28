#Requires -Version 5.1
<#
.SYNOPSIS
将厂商原始日志统一转换为标准 JSON 字段格式。
.DESCRIPTION
按 config\vendors.json 中的路由规则执行字段映射与转换，输出标准化事件数组。
.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\Convert-VendorLogs.ps1 -VendorId tencent -InputPath cloud.json -OutputPath normalized.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$VendorId,
    [Parameter(Mandatory = $true)][string]$InputPath,
    [Parameter(Mandatory = $true)][string]$OutputPath
)
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $projectRoot 'core\EdrTelemetry.Common.ps1')
. (Join-Path $projectRoot 'core\EdrTelemetry.Normalizer.ps1')
$result = ConvertFrom-EdrVendorLog -InputPath $InputPath -VendorId $VendorId
Export-EdrJson -Path $OutputPath -Value $result.events
Write-Host "已标准化 $($result.events.Count) 条事件：$OutputPath"
