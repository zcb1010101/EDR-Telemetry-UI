#Requires -Version 5.1
<#
.SYNOPSIS
把项目内脚本与配置文件统一转换为 UTF-8 with BOM。
.DESCRIPTION
Windows PowerShell 5.1 在读取无 BOM 的 UTF-8 中文脚本时会按系统 ANSI 解码，
导致中文乱码并可能触发“输入字符串的格式不正确”。复制项目到新机器后，
如出现该错误，先运行本工具再执行脚本。
.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\Fix-FileEncoding.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$files = @(Get-ChildItem -LiteralPath $projectRoot -Recurse -File | Where-Object {
    $_.Extension -in @('.ps1', '.json', '.csv', '.md') -and $_.FullName -notmatch '\\(runs|logs|import|reports|\.git)\\'
})
$utf8Bom = New-Object System.Text.UTF8Encoding($true)
$converted = 0
foreach ($file in $files) {
    $text = [System.IO.File]::ReadAllText($file.FullName, [System.Text.Encoding]::UTF8)
    [System.IO.File]::WriteAllText($file.FullName, $text, $utf8Bom)
    $converted++
}
Write-Host "已转换 $converted 个文件为 UTF-8 BOM：$projectRoot" -ForegroundColor Green
