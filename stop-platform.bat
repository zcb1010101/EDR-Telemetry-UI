@echo off
setlocal
chcp 65001 >nul
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0stop-platform.ps1" %*
exit /b %errorlevel%