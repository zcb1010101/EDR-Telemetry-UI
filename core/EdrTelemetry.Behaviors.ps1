#Requires -Version 5.1
Set-StrictMode -Version 2.0

if (-not (Get-Command 'Initialize-EdrContext' -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'EdrTelemetry.Common.ps1')
}

if (-not ('EdrTelemetry.NativeMethods' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace EdrTelemetry
{
    public static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr LoadLibraryW(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);
    }
}
"@
}

function Invoke-EdrTelemetryScenario {
    param(
        [Parameter(Mandatory = $true)]$Scenario,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [string]$ThreatLevel,
        [switch]$SkipCleanup,
        [string]$ServiceName,
        [int]$UsbWaitSeconds = 0,
        [switch]$ConfirmManual
    )

    $operation = $Scenario.Operation
    $requiresAdmin = $Scenario.RequiresAdmin -eq 'true'
    $disabledScenario = $Scenario.ScenarioId -match '^win\.(edr_sysops|driver)\.'
    if ($disabledScenario) {
        $event = New-EdrEvent -Scenario $Scenario -RunId $RunId -Nonce $Nonce -Operation $operation `
            -Status 'SKIPPED' -Success $false -Verification 'disabled' -ThreatLevel $ThreatLevel `
            -Detail 'SCENARIO_DISABLED：该能力暂未实现，已在平台置灰并自动跳过。' `
            -Data $null -Cleanup (Get-EdrCleanupResult -Status 'not_required' -Detail '能力未实现，无需清理。')
        $event.observed_at_utc = Get-EdrUtcTimestamp
        return $event
    }
    $workDir = New-EdrTempDirectory -RunId $RunId -ScenarioId $Scenario.ScenarioId -Nonce $Nonce

    if ($requiresAdmin -and -not (Test-EdrAdministrator)) {
        $event = New-EdrEvent -Scenario $Scenario -RunId $RunId -Nonce $Nonce -Operation $operation `
            -Status 'SKIPPED' -Success $false -Verification 'skipped' -ThreatLevel $ThreatLevel `
            -Detail 'ADMINISTRATOR_REQUIRED：当前进程不是管理员，跳过该场景。' `
            -Data $null -Cleanup (Get-EdrCleanupResult -Status 'not_required' -Detail '未执行行为，无需清理。')
        $event.observed_at_utc = Get-EdrUtcTimestamp
        return $event
    }

    $behaviorParams = @{
        WorkDir = $workDir
        Nonce = $Nonce
        ScenarioId = $Scenario.ScenarioId
        ServiceName = $ServiceName
        UsbWaitSeconds = $UsbWaitSeconds
        ConfirmManual = $ConfirmManual.IsPresent
        SkipCleanup = $SkipCleanup.IsPresent
    }

    try {
        $result = switch ($Scenario.BehaviorKind) {
            'process.create' { Invoke-EdrProcessCreate @behaviorParams }
            'process.terminate' { Invoke-EdrProcessTerminate @behaviorParams }
            'process.access' { Invoke-EdrProcessAccess @behaviorParams }
            'process.image_load' { Invoke-EdrProcessImageLoad @behaviorParams }
            'process.remote_thread' { Invoke-EdrProcessRemoteThread @behaviorParams }
            'process.tampering' { Invoke-EdrProcessTampering @behaviorParams }
            'file.create' { Invoke-EdrFileCreate @behaviorParams }
            'file.open' { Invoke-EdrFileOpen @behaviorParams }
            'file.delete' { Invoke-EdrFileDelete @behaviorParams }
            'file.modify' { Invoke-EdrFileModify @behaviorParams }
            'file.rename' { Invoke-EdrFileRename @behaviorParams }
            'account.local_create' { Invoke-EdrAccountLocalCreate @behaviorParams }
            'account.local_modify' { Invoke-EdrAccountLocalModify @behaviorParams }
            'account.local_delete' { Invoke-EdrAccountLocalDelete @behaviorParams }
            'account.login' { Invoke-EdrAccountLogin @behaviorParams }
            'account.logoff' { Invoke-EdrAccountLogoff @behaviorParams }
            'network.tcp' { Invoke-EdrNetworkTcp @behaviorParams }
            'network.udp' { Invoke-EdrNetworkUdp @behaviorParams }
            'network.url_access' { Invoke-EdrNetworkUrlAccess @behaviorParams }
            'network.dns_query' { Invoke-EdrNetworkDnsQuery @behaviorParams }
            'network.file_download' { Invoke-EdrNetworkFileDownload @behaviorParams }
            'hash.md5' { Invoke-EdrHashMd5 @behaviorParams }
            'hash.sha' { Invoke-EdrHashSha @behaviorParams }
            'hash.imphash' { Invoke-EdrHashImphash @behaviorParams }
            'registry.create' { Invoke-EdrRegistryCreate @behaviorParams }
            'registry.modify' { Invoke-EdrRegistryModify @behaviorParams }
            'registry.delete' { Invoke-EdrRegistryDelete @behaviorParams }
            'scheduled_task.create' { Invoke-EdrScheduledTaskCreate @behaviorParams }
            'scheduled_task.modify' { Invoke-EdrScheduledTaskModify @behaviorParams }
            'scheduled_task.delete' { Invoke-EdrScheduledTaskDelete @behaviorParams }
            'service.create' { Invoke-EdrServiceCreate @behaviorParams }
            'service.modify' { Invoke-EdrServiceModify @behaviorParams }
            'service.delete' { Invoke-EdrServiceDelete @behaviorParams }
            'driver.load' { Invoke-EdrDriverLoad @behaviorParams }
            'driver.modify' { Invoke-EdrDriverModify @behaviorParams }
            'driver.unload' { Invoke-EdrDriverUnload @behaviorParams }
            'device.virtual_disk_mount' { Invoke-EdrVirtualDiskMount @behaviorParams }
            'device.usb_unmount' { Invoke-EdrUsbUnmount @behaviorParams }
            'device.usb_mount' { Invoke-EdrUsbMount @behaviorParams }
            'group_policy.modify' { Invoke-EdrGroupPolicyModify @behaviorParams }
            'named_pipe.create' { Invoke-EdrNamedPipeCreate @behaviorParams }
            'named_pipe.connect' { Invoke-EdrNamedPipeConnect @behaviorParams }
            'edr_sysops.agent_start' { Invoke-EdrAgentStart @behaviorParams }
            'edr_sysops.agent_stop' { Invoke-EdrAgentStop @behaviorParams }
            'edr_sysops.agent_install' { Invoke-EdrAgentInstall @behaviorParams }
            'edr_sysops.agent_uninstall' { Invoke-EdrAgentUninstall @behaviorParams }
            'edr_sysops.agent_keepalive' { Invoke-EdrAgentKeepAlive @behaviorParams }
            'edr_sysops.agent_error' { Invoke-EdrAgentError @behaviorParams }
            'wmi.consumer_filter_binding' { Invoke-EdrWmiConsumerFilterBinding @behaviorParams }
            'wmi.event_consumer' { Invoke-EdrWmiEventConsumer @behaviorParams }
            'wmi.event_filter' { Invoke-EdrWmiEventFilter @behaviorParams }
            'bits.job' { Invoke-EdrBitsJob @behaviorParams }
            'powershell.script_block' { Invoke-EdrPowerShellScriptBlock @behaviorParams }
            default { throw "未实现的行为类型：$($Scenario.BehaviorKind)" }
        }

        if ($null -eq $result) { throw "行为函数未返回结果：$($Scenario.BehaviorKind)" }
        if ($result.Skip) {
            $event = New-EdrEvent -Scenario $Scenario -RunId $RunId -Nonce $Nonce -Operation $operation `
                -Status 'SKIPPED' -Success $false -Verification $(if ($result.Verification) { $result.Verification } else { 'skipped' }) `
                -ThreatLevel $ThreatLevel -Detail $result.Detail -Data $result.Data -Errors $result.Errors `
                -Cleanup $(if ($result.Cleanup) { $result.Cleanup } else { Get-EdrCleanupResult -Status 'not_required' -Detail '未执行行为，无需清理。' })
        }
        else {
            $event = New-EdrEvent -Scenario $Scenario -RunId $RunId -Nonce $Nonce -Operation $operation `
                -Status $(if ($result.Success) { 'SUCCESS' } else { 'FAILED' }) -Success $result.Success `
                -Verification $result.Verification -ThreatLevel $ThreatLevel -Detail $result.Detail `
                -Data $result.Data -Errors $result.Errors -Cleanup $result.Cleanup
        }
        $event.observed_at_utc = Get-EdrUtcTimestamp
        return $event
    }
    catch {
        $event = New-EdrEvent -Scenario $Scenario -RunId $RunId -Nonce $Nonce -Operation $operation `
            -Status 'FAILED' -Success $false -Verification 'error' -ThreatLevel $ThreatLevel `
            -Detail "场景执行异常：$($_.Exception.Message)" -Errors @($_.Exception.Message) `
            -Cleanup (Get-EdrCleanupResult -Status 'failed' -Detail "清理交由 finally 与清理流程处理：$($_.Exception.Message)")
        $event.observed_at_utc = Get-EdrUtcTimestamp
        return $event
    }
    finally {
        if (-not $SkipCleanup) {
            Remove-EdrTempDirectory -Path $workDir
        }
    }
}

function New-EdrBehaviorResult {
    param(
        [bool]$Success = $true,
        [string]$Verification = 'independent',
        [string]$Detail = '',
        [AllowNull()]$Data,
        [string[]]$Errors = @(),
        [AllowNull()]$Cleanup,
        [string]$Skip = ''
    )
    if (-not $Cleanup) {
        $Cleanup = Get-EdrCleanupResult -Status 'not_required' -Detail '行为未产生需要额外清理的系统资源。'
    }
    return [pscustomobject]@{
        Success = $Success
        Verification = $Verification
        Detail = $Detail
        Data = $Data
        Errors = @($Errors)
        Cleanup = $Cleanup
        Skip = $Skip
    }
}

function Invoke-EdrProcessCreate {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $commandLine = "/d /c echo EdrTelemProcessCreate $Nonce"
    $process = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList $commandLine `
        -WorkingDirectory $WorkDir -WindowStyle Hidden -PassThru -ErrorAction Stop
    $exe = $process.Path
    $name = $process.ProcessName
    $exited = $process.WaitForExit(5000)
    $exitCode = if ($exited) { $process.ExitCode } else { $null }
    $success = $exited -and $exitCode -eq 0
    $data = [pscustomobject]@{
        process = [pscustomobject]@{
            pid = $process.Id
            executable = $exe
            name = $name
            command_line = "cmd.exe $commandLine"
            start_time = $(if ($process.StartTime) { $process.StartTime.ToUniversalTime().ToString('o') } else { $null })
            exit_code = $exitCode
        }
    }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "通过 cmd.exe 创建进程并验证退出码：PID=$($process.Id) ExitCode=$exitCode" -Data $data `
        -Errors $(if ($success) { @() } else { @('子进程未按预期退出或退出码非 0。') })
}

function Invoke-EdrProcessTerminate {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $process = Start-Process -FilePath "$env:SystemRoot\System32\ping.exe" -ArgumentList '-n 60 127.0.0.1' `
        -WorkingDirectory $WorkDir -WindowStyle Hidden -PassThru -ErrorAction Stop
    Start-Sleep -Seconds 1
    $pidBefore = $process.Id
    Stop-Process -Id $pidBefore -Force -ErrorAction Stop
    Start-Sleep -Milliseconds 300
    $stillExists = $null -ne (Get-Process -Id $pidBefore -ErrorAction SilentlyContinue)
    $success = -not $stillExists
    $data = [pscustomobject]@{
        process = [pscustomobject]@{
            pid = $pidBefore
            executable = $process.Path
            name = $process.ProcessName
            command_line = 'ping.exe -n 60 127.0.0.1'
            terminated = $true
        }
    }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "终止进程 PID=$pidBefore，验证进程已消失。" -Data $data `
        -Errors $(if ($success) { @() } else { @('进程终止后仍存在。') })
}

function Invoke-EdrProcessAccess {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $accessMask = 0x1000
    $handle = [EdrTelemetry.NativeMethods]::OpenProcess($accessMask, $false, $PID)
    $success = $handle -ne [IntPtr]::Zero
    if ($success) {
        [void][EdrTelemetry.NativeMethods]::CloseHandle($handle)
    }
    $data = [pscustomobject]@{
        process = [pscustomobject]@{
            pid = $PID
            executable = (Get-Process -Id $PID).Path
            name = (Get-Process -Id $PID).ProcessName
            access_mask = ('0x{0:X}' -f $accessMask)
            handle_opened = $success
        }
    }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "OpenProcess 自身进程（PROCESS_QUERY_LIMITED_INFORMATION），句柄打开=$success。" -Data $data `
        -Errors $(if ($success) { @() } else { @("OpenProcess 失败，Win32 Error=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())") })
}

function Invoke-EdrProcessImageLoad {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $library = Join-Path $env:SystemRoot 'System32\dbghelp.dll'
    $handle = [EdrTelemetry.NativeMethods]::LoadLibraryW($library)
    $success = $handle -ne [IntPtr]::Zero
    $data = [pscustomobject]@{
        process = [pscustomobject]@{
            pid = $PID
            executable = (Get-Process -Id $PID).Path
            name = (Get-Process -Id $PID).ProcessName
        }
        image = [pscustomobject]@{
            path = $library
            name = [System.IO.Path]::GetFileName($library)
            module_handle = ('0x{0:X}' -f $handle.ToInt64())
        }
    }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "LoadLibraryW 加载 $library，模块句柄非空=$success。" -Data $data `
        -Errors $(if ($success) { @() } else { @('LoadLibraryW 返回空句柄。') })
}

function Invoke-EdrProcessRemoteThread {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $kernel32 = [EdrTelemetry.NativeMethods]::LoadLibraryW('kernel32.dll')
    $exitThread = [EdrTelemetry.NativeMethods]::GetProcAddress($kernel32, 'ExitThread')
    if ($exitThread -eq [IntPtr]::Zero) { throw '无法解析 kernel32!ExitThread。' }
    $threadId = 0
    $thread = [EdrTelemetry.NativeMethods]::CreateRemoteThread(
        [EdrTelemetry.NativeMethods]::GetCurrentProcess(),
        [IntPtr]::Zero,
        [UIntPtr]::Zero,
        $exitThread,
        [IntPtr]::Zero,
        0,
        [ref]$threadId)
    $success = $thread -ne [IntPtr]::Zero
    $exitCode = [uint32]0
    if ($success) {
        [void][EdrTelemetry.NativeMethods]::WaitForSingleObject($thread, 5000)
        [void][EdrTelemetry.NativeMethods]::GetExitCodeThread($thread, [ref]$exitCode)
        [void][EdrTelemetry.NativeMethods]::CloseHandle($thread)
        $success = $exitCode -eq 0
    }
    $data = [pscustomobject]@{
        process = [pscustomobject]@{
            pid = $PID
            executable = (Get-Process -Id $PID).Path
            name = (Get-Process -Id $PID).ProcessName
        }
        thread = [pscustomobject]@{
            thread_id = $threadId
            start_address = ('0x{0:X}' -f $exitThread.ToInt64())
            exit_code = $exitCode
        }
    }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "CreateRemoteThread 在当前进程创建线程，threadId=$threadId，exitCode=$exitCode。" -Data $data `
        -Errors $(if ($success) { @() } else { @('远程线程创建或退出码验证失败。') })
}

function Invoke-EdrProcessTampering {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $bytes = [byte[]](0x41, 0x42, 0x43)
    $handle = [System.Runtime.InteropServices.GCHandle]::Alloc($bytes, [System.Runtime.InteropServices.GCHandleType]::Pinned)
    try {
        $buffer = $handle.AddrOfPinnedObject()
        $written = [UIntPtr]::Zero
        $ok = [EdrTelemetry.NativeMethods]::WriteProcessMemory(
            [EdrTelemetry.NativeMethods]::GetCurrentProcess(),
            $buffer,
            $buffer,
            [UIntPtr]::new([uint32]$bytes.Length),
            [ref]$written)
        $success = $ok -and $written.ToUInt64() -eq $bytes.Length
        $data = [pscustomobject]@{
            process = [pscustomobject]@{
                pid = $PID
                executable = (Get-Process -Id $PID).Path
                name = (Get-Process -Id $PID).ProcessName
            }
            memory = [pscustomobject]@{
                address = ('0x{0:X}' -f $buffer.ToInt64())
                written_bytes = $written.ToUInt64()
                value = [System.Text.Encoding]::ASCII.GetString($bytes)
            }
        }
        return New-EdrBehaviorResult -Success $success -Verification 'independent' `
            -Detail "WriteProcessMemory 修改自身进程内存，写入 $($written.ToUInt64()) 字节。" -Data $data `
            -Errors $(if ($success) { @() } else { @("WriteProcessMemory 写入字节数不符：$($written.ToUInt64())") })
    }
    finally {
        $handle.Free()
    }
}

function Get-EdrScenarioFileExtension {
    param([AllowNull()][string]$ScenarioId)
    if ($ScenarioId -and $ScenarioId -match '\.(txt|json|dll)$') {
        return $Matches[1].ToLowerInvariant()
    }
    return 'txt'
}

function New-EdrFileSample {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Extension,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [string]$Kind
    )
    if ($Extension -eq 'dll') {
        $source = Join-Path $env:SystemRoot 'System32\dbghelp.dll'
        if (-not (Test-Path -LiteralPath $source)) { $source = Join-Path $env:SystemRoot 'System32\kernel32.dll' }
        Copy-Item -LiteralPath $source -Destination $Path -Force
        return
    }
    if ($Extension -eq 'json') {
        $content = [pscustomobject]@{ nonce = $Nonce; kind = $Kind; type = 'json' } | ConvertTo-Json -Compress
    }
    else {
        $content = "$Kind $Nonce"
    }
    [System.IO.File]::WriteAllText($Path, $content, (New-Object System.Text.UTF8Encoding($false)))
}

function Invoke-EdrFileCreate {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $extension = Get-EdrScenarioFileExtension -ScenarioId $ScenarioId
    $path = Join-Path $WorkDir "edrtelem-create-$Nonce.$extension"
    New-EdrFileSample -Path $path -Extension $extension -Nonce $Nonce -Kind 'EdrTelemFileCreate'
    $exists = Test-Path -LiteralPath $path
    $size = if ($exists) { (Get-Item -LiteralPath $path).Length } else { 0 }
    $data = [pscustomobject]@{
        file = [pscustomobject]@{
            path = $path
            name = [System.IO.Path]::GetFileName($path)
            extension = $extension
            size = $size
            created = $exists
        }
    }
    Start-Sleep -Milliseconds ([int](Get-EdrConfig).file_behavior_hold_ms)
    $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail "删除临时文件：$path"
    if (-not $SkipCleanup -and $exists) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
    return New-EdrBehaviorResult -Success $exists -Verification 'independent' `
        -Detail "创建文件 $path 并验证存在。" -Data $data -Cleanup $cleanup `
        -Errors $(if ($exists) { @() } else { @('文件创建后不存在。') })
}

function Invoke-EdrFileOpen {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $extension = Get-EdrScenarioFileExtension -ScenarioId $ScenarioId
    $path = Join-Path $WorkDir "edrtelem-open-$Nonce.$extension"
    New-EdrFileSample -Path $path -Extension $extension -Nonce $Nonce -Kind 'EdrTelemFileOpen'
    $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        if ($extension -eq 'dll') {
            $reader = New-Object System.IO.BinaryReader($stream)
            $success = $reader.ReadByte() -ge 0
            $reader.Dispose()
        }
        else {
            $reader = New-Object System.IO.StreamReader($stream, (New-Object System.Text.UTF8Encoding($false)))
            $content = $reader.ReadToEnd()
            $reader.Dispose()
            $success = $content.Contains($Nonce)
        }
        $data = [pscustomobject]@{
            file = [pscustomobject]@{
                path = $path
                name = [System.IO.Path]::GetFileName($path)
                extension = $extension
                size = (Get-Item -LiteralPath $path).Length
                opened = $true
                content_verified = $success
            }
        }
        Start-Sleep -Milliseconds ([int](Get-EdrConfig).file_behavior_hold_ms)
        $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail "关闭句柄并删除临时文件：$path"
        if (-not $SkipCleanup) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
        return New-EdrBehaviorResult -Success $success -Verification 'independent' `
            -Detail "以 FileShare.ReadWrite 打开文件并读取内容，验证 nonce 存在。" -Data $data -Cleanup $cleanup `
            -Errors $(if ($success) { @() } else { @('文件内容不包含本轮 nonce。') })
    }
    finally {
        $stream.Dispose()
    }
}

function Invoke-EdrFileDelete {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $extension = Get-EdrScenarioFileExtension -ScenarioId $ScenarioId
    $path = Join-Path $WorkDir "edrtelem-delete-$Nonce.$extension"
    New-EdrFileSample -Path $path -Extension $extension -Nonce $Nonce -Kind 'EdrTelemFileDelete'
    Start-Sleep -Seconds 1
    Start-Sleep -Milliseconds ([int](Get-EdrConfig).file_behavior_hold_ms)
    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
    $gone = -not (Test-Path -LiteralPath $path)
    $data = [pscustomobject]@{
        file = [pscustomobject]@{
            path = $path
            name = [System.IO.Path]::GetFileName($path)
            extension = $extension
            deleted = $gone
        }
    }
    return New-EdrBehaviorResult -Success $gone -Verification 'independent' `
        -Detail "删除文件 $path 并验证不存在。" -Data $data `
        -Errors $(if ($gone) { @() } else { @('文件删除后仍存在。') })
}

function Invoke-EdrFileModify {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $path = Join-Path $WorkDir "edrtelem-modify-$Nonce.txt"
    [System.IO.File]::WriteAllText($path, "before $Nonce", (New-Object System.Text.UTF8Encoding($false)))
    $sizeBefore = (Get-Item -LiteralPath $path).Length
    Start-Sleep -Seconds 1
    Add-Content -LiteralPath $path -Value "after $Nonce" -Encoding UTF8
    $sizeAfter = (Get-Item -LiteralPath $path).Length
    $success = $sizeAfter -gt $sizeBefore
    $data = [pscustomobject]@{
        file = [pscustomobject]@{
            path = $path
            name = [System.IO.Path]::GetFileName($path)
            size_before = $sizeBefore
            size_after = $sizeAfter
            modified = $success
        }
    }
    Start-Sleep -Milliseconds ([int](Get-EdrConfig).file_behavior_hold_ms)
    $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail "删除临时文件：$path"
    if (-not $SkipCleanup) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "修改文件内容，大小从 $sizeBefore 变为 $sizeAfter。" -Data $data -Cleanup $cleanup `
        -Errors $(if ($success) { @() } else { @('文件修改后大小未变化。') })
}

function Invoke-EdrFileRename {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $oldPath = Join-Path $WorkDir "edrtelem-rename-$Nonce.txt"
    $newPath = Join-Path $WorkDir "edrtelem-renamed-$Nonce.txt"
    [System.IO.File]::WriteAllText($oldPath, "EdrTelemFileRename $Nonce", (New-Object System.Text.UTF8Encoding($false)))
    Rename-Item -LiteralPath $oldPath -NewName ([System.IO.Path]::GetFileName($newPath)) -Force
    $success = (Test-Path -LiteralPath $newPath) -and (-not (Test-Path -LiteralPath $oldPath))
    $data = [pscustomobject]@{
        file = [pscustomobject]@{
            old_path = $oldPath
            path = $newPath
            name = [System.IO.Path]::GetFileName($newPath)
            renamed = $success
        }
    }
    Start-Sleep -Milliseconds ([int](Get-EdrConfig).file_behavior_hold_ms)
    $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail "删除重命名后的临时文件：$newPath"
    if (-not $SkipCleanup) { Remove-Item -LiteralPath $newPath -Force -ErrorAction SilentlyContinue }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "重命名文件并验证旧路径消失、新路径存在。" -Data $data -Cleanup $cleanup `
        -Errors $(if ($success) { @() } else { @('重命名结果验证失败。') })
}

function Get-EdrTempAccountName {
    param([Parameter(Mandatory = $true)][string]$Nonce)
    return "EdrTelem_$(($Nonce.Substring(0, [Math]::Min(8, $Nonce.Length))).ToLowerInvariant())"
}

function Invoke-EdrAccountLocalCreate {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $accountName = Get-EdrTempAccountName -Nonce $Nonce
    $password = "EdrTelem!$Nonce"
    & net.exe user $accountName $password /add | Out-Null
    if ($LASTEXITCODE -ne 0) {
        return New-EdrBehaviorResult -Success $false -Verification 'api' -Detail "net user /add 失败：$accountName" `
            -Errors @("net.exe 退出码 $LASTEXITCODE") -Skip 'FAILED'
    }
    $exists = $null -ne (Get-LocalUser -Name $accountName -ErrorAction SilentlyContinue)
    $data = [pscustomobject]@{
        account = [pscustomobject]@{
            name = $accountName
            created = $exists
            source = 'net.exe'
        }
    }
    $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail "删除临时账号：$accountName"
    if (-not $SkipCleanup) {
        & net.exe user $accountName /delete | Out-Null
    }
    return New-EdrBehaviorResult -Success $exists -Verification 'independent' `
        -Detail "创建本地账号 $accountName 并验证存在。" -Data $data -Cleanup $cleanup `
        -Errors $(if ($exists) { @() } else { @('账号创建后查询不到。') })
}

function Invoke-EdrAccountLocalModify {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $accountName = Get-EdrTempAccountName -Nonce $Nonce
    $password = "EdrTelem!$Nonce"
    & net.exe user $accountName $password /add | Out-Null
    if ($LASTEXITCODE -ne 0) {
        return New-EdrBehaviorResult -Success $false -Verification 'api' -Detail "net user /add 失败：$accountName" -Errors @("net.exe 退出码 $LASTEXITCODE")
    }
    Start-Sleep -Seconds 1
    $newPassword = "EdrTelem!${Nonce}New"
    & net.exe user $accountName $newPassword | Out-Null
    $modified = $LASTEXITCODE -eq 0
    $data = [pscustomobject]@{
        account = [pscustomobject]@{
            name = $accountName
            modified = $modified
            source = 'net.exe'
        }
    }
    $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail "删除临时账号：$accountName"
    if (-not $SkipCleanup) {
        & net.exe user $accountName /delete | Out-Null
    }
    return New-EdrBehaviorResult -Success $modified -Verification 'api' `
        -Detail "修改临时账号 $accountName 密码并确认 net.exe 返回 0。" -Data $data -Cleanup $cleanup `
        -Errors $(if ($modified) { @() } else { @("net.exe 退出码 $LASTEXITCODE") })
}

function Invoke-EdrAccountLocalDelete {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $accountName = Get-EdrTempAccountName -Nonce $Nonce
    $password = "EdrTelem!$Nonce"
    & net.exe user $accountName $password /add | Out-Null
    Start-Sleep -Seconds 1
    & net.exe user $accountName /delete | Out-Null
    $gone = $null -eq (Get-LocalUser -Name $accountName -ErrorAction SilentlyContinue)
    $data = [pscustomobject]@{
        account = [pscustomobject]@{
            name = $accountName
            deleted = $gone
        }
    }
    return New-EdrBehaviorResult -Success $gone -Verification 'independent' `
        -Detail "创建后删除临时账号 $accountName 并验证不存在。" -Data $data `
        -Errors $(if ($gone) { @() } else { @('账号删除后仍存在。') })
}

function Invoke-EdrAccountLogin {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $accountName = Get-EdrTempAccountName -Nonce $Nonce
    $password = "EdrTelem!$Nonce"
    & net.exe user $accountName $password /add | Out-Null
    if ($LASTEXITCODE -ne 0) {
        return New-EdrBehaviorResult -Success $false -Verification 'api' -Detail "net user /add 失败：$accountName" -Errors @("net.exe 退出码 $LASTEXITCODE")
    }
    $taskName = "EdrTelemLogon_$($accountName)"
    $startTime = (Get-Date).AddMinutes(1).ToString('HH:mm')
    & schtasks.exe /Create /TN $taskName /TR "cmd.exe /c echo $Nonce" /SC ONCE /ST $startTime /RU "$env:COMPUTERNAME\$accountName" /RP $password /F | Out-Null
    $taskCreated = $LASTEXITCODE -eq 0
    $taskRan = $false
    if ($taskCreated) {
        & schtasks.exe /Run /TN $taskName | Out-Null
        $taskRan = $LASTEXITCODE -eq 0
        Start-Sleep -Seconds 3
    }
    $data = [pscustomobject]@{
        account = [pscustomobject]@{
            name = $accountName
            login_method = 'scheduled_task'
            task_name = $taskName
            task_ran = $taskRan
        }
    }
    $cleanupDetail = @("删除计划任务 $taskName")
    if (-not $SkipCleanup) {
        & schtasks.exe /Delete /TN $taskName /F | Out-Null
        & net.exe user $accountName /delete | Out-Null
        $cleanupDetail += "删除临时账号 $accountName"
    }
    return New-EdrBehaviorResult -Success ($taskCreated -and $taskRan) -Verification 'independent' `
        -Detail "通过计划任务以 $accountName 身份触发登录会话。" -Data $data `
        -Cleanup (Get-EdrCleanupResult -Status 'succeeded' -Detail ($cleanupDetail -join '；')) `
        -Errors $(if ($taskCreated -and $taskRan) { @() } else { @("任务创建=$taskCreated，任务运行=$taskRan") })
}

function Invoke-EdrAccountLogoff {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $accountName = Get-EdrTempAccountName -Nonce $Nonce
    $loginResult = Invoke-EdrAccountLogin -WorkDir $WorkDir -Nonce $Nonce -ScenarioId 'win.account.login' -ServiceName $ServiceName -UsbWaitSeconds $UsbWaitSeconds -ConfirmManual:$ConfirmManual -SkipCleanup:$true
    if (-not $loginResult.Success) {
        return New-EdrBehaviorResult -Success $false -Verification 'skipped' `
            -Detail '登出动作链需要先成功创建登录会话；前置登录未成功，已跳过。' `
            -Data ([pscustomobject]@{ account = [pscustomobject]@{ name = $accountName; session_id = $null } }) -Skip 'LOGIN_PREREQUISITE_FAILED'
    }
    Start-Sleep -Seconds 1
    $sessionId = $null
    if (-not (Get-Command quser.exe -ErrorAction SilentlyContinue) -or -not (Get-Command logoff.exe -ErrorAction SilentlyContinue)) {
        return New-EdrBehaviorResult -Success $false -Verification 'skipped' `
            -Detail '当前系统缺少 quser.exe 或 logoff.exe，无法执行账号登出场景。' `
            -Data ([pscustomobject]@{ account = [pscustomobject]@{ name = $accountName; session_id = $null } }) `
            -Skip 'QUSER_OR_LOGOFF_UNAVAILABLE'
    }
    $quserOutput = @(& quser.exe /FO:CSV 2>$null)
    if ($LASTEXITCODE -eq 0 -and $quserOutput.Count -gt 1) {
        $header = $quserOutput[0].Trim('"').Split('","')
        for ($i = 1; $i -lt $quserOutput.Count; $i++) {
            $fields = $quserOutput[$i].Trim('"').Split('","')
            if ($fields[0] -eq $accountName -and $fields.Count -ge 3) {
                $sessionId = $fields[2]
                break
            }
        }
    }
    if (-not $sessionId) {
        return New-EdrBehaviorResult -Success $false -Verification 'skipped' -Detail "未找到 $accountName 的活动会话；请先运行账号登录场景。" `
            -Data ([pscustomobject]@{ account = [pscustomobject]@{ name = $accountName; session_id = $null } }) -Skip 'NO_ACTIVE_SESSION'
    }
    $currentSession = (Get-Process -Id $PID).SessionId
    if ([int]$sessionId -eq $currentSession) {
        return New-EdrBehaviorResult -Success $false -Verification 'skipped' -Detail '拒绝登出当前控制台会话。' `
            -Data ([pscustomobject]@{ account = [pscustomobject]@{ name = $accountName; session_id = $sessionId } }) -Skip 'CURRENT_SESSION'
    }
    & logoff.exe $sessionId | Out-Null
    $success = $LASTEXITCODE -eq 0
    $data = [pscustomobject]@{
        account = [pscustomobject]@{
            name = $accountName
            session_id = $sessionId
            logged_off = $success
        }
    }
    return New-EdrBehaviorResult -Success $success -Verification 'api' -Detail "登出会话 $sessionId（$accountName）。" -Data $data `
        -Errors $(if ($success) { @() } else { @("logoff.exe 退出码 $LASTEXITCODE") })
}

function Invoke-EdrNetworkTcp {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $payload = "EdrTelemTcp $Nonce"
    $acceptTask = $listener.AcceptTcpClientAsync()
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect('127.0.0.1', $port)
    $stream = $client.GetStream()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
    $stream.Write($bytes, 0, $bytes.Length)
    if (-not $acceptTask.Wait(5000)) { throw 'TCP 回环服务器未接受连接。' }
    $serverClient = $acceptTask.Result
    $serverStream = $serverClient.GetStream()
    $serverBuffer = New-Object byte[] 1024
    $serverCount = $serverStream.Read($serverBuffer, 0, $serverBuffer.Length)
    $serverText = [System.Text.Encoding]::UTF8.GetString($serverBuffer, 0, $serverCount)
    $serverResponse = [System.Text.Encoding]::UTF8.GetBytes($serverText)
    $serverStream.Write($serverResponse, 0, $serverResponse.Length)
    $buffer = New-Object byte[] 1024
    $count = $stream.Read($buffer, 0, $buffer.Length)
    $response = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $count)
    $client.Close()
    $serverClient.Close()
    $listener.Stop()
    $success = $serverText.Contains($Nonce) -and $response.Contains($Nonce)
    $data = [pscustomobject]@{
        network = [pscustomobject]@{
            protocol = 'tcp'
            source_ip = '127.0.0.1'
            source_port = $null
            destination_ip = '127.0.0.1'
            destination_port = $port
            bytes_sent = $bytes.Length
            loopback = $true
        }
    }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "回环 TCP 连接到 127.0.0.1:$port 并完成数据交换。" -Data $data `
        -Errors $(if ($success) { @() } else { @('TCP 回环数据验证失败。') })
}

function Invoke-EdrNetworkUdp {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    try {
        $extSender = New-Object System.Net.Sockets.UdpClient
        $extBytes = [System.Text.Encoding]::ASCII.GetBytes("EdrTelemUdp $Nonce")
        [void]$extSender.Send($extBytes, $extBytes.Length, '8.8.8.8', 53)
        $extSender.Close()
        $data = [pscustomobject]@{
            network = [pscustomobject]@{
                protocol = 'udp'
                source_ip = $null
                source_port = $null
                destination_ip = '8.8.8.8'
                destination_port = 53
                bytes_sent = $extBytes.Length
                loopback = $false
            }
        }
        return New-EdrBehaviorResult -Success $true -Verification 'independent' `
            -Detail '外网 UDP 数据包发送到 8.8.8.8:53。' -Data $data
    }
    catch { }
    $receiver = New-Object System.Net.Sockets.UdpClient([System.Net.IPAddress]::Loopback, 0)
    $port = ([System.Net.IPEndPoint]$receiver.Client.LocalEndPoint).Port
    $sender = New-Object System.Net.Sockets.UdpClient
    $payload = "EdrTelemUdp $Nonce"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
    $sender.Send($bytes, $bytes.Length, '127.0.0.1', $port) | Out-Null
    $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $received = $receiver.Receive([ref]$remote)
    $text = [System.Text.Encoding]::UTF8.GetString($received)
    $receiver.Close()
    $sender.Close()
    $success = $text.Contains($Nonce)
    $data = [pscustomobject]@{
        network = [pscustomobject]@{
            protocol = 'udp'
            source_ip = '127.0.0.1'
            source_port = $null
            destination_ip = '127.0.0.1'
            destination_port = $port
            bytes_sent = $bytes.Length
            loopback = $true
        }
    }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "回环 UDP 发送到 127.0.0.1:$port 并验证接收内容。" -Data $data `
        -Errors $(if ($success) { @() } else { @('UDP 回环数据验证失败。') })
}

function Invoke-EdrNetworkUrlAccess {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    try {
        $external = Invoke-WebRequest -Uri 'https://www.baidu.com' -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
        if ($external.StatusCode -ge 200 -and $external.StatusCode -lt 400) {
            $data = [pscustomobject]@{
                network = [pscustomobject]@{
                    protocol = 'tcp'
                    method = 'GET'
                    url = 'https://www.baidu.com'
                    destination_ip = $null
                    destination_port = 443
                    loopback = $false
                    status_code = $external.StatusCode
                }
            }
            return New-EdrBehaviorResult -Success $true -Verification 'independent' `
                -Detail '外网 HTTP(S) 访问 https://www.baidu.com 成功。' -Data $data
        }
    }
    catch { }
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $url = "http://127.0.0.1:$port/edrtelem/$Nonce"
    $acceptTask = $listener.AcceptTcpClientAsync()
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect('127.0.0.1', $port)
    $stream = $client.GetStream()
    $request = "GET /edrtelem/$Nonce HTTP/1.1`r`nHost: 127.0.0.1:$port`r`nConnection: close`r`n`r`n"
    $requestBytes = [System.Text.Encoding]::ASCII.GetBytes($request)
    $stream.Write($requestBytes, 0, $requestBytes.Length)
    if (-not $acceptTask.Wait(5000)) { throw 'HTTP 回环服务器未接受连接。' }
    $serverClient = $acceptTask.Result
    $serverStream = $serverClient.GetStream()
    $reader = New-Object System.IO.StreamReader($serverStream)
    $null = $reader.ReadLine()
    while ($reader.ReadLine() -ne '') { }
    $body = "EdrTelemUrl $Nonce"
    $header = "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n"
    $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($header + $body)
    $serverStream.Write($responseBytes, 0, $responseBytes.Length)
    $serverClient.Close()
    $buffer = New-Object byte[] 4096
    $count = $stream.Read($buffer, 0, $buffer.Length)
    $content = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $count)
    $client.Close()
    $listener.Stop()
    $success = $content.Contains($Nonce)
    $data = [pscustomobject]@{
        network = [pscustomobject]@{
            protocol = 'tcp'
            method = 'GET'
            url = $url
            destination_ip = '127.0.0.1'
            destination_port = $port
            loopback = $true
        }
    }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "回环 HTTP GET $url 并验证响应内容。" -Data $data `
        -Errors $(if ($success) { @() } else { @('HTTP 回环响应验证失败。') })
}

function Invoke-EdrNetworkDnsQuery {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $queryName = 'www.baidu.com'
    try {
        $hostEntry = [System.Net.Dns]::GetHostEntry($queryName)
    }
    catch {
        $queryName = 'localhost'
        $hostEntry = [System.Net.Dns]::GetHostEntry($queryName)
    }
    $addresses = @($hostEntry.AddressList | ForEach-Object { $_.ToString() })
    $success = $addresses.Count -gt 0
    $data = [pscustomobject]@{
        network = [pscustomobject]@{
            protocol = 'udp'
            dns_query_name = $queryName
            resolved_ips = $addresses
            query_method = 'GetHostEntry'
        }
    }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "DNS 解析 $queryName，得到 $($addresses -join '、')。" -Data $data `
        -Errors $(if ($success) { @() } else { @('DNS 解析未返回地址。') })
}

function Invoke-EdrNetworkFileDownload {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $source = Join-Path $WorkDir "edrtelem-download-source-$Nonce.bin"
    $target = Join-Path $WorkDir "edrtelem-download-target-$Nonce.bin"
    $content = New-Object byte[] 8192
    (New-Object System.Random(42)).NextBytes($content)
    [System.IO.File]::WriteAllBytes($source, $content)
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $url = "http://127.0.0.1:$port/edrtelem/$Nonce.bin"
    $acceptTask = $listener.AcceptTcpClientAsync()
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect('127.0.0.1', $port)
    $stream = $client.GetStream()
    $request = "GET /edrtelem/$Nonce.bin HTTP/1.1`r`nHost: 127.0.0.1:$port`r`nConnection: close`r`n`r`n"
    $requestBytes = [System.Text.Encoding]::ASCII.GetBytes($request)
    $stream.Write($requestBytes, 0, $requestBytes.Length)
    if (-not $acceptTask.Wait(5000)) { throw 'HTTP 下载回环服务器未接受连接。' }
    $serverClient = $acceptTask.Result
    $serverStream = $serverClient.GetStream()
    $reader = New-Object System.IO.StreamReader($serverStream)
    $null = $reader.ReadLine()
    while ($reader.ReadLine() -ne '') { }
    $header = "HTTP/1.1 200 OK`r`nContent-Length: $($content.Length)`r`nConnection: close`r`n`r`n"
    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
    $serverStream.Write($headerBytes, 0, $headerBytes.Length)
    $serverStream.Write($content, 0, $content.Length)
    $serverClient.Close()
    $fileStream = [System.IO.File]::Create($target)
    try {
        $buffer = New-Object byte[] 4096
        $headerBytes = New-Object System.Collections.Generic.List[byte]
        $headerEnded = $false
        while (-not $headerEnded) {
            $count = $stream.Read($buffer, 0, $buffer.Length)
            if ($count -le 0) { break }
            for ($i = 0; $i -lt $count; $i++) {
                $headerBytes.Add($buffer[$i])
                $n = $headerBytes.Count
                if ($n -ge 4 -and $headerBytes[$n - 4] -eq 13 -and $headerBytes[$n - 3] -eq 10 -and $headerBytes[$n - 2] -eq 13 -and $headerBytes[$n - 1] -eq 10) {
                    $headerEnded = $true
                    for ($j = $i + 1; $j -lt $count; $j++) {
                        $fileStream.WriteByte($buffer[$j])
                    }
                    break
                }
            }
        }
        while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $fileStream.Write($buffer, 0, $count)
        }
    }
    finally {
        $fileStream.Dispose()
        $client.Close()
    }
    $listener.Stop()
    $downloaded = Test-Path -LiteralPath $target
    $sameHash = $downloaded -and ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash)
    $data = [pscustomobject]@{
        network = [pscustomobject]@{
            protocol = 'tcp'
            method = 'GET'
            url = $url
            destination_ip = '127.0.0.1'
            destination_port = $port
            bytes_transferred = $(if ($downloaded) { (Get-Item -LiteralPath $target).Length } else { 0 })
        }
        file = [pscustomobject]@{
            path = $target
            name = [System.IO.Path]::GetFileName($target)
            size = $(if ($downloaded) { (Get-Item -LiteralPath $target).Length } else { 0 })
            hash_sha256 = $(if ($downloaded) { (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null })
        }
    }
    return New-EdrBehaviorResult -Success ($downloaded -and $sameHash) -Verification 'independent' `
        -Detail "通过回环 HTTP 下载 8KB 文件并验证 SHA-256 一致。" -Data $data `
        -Errors $(if ($downloaded -and $sameHash) { @() } else { @('下载文件缺失或哈希不一致。') })
}

function Get-EdrHashSample {
    param(
        [Parameter(Mandatory = $true)][string]$WorkDir,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [string]$ScenarioId = ''
    )
    $extension = Get-EdrScenarioFileExtension -ScenarioId $ScenarioId
    $target = Join-Path $WorkDir "edrtelem-sample-$Nonce.$extension"
    New-EdrFileSample -Path $target -Extension $extension -Nonce $Nonce -Kind 'EdrTelemHashSample'
    return $target
}

function Invoke-EdrHashMd5 {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $sample = Get-EdrHashSample -WorkDir $WorkDir -Nonce $Nonce -ScenarioId $ScenarioId
    $hash = (Get-FileHash -LiteralPath $sample -Algorithm MD5).Hash.ToLowerInvariant()
    $data = [pscustomobject]@{
        hash = [pscustomobject]@{
            algorithm = 'md5'
            value = $hash
            path = $sample
            name = [System.IO.Path]::GetFileName($sample)
            file_size = (Get-Item -LiteralPath $sample).Length
        }
    }
    $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail '删除临时样本。'
    if (-not $SkipCleanup) { Remove-Item -LiteralPath $sample -Force -ErrorAction SilentlyContinue }
    return New-EdrBehaviorResult -Success $true -Verification 'independent' `
        -Detail "MD5=$hash" -Data $data -Cleanup $cleanup
}

function Invoke-EdrHashSha {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $sample = Get-EdrHashSample -WorkDir $WorkDir -Nonce $Nonce -ScenarioId $ScenarioId
    $sha1 = (Get-FileHash -LiteralPath $sample -Algorithm SHA1).Hash.ToLowerInvariant()
    $sha256 = (Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash.ToLowerInvariant()
    $data = [pscustomobject]@{
        hash = [pscustomobject]@{
            algorithm = 'sha256'
            value = $sha256
            sha1 = $sha1
            path = $sample
            name = [System.IO.Path]::GetFileName($sample)
            file_size = (Get-Item -LiteralPath $sample).Length
            timestamp = Get-EdrUtcTimestamp
        }
    }
    $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail '删除临时样本。'
    if (-not $SkipCleanup) { Remove-Item -LiteralPath $sample -Force -ErrorAction SilentlyContinue }
    return New-EdrBehaviorResult -Success $true -Verification 'independent' `
        -Detail "SHA1=$sha1；SHA256=$sha256" -Data $data -Cleanup $cleanup
}

function Invoke-EdrHashImphash {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $sample = Get-EdrHashSample -WorkDir $WorkDir -Nonce $Nonce -ScenarioId $ScenarioId
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $python) {
        return New-EdrBehaviorResult -Success $false -Verification 'skipped' -Detail '未找到 python，无法计算 IMPHASH。' `
            -Data ([pscustomobject]@{ hash = [pscustomobject]@{ algorithm = 'imphash'; value = $null; path = $sample } }) `
            -Skip 'PYTHON_REQUIRED'
    }
    $script = "import pefile,sys; pe=pefile.PE(sys.argv[1]); print(pe.get_imphash())"
    $imphash = & $python.Source -c $script $sample 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $imphash) {
        return New-EdrBehaviorResult -Success $false -Verification 'skipped' `
            -Detail 'pefile 未安装或计算失败；运行 pip install pefile 后重试。' `
            -Data ([pscustomobject]@{ hash = [pscustomobject]@{ algorithm = 'imphash'; value = $null; path = $sample } }) `
            -Skip 'PEFILE_REQUIRED'
    }
    $value = ($imphash | Select-Object -First 1).Trim()
    $data = [pscustomobject]@{
        hash = [pscustomobject]@{
            algorithm = 'imphash'
            value = $value
            path = $sample
            name = [System.IO.Path]::GetFileName($sample)
            file_size = (Get-Item -LiteralPath $sample).Length
        }
    }
    $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail '删除临时样本。'
    if (-not $SkipCleanup) { Remove-Item -LiteralPath $sample -Force -ErrorAction SilentlyContinue }
    return New-EdrBehaviorResult -Success $true -Verification 'independent' -Detail "IMPHASH=$value" -Data $data -Cleanup $cleanup
}

function Get-EdrRegistryPath {
    param([Parameter(Mandatory = $true)][string]$Nonce)
    return "HKCU:\Software\EdrTelemetry\Runs\$Nonce"
}

function Invoke-EdrRegistryCreate {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $keyPath = Get-EdrRegistryPath -Nonce $Nonce
    New-Item -Path $keyPath -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name 'Marker' -Value "EdrTelemRegistryCreate $Nonce" -PropertyType String -Force | Out-Null
    $value = (Get-ItemProperty -Path $keyPath -Name 'Marker' -ErrorAction Stop).Marker
    $success = $value -eq "EdrTelemRegistryCreate $Nonce"
    $data = [pscustomobject]@{
        registry = [pscustomobject]@{
            key = $keyPath
            value_name = 'Marker'
            value_data = $value
            created = $success
        }
    }
    $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail "删除临时注册表键：$keyPath"
    if (-not $SkipCleanup) { Remove-Item -Path $keyPath -Recurse -Force -ErrorAction SilentlyContinue }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "创建注册表键/值 $keyPath\Marker 并验证读取。" -Data $data -Cleanup $cleanup `
        -Errors $(if ($success) { @() } else { @('注册表值读取不一致。') })
}

function Invoke-EdrRegistryModify {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $keyPath = Get-EdrRegistryPath -Nonce $Nonce
    New-Item -Path $keyPath -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name 'Marker' -Value 'before' -PropertyType String -Force | Out-Null
    Start-Sleep -Seconds 1
    Set-ItemProperty -Path $keyPath -Name 'Marker' -Value "EdrTelemRegistryModify $Nonce" -Force
    $value = (Get-ItemProperty -Path $keyPath -Name 'Marker' -ErrorAction Stop).Marker
    $success = $value -eq "EdrTelemRegistryModify $Nonce"
    $data = [pscustomobject]@{
        registry = [pscustomobject]@{
            key = $keyPath
            value_name = 'Marker'
            value_data = $value
            modified = $success
        }
    }
    $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail "删除临时注册表键：$keyPath"
    if (-not $SkipCleanup) { Remove-Item -Path $keyPath -Recurse -Force -ErrorAction SilentlyContinue }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "修改注册表值 $keyPath\Marker 并验证新值。" -Data $data -Cleanup $cleanup `
        -Errors $(if ($success) { @() } else { @('注册表值修改后读取不一致。') })
}

function Invoke-EdrRegistryDelete {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $keyPath = Get-EdrRegistryPath -Nonce $Nonce
    New-Item -Path $keyPath -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name 'Marker' -Value "EdrTelemRegistryDelete $Nonce" -PropertyType String -Force | Out-Null
    Start-Sleep -Seconds 1
    Remove-Item -Path $keyPath -Recurse -Force -ErrorAction Stop
    $gone = -not (Test-Path -Path $keyPath)
    $data = [pscustomobject]@{
        registry = [pscustomobject]@{
            key = $keyPath
            value_name = 'Marker'
            deleted = $gone
        }
    }
    return New-EdrBehaviorResult -Success $gone -Verification 'independent' `
        -Detail "删除注册表键 $keyPath 并验证不存在。" -Data $data `
        -Errors $(if ($gone) { @() } else { @('注册表键删除后仍存在。') })
}

function Get-EdrScheduledTaskName {
    param([Parameter(Mandatory = $true)][string]$Nonce, [string]$Suffix)
    return "EdrTelem_$(($Nonce.Substring(0, 8)).ToLowerInvariant())_$Suffix"
}

function Invoke-EdrScheduledTaskCreate {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $taskName = Get-EdrScheduledTaskName -Nonce $Nonce -Suffix 'create'
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument "/c echo $Nonce"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(1)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Description "EdrTelem $Nonce" -Force | Out-Null
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    $success = $null -ne $task
    $data = [pscustomobject]@{
        scheduled_task = [pscustomobject]@{
            name = $taskName
            action = 'cmd.exe /c echo <nonce>'
            trigger = 'one_year_once'
            created = $success
        }
    }
    $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail "删除计划任务：$taskName"
    if (-not $SkipCleanup) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "创建计划任务 $taskName 并验证存在。" -Data $data -Cleanup $cleanup `
        -Errors $(if ($success) { @() } else { @('计划任务创建后查询不到。') })
}

function Invoke-EdrScheduledTaskModify {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $taskName = Get-EdrScheduledTaskName -Nonce $Nonce -Suffix 'modify'
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument "/c echo $Nonce"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(1)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Description 'before' -Force | Out-Null
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Description "EdrTelemModified $Nonce" -Force | Out-Null
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    $success = $null -ne $task -and $task.Description -eq "EdrTelemModified $Nonce"
    $data = [pscustomobject]@{
        scheduled_task = [pscustomobject]@{
            name = $taskName
            description = $(if ($task) { $task.Description } else { $null })
            modified = $success
        }
    }
    $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail "删除计划任务：$taskName"
    if (-not $SkipCleanup) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "修改计划任务 $taskName 描述并验证。" -Data $data -Cleanup $cleanup `
        -Errors $(if ($success) { @() } else { @('计划任务修改后描述不一致。') })
}

function Invoke-EdrScheduledTaskDelete {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $taskName = Get-EdrScheduledTaskName -Nonce $Nonce -Suffix 'delete'
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument "/c echo $Nonce"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(1)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force | Out-Null
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
    $gone = $null -eq (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)
    $data = [pscustomobject]@{
        scheduled_task = [pscustomobject]@{
            name = $taskName
            deleted = $gone
        }
    }
    return New-EdrBehaviorResult -Success $gone -Verification 'independent' `
        -Detail "创建后删除计划任务 $taskName 并验证不存在。" -Data $data `
        -Errors $(if ($gone) { @() } else { @('计划任务删除后仍存在。') })
}

function Get-EdrServiceName {
    param([Parameter(Mandatory = $true)][string]$Nonce, [string]$Suffix)
    return "EdrTelemSvc_$(($Nonce.Substring(0, 8)).ToLowerInvariant())_$Suffix"
}

function Invoke-EdrServiceCreate {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $serviceName = Get-EdrServiceName -Nonce $Nonce -Suffix 'create'
    New-Service -Name $serviceName -BinaryPathName "cmd.exe /c exit 0" -DisplayName "EdrTelem Create $Nonce" -StartupType Manual -ErrorAction Stop | Out-Null
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    $success = $null -ne $service
    $data = [pscustomobject]@{
        service = [pscustomobject]@{
            name = $serviceName
            display_name = "EdrTelem Create $Nonce"
            binary_path = 'cmd.exe /c exit 0'
            start_type = 'Manual'
            state = $(if ($service) { $service.Status.ToString() } else { $null })
            created = $success
        }
    }
    $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail "删除临时服务：$serviceName"
    if (-not $SkipCleanup) {
        & sc.exe delete $serviceName | Out-Null
    }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "创建服务 $serviceName 并验证存在。" -Data $data -Cleanup $cleanup `
        -Errors $(if ($success) { @() } else { @('服务创建后查询不到。') })
}

function Invoke-EdrServiceModify {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $serviceName = Get-EdrServiceName -Nonce $Nonce -Suffix 'modify'
    New-Service -Name $serviceName -BinaryPathName "cmd.exe /c exit 0" -DisplayName 'before' -StartupType Manual -ErrorAction Stop | Out-Null
    Start-Sleep -Seconds 1
    & sc.exe config $serviceName start= disabled DisplayName= "EdrTelem Modified $Nonce" | Out-Null
    $modified = $LASTEXITCODE -eq 0
    $cim = Get-CimInstance Win32_Service -Filter "Name = '$serviceName'" -ErrorAction SilentlyContinue
    $success = $modified -and $null -ne $cim -and $cim.StartMode -eq 'Disabled'
    $data = [pscustomobject]@{
        service = [pscustomobject]@{
            name = $serviceName
            display_name = $(if ($cim) { $cim.DisplayName } else { $null })
            start_type = $(if ($cim) { $cim.StartMode } else { $null })
            modified = $success
        }
    }
    $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail "删除临时服务：$serviceName"
    if (-not $SkipCleanup) {
        & sc.exe delete $serviceName | Out-Null
    }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "修改服务 $serviceName 的启动类型与显示名并验证。" -Data $data -Cleanup $cleanup `
        -Errors $(if ($success) { @() } else { @('服务修改结果验证失败。') })
}

function Invoke-EdrServiceDelete {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $serviceName = Get-EdrServiceName -Nonce $Nonce -Suffix 'delete'
    New-Service -Name $serviceName -BinaryPathName "cmd.exe /c exit 0" -DisplayName "EdrTelem Delete $Nonce" -StartupType Manual -ErrorAction Stop | Out-Null
    Start-Sleep -Seconds 1
    & sc.exe delete $serviceName | Out-Null
    $gone = $null -eq (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)
    $data = [pscustomobject]@{
        service = [pscustomobject]@{
            name = $serviceName
            deleted = $gone
        }
    }
    return New-EdrBehaviorResult -Success $gone -Verification 'independent' `
        -Detail "创建后删除服务 $serviceName 并验证不存在。" -Data $data `
        -Errors $(if ($gone) { @() } else { @('服务删除后仍存在。') })
}

function Get-EdrDriverName {
    param([Parameter(Mandatory = $true)][string]$Nonce, [string]$Suffix)
    return "EdrTelemDrv_$(($Nonce.Substring(0, 8)).ToLowerInvariant())_$Suffix"
}

function Invoke-EdrDriverLoad {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $driverName = Get-EdrDriverName -Nonce $Nonce -Suffix 'load'
    $binaryPath = Join-Path $env:SystemRoot "System32\drivers\edrtelem_$Nonce.sys"
    $createOutput = @(& sc.exe create $driverName type= kernel start= demand binPath= $binaryPath DisplayName= "EdrTelem Driver Load $Nonce" 2>&1)
    $createExit = $LASTEXITCODE
    $created = $createExit -eq 0
    $queryOutput = @(& sc.exe query $driverName 2>&1)
    $queryOk = $LASTEXITCODE -eq 0
    $success = $created -and $queryOk
    $data = [pscustomobject]@{
        driver = [pscustomobject]@{
            name = $driverName
            image_path = $binaryPath
            start_type = 'demand'
            loaded = $false
            service_entry_created = $success
            create_exit_code = $createExit
        }
    }
    $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail "删除驱动服务配置项：$driverName"
    if (-not $SkipCleanup) {
        & sc.exe delete $driverName | Out-Null
    }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "创建内核驱动服务配置项 $driverName（未加载驱动）。" -Data $data -Cleanup $cleanup `
        -Errors $(if ($success) { @() } else { @("sc.exe create 输出：$($createOutput -join ' ')；sc.exe query 输出：$($queryOutput -join ' ')") })
}

function Invoke-EdrDriverModify {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $driverName = Get-EdrDriverName -Nonce $Nonce -Suffix 'modify'
    $binaryPath = Join-Path $env:SystemRoot "System32\drivers\edrtelem_$Nonce.sys"
    $createOutput = @(& sc.exe create $driverName type= kernel start= demand binPath= $binaryPath DisplayName= 'before' 2>&1)
    $created = $LASTEXITCODE -eq 0
    & sc.exe config $driverName start= auto DisplayName= "EdrTelem Driver Modified $Nonce" | Out-Null
    $modified = $LASTEXITCODE -eq 0
    $qcOutput = @(& sc.exe qc $driverName 2>&1)
    $qcOk = $LASTEXITCODE -eq 0
    $startLine = @($qcOutput | Where-Object { $_ -match 'START_TYPE' } | Select-Object -First 1)
    $auto = [bool]($startLine -match 'AUTO_START')
    $success = $created -and $modified -and $qcOk -and $auto
    $data = [pscustomobject]@{
        driver = [pscustomobject]@{
            name = $driverName
            image_path = $binaryPath
            start_type = $(if ($auto) { 'auto' } else { $null })
            modified = $success
        }
    }
    $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail "删除驱动服务配置项：$driverName"
    if (-not $SkipCleanup) {
        & sc.exe delete $driverName | Out-Null
    }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "修改驱动服务配置项 $driverName 的启动类型并验证。" -Data $data -Cleanup $cleanup `
        -Errors $(if ($success) { @() } else { @("sc.exe create 输出：$($createOutput -join ' ')；sc.exe qc 输出：$($qcOutput -join ' ')") })
}

function Invoke-EdrDriverUnload {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $driverName = Get-EdrDriverName -Nonce $Nonce -Suffix 'unload'
    $binaryPath = Join-Path $env:SystemRoot "System32\drivers\edrtelem_$Nonce.sys"
    & sc.exe create $driverName type= kernel start= demand binPath= $binaryPath DisplayName= "EdrTelem Driver Unload $Nonce" | Out-Null
    & sc.exe delete $driverName | Out-Null
    $gone = $null -eq (Get-CimInstance Win32_SystemDriver -Filter "Name = '$driverName'" -ErrorAction SilentlyContinue)
    $data = [pscustomobject]@{
        driver = [pscustomobject]@{
            name = $driverName
            image_path = $binaryPath
            unloaded = $gone
        }
    }
    return New-EdrBehaviorResult -Success $gone -Verification 'independent' `
        -Detail "创建后删除驱动服务配置项 $driverName 并验证不存在。" -Data $data `
        -Errors $(if ($gone) { @() } else { @('驱动服务配置项删除后仍存在。') })
}

function Get-EdrFreeSubstDrive {
    $used = @(Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Name)
    for ($code = 90; $code -ge 68; $code--) {
        $letter = [char]$code
        if ($used -notcontains $letter) { return "$($letter):" }
    }
    throw '没有可用的空闲盘符。'
}

function Invoke-EdrVirtualDiskMount {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $drive = Get-EdrFreeSubstDrive
    $mountPoint = Join-Path $WorkDir 'subst-root'
    New-Item -ItemType Directory -Path $mountPoint -Force | Out-Null
    $upanExe = Join-Path $WorkDir 'EDR-Upan.exe'
    Copy-Item -LiteralPath "$env:SystemRoot\System32\cmd.exe" -Destination $upanExe -Force
    $upanProcess = Start-Process -FilePath $upanExe -ArgumentList '/c','timeout','/t','20','/nobreak' -WindowStyle Hidden -PassThru
    try {
        & subst.exe $drive $mountPoint | Out-Null
        Start-Sleep -Milliseconds 500
        $mapped = $null -ne (Get-PSDrive -Name ($drive.TrimEnd(':')) -ErrorAction SilentlyContinue)
        $data = [pscustomobject]@{
            device = [pscustomobject]@{
                device_id = $drive
                type = 'virtual_usb'
                mount_point = $mountPoint
                process_name = 'EDR-Upan'
                process_id = $upanProcess.Id
                mounted = $mapped
            }
        }
        $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail "停止 EDR-Upan 进程并卸载虚拟盘符：$drive"
        return New-EdrBehaviorResult -Success $mapped -Verification 'independent' `
            -Detail "通过 EDR-Upan 进程模拟虚拟 U 盘插入并挂载 $drive。" -Data $data -Cleanup $cleanup `
            -Errors $(if ($mapped) { @() } else { @('虚拟 U 盘挂载后未出现在 PSDrive 中。') })
    }
    finally {
        Stop-Process -Id $upanProcess.Id -Force -ErrorAction SilentlyContinue
        if (-not $SkipCleanup) { & subst.exe $drive /d | Out-Null }
        Remove-Item -LiteralPath $upanExe -Force -ErrorAction SilentlyContinue
    }
}

function Get-EdrUsbVolumes {
    return @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2' -ErrorAction SilentlyContinue | ForEach-Object { $_.DeviceID })
}

function Invoke-EdrUsbUnmount {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $wait = if ($UsbWaitSeconds -gt 0) { $UsbWaitSeconds } else { (Get-EdrConfig).usb_wait_seconds }
    $before = Get-EdrUsbVolumes
    Write-EdrConsole -Message "请拔除 USB 设备，等待 $wait 秒..." -Color Cyan
    Start-Sleep -Seconds $wait
    $after = Get-EdrUsbVolumes
    $removed = @($before | Where-Object { $_ -notin $after })
    $success = $removed.Count -gt 0
    $data = [pscustomobject]@{
        device = [pscustomobject]@{
            type = 'usb'
            before = $before
            after = $after
            removed = $removed
            detected = $success
        }
    }
    if (-not $success) {
        return New-EdrBehaviorResult -Success $false -Verification 'manual' -Detail '等待期间未检测到 USB 设备拔除。' -Data $data -Skip 'USB_REMOVAL_NOT_OBSERVED'
    }
    return New-EdrBehaviorResult -Success $true -Verification 'manual' `
        -Detail "检测到 USB 设备移除：$($removed -join '、')。" -Data $data
}

function Invoke-EdrUsbMount {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $wait = if ($UsbWaitSeconds -gt 0) { $UsbWaitSeconds } else { (Get-EdrConfig).usb_wait_seconds }
    $before = Get-EdrUsbVolumes
    Write-EdrConsole -Message "请插入 USB 设备，等待 $wait 秒..." -Color Cyan
    Start-Sleep -Seconds $wait
    $after = Get-EdrUsbVolumes
    $added = @($after | Where-Object { $_ -notin $before })
    $success = $added.Count -gt 0
    $data = [pscustomobject]@{
        device = [pscustomobject]@{
            type = 'usb'
            before = $before
            after = $after
            added = $added
            detected = $success
        }
    }
    if (-not $success) {
        return New-EdrBehaviorResult -Success $false -Verification 'manual' -Detail '等待期间未检测到 USB 设备插入。' -Data $data -Skip 'USB_INSERTION_NOT_OBSERVED'
    }
    return New-EdrBehaviorResult -Success $true -Verification 'manual' `
        -Detail "检测到 USB 设备挂载：$($added -join '、')。" -Data $data
}

function Invoke-EdrGroupPolicyModify {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $keyPath = "HKLM:\SOFTWARE\Policies\EdrTelemetry\$Nonce"
    New-Item -Path $keyPath -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name 'Marker' -Value "EdrTelemGpo $Nonce" -PropertyType String -Force | Out-Null
    Set-ItemProperty -Path $keyPath -Name 'Marker' -Value "EdrTelemGpoModified $Nonce" -Force
    $value = (Get-ItemProperty -Path $keyPath -Name 'Marker' -ErrorAction Stop).Marker
    $success = $value -eq "EdrTelemGpoModified $Nonce"
    $data = [pscustomobject]@{
        policy = [pscustomobject]@{
            key = $keyPath
            value_name = 'Marker'
            value_data = $value
            modified = $success
        }
    }
    $cleanup = Get-EdrCleanupResult -Status 'succeeded' -Detail "删除临时组策略注册表键：$keyPath"
    if (-not $SkipCleanup) { Remove-Item -Path $keyPath -Recurse -Force -ErrorAction SilentlyContinue }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "在 HKLM\SOFTWARE\Policies 下创建并修改临时策略值，验证读取一致。" -Data $data -Cleanup $cleanup `
        -Errors $(if ($success) { @() } else { @('组策略临时值验证失败。') })
}

function Invoke-EdrNamedPipe {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup, [string]$Mode)
    $pipeName = "edrtelem_$Nonce"
    $fullName = "\\.\pipe\$pipeName"
    $message = "EdrTelemPipe $Nonce"
    $job = Start-Job -ScriptBlock {
        param($PipeName, $Message)
        $server = New-Object System.IO.Pipes.NamedPipeServerStream($PipeName, [System.IO.Pipes.PipeDirection]::InOut, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte)
        $writer = $null
        try {
            $server.WaitForConnection()
            $writer = New-Object System.IO.StreamWriter($server)
            $writer.AutoFlush = $true
            $writer.Write($Message)
            Start-Sleep -Milliseconds 300
        }
        finally {
            if ($writer) { $writer.Dispose() }
            $server.Dispose()
        }
    } -ArgumentList $pipeName, $message
    $client = $null
    try {
        $client = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
        $connected = $false
        for ($attempt = 0; $attempt -lt 10 -and -not $connected; $attempt++) {
            try {
                $client.Connect(1000)
                $connected = $true
            }
            catch {
                Start-Sleep -Milliseconds 200
            }
        }
        if (-not $connected) { throw '命名管道客户端连接超时。' }
        $reader = New-Object System.IO.StreamReader($client)
        $text = $reader.ReadLine()
        $success = $text -eq $message
    }
    finally {
        if ($client) { $client.Dispose() }
        Wait-Job $job -Timeout 5 -ErrorAction SilentlyContinue | Out-Null
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
    $data = [pscustomobject]@{
        pipe = [pscustomobject]@{
            name = $fullName
            mode = $Mode
            connected = $success
        }
    }
    $modeLabel = if ($Mode -eq 'create') { '创建并接受连接' } else { '客户端连接' }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "命名管道 $fullName $modeLabel，数据验证成功。" -Data $data `
        -Errors $(if ($success) { @() } else { @('命名管道数据交换验证失败。') })
}

function Invoke-EdrNamedPipeCreate {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    return Invoke-EdrNamedPipe -WorkDir $WorkDir -Nonce $Nonce -ScenarioId $ScenarioId -ServiceName $ServiceName -UsbWaitSeconds $UsbWaitSeconds -ConfirmManual:$ConfirmManual -SkipCleanup:$SkipCleanup -Mode 'create'
}

function Invoke-EdrNamedPipeConnect {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    return Invoke-EdrNamedPipe -WorkDir $WorkDir -Nonce $Nonce -ScenarioId $ScenarioId -ServiceName $ServiceName -UsbWaitSeconds $UsbWaitSeconds -ConfirmManual:$ConfirmManual -SkipCleanup:$SkipCleanup -Mode 'connect'
}

function Get-EdrAgentServiceCandidates {
    $known = @('TencentIOA', 'IOAClient', 'TencentSafeCare', 'HuorongSysService', 'wsctrl', '360EntClientSvc', '360Srv')
    $found = @()
    foreach ($name in $known) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($service) { $found += $service }
    }
    if ($found.Count -eq 0) {
        $found = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
            Where-Object { $_.PathName -match 'Tencent|IOA|Huorong|360|QQPCTray' } |
            ForEach-Object { Get-Service -Name $_.Name -ErrorAction SilentlyContinue })
    }
    Write-Output -NoEnumerate $found
}

function Invoke-EdrAgentStart {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $target = $ServiceName
    if (-not $target) {
        $candidates = @(Get-EdrAgentServiceCandidates)
        if ($candidates.Count -eq 0) {
            return New-EdrBehaviorResult -Success $false -Verification 'skipped' -Detail '未找到已知 EDR 服务；请用 -ServiceName 显式指定。' -Skip 'NO_EDR_SERVICE'
        }
        $target = $candidates[0].Name
    }
    $service = Get-Service -Name $target -ErrorAction SilentlyContinue
    if (-not $service) {
        return New-EdrBehaviorResult -Success $false -Verification 'skipped' -Detail "服务 $target 不存在。" -Skip 'SERVICE_NOT_FOUND'
    }
    $before = $service.Status.ToString()
    if ($before -eq 'Running') {
        return New-EdrBehaviorResult -Success $false -Verification 'skipped' -Detail "服务 $target 已在运行。" `
            -Data ([pscustomobject]@{ agent = [pscustomobject]@{ service_name = $target; operation = 'start'; status_before = $before } }) -Skip 'ALREADY_RUNNING'
    }
    Start-Service -Name $target -ErrorAction Stop
    Start-Sleep -Milliseconds 500
    $after = (Get-Service -Name $target).Status.ToString()
    $success = $after -eq 'Running'
    $data = [pscustomobject]@{
        agent = [pscustomobject]@{
            service_name = $target
            operation = 'start'
            status_before = $before
            status_after = $after
        }
    }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "启动 EDR 服务 $target：$before -> $after。" -Data $data `
        -Errors $(if ($success) { @() } else { @('服务启动后未进入 Running。') })
}

function Invoke-EdrAgentStop {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    if (-not $ServiceName) {
        return New-EdrBehaviorResult -Success $false -Verification 'skipped' `
            -Detail '停止 EDR 代理会临时失去防护，必须显式提供 -ServiceName，并建议使用 -ConfirmManual 确认测试环境。' -Skip 'SERVICE_NAME_REQUIRED'
    }
    if (-not $ConfirmManual) {
        return New-EdrBehaviorResult -Success $false -Verification 'skipped' `
            -Detail '停止 EDR 代理需要 -ConfirmManual 确认在隔离测试机执行。' -Skip 'MANUAL_CONFIRM_REQUIRED'
    }
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        return New-EdrBehaviorResult -Success $false -Verification 'skipped' -Detail "服务 $ServiceName 不存在。" -Skip 'SERVICE_NOT_FOUND'
    }
    $before = $service.Status.ToString()
    if ($before -eq 'Stopped') {
        return New-EdrBehaviorResult -Success $false -Verification 'skipped' -Detail "服务 $ServiceName 已停止。" -Skip 'ALREADY_STOPPED'
    }
    Stop-Service -Name $ServiceName -Force -ErrorAction Stop
    Start-Sleep -Milliseconds 500
    $after = (Get-Service -Name $ServiceName).Status.ToString()
    $success = $after -eq 'Stopped'
    $data = [pscustomobject]@{
        agent = [pscustomobject]@{
            service_name = $ServiceName
            operation = 'stop'
            status_before = $before
            status_after = $after
        }
    }
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "停止 EDR 服务 $ServiceName：$before -> $after。测试后请手动恢复。" -Data $data `
        -Errors $(if ($success) { @() } else { @('服务停止后未进入 Stopped。') })
}

function Invoke-EdrAgentInstall {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    return New-EdrBehaviorResult -Success $false -Verification 'manual' `
        -Detail '代理安装依赖产品安装包与控制台，无法通用生成；可在测试机手动安装后用 -ConfirmManual 记录外部观察。' `
        -Data ([pscustomobject]@{ agent = [pscustomobject]@{ service_name = $ServiceName; operation = 'install' } }) -Skip 'MANUAL_REQUIRED'
}

function Invoke-EdrAgentUninstall {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    return New-EdrBehaviorResult -Success $false -Verification 'manual' `
        -Detail '代理卸载依赖产品卸载流程，无法通用生成；可在测试机手动卸载后用 -ConfirmManual 记录外部观察。' `
        -Data ([pscustomobject]@{ agent = [pscustomobject]@{ service_name = $ServiceName; operation = 'uninstall' } }) -Skip 'MANUAL_REQUIRED'
}

function Invoke-EdrAgentKeepAlive {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $candidates = @(Get-EdrAgentServiceCandidates)
    if ($candidates.Count -eq 0) {
        return New-EdrBehaviorResult -Success $false -Verification 'skipped' -Detail '未找到已知 EDR 服务，无法验证保活。' -Skip 'NO_EDR_SERVICE'
    }
    $running = @($candidates | Where-Object { $_.Status -eq 'Running' })
    $data = [pscustomobject]@{
        agent = [pscustomobject]@{
            service_names = @($candidates | ForEach-Object { $_.Name })
            running_services = @($running | ForEach-Object { $_.Name })
            operation = 'keepalive'
        }
    }
    $success = $running.Count -gt 0
    return New-EdrBehaviorResult -Success $success -Verification 'independent' `
        -Detail "探测到 EDR 服务 $($running.Count) 个正在运行，保活状态正常。" -Data $data `
        -Errors $(if ($success) { @() } else { @('未发现正在运行的 EDR 服务。') })
}

function Invoke-EdrAgentError {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    return New-EdrBehaviorResult -Success $false -Verification 'manual' `
        -Detail '代理异常报错依赖产品运行状态，无法通用生成；可在测试机观察后用 -ConfirmManual 记录外部观察。' `
        -Data ([pscustomobject]@{ agent = [pscustomobject]@{ service_name = $ServiceName; operation = 'error' } }) -Skip 'MANUAL_REQUIRED'
}

function Remove-EdrWmiInstance {
    param([Parameter(Mandatory = $true)][string]$Namespace, [Parameter(Mandatory = $true)][string]$Class, [Parameter(Mandatory = $true)][string]$Name)
    $instance = Get-WmiObject -Namespace $Namespace -Class $Class -Filter "Name = '$Name'" -ErrorAction SilentlyContinue
    if ($instance) { $instance.Delete() | Out-Null }
}

function Invoke-EdrWmiConsumerFilterBinding {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $namespace = 'root\subscription'
    $name = "EdrTelem_$(($Nonce.Substring(0, 8)).ToLowerInvariant())"
    try {
        $filter = Set-WmiInstance -Namespace $namespace -Class __EventFilter -Arguments @{
            Name = $name
            EventNamespace = 'root\cimv2'
            QueryLanguage = 'WQL'
            Query = "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name='edrtelem-nonexistent'"
        } -ErrorAction Stop
        $consumer = Set-WmiInstance -Namespace $namespace -Class CommandLineEventConsumer -Arguments @{
            Name = $name
            CommandLineTemplate = "cmd.exe /c echo $Nonce"
        } -ErrorAction Stop
        $binding = Set-WmiInstance -Namespace $namespace -Class __FilterToConsumerBinding -Arguments @{
            Filter = $filter
            Consumer = $consumer
        } -ErrorAction Stop
        $success = $null -ne $binding
        $data = [pscustomobject]@{
            wmi = [pscustomobject]@{
                name = $name
                class = '__FilterToConsumerBinding'
                namespace = $namespace
                filter = $filter.Name
                consumer = $consumer.Name
                created = $success
            }
        }
        $cleanupDetail = @('删除 FilterToConsumerBinding、EventConsumer、EventFilter')
        if (-not $SkipCleanup) {
            Remove-EdrWmiInstance -Namespace $namespace -Class __FilterToConsumerBinding -Name $name
            Remove-EdrWmiInstance -Namespace $namespace -Class CommandLineEventConsumer -Name $name
            Remove-EdrWmiInstance -Namespace $namespace -Class __EventFilter -Name $name
        }
        return New-EdrBehaviorResult -Success $success -Verification 'independent' `
            -Detail "创建 WMI 事件消费者/过滤器/绑定：$name 并验证。" -Data $data `
            -Cleanup (Get-EdrCleanupResult -Status 'succeeded' -Detail ($cleanupDetail -join '；')) `
            -Errors $(if ($success) { @() } else { @('WMI 绑定创建失败。') })
    }
    catch {
        return New-EdrBehaviorResult -Success $false -Verification 'error' -Detail "WMI 操作失败：$($_.Exception.Message)" `
            -Errors @($_.Exception.Message) -Skip 'WMI_OPERATION_FAILED'
    }
}

function Invoke-EdrWmiEventConsumer {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $namespace = 'root\subscription'
    $name = "EdrTelem_$(($Nonce.Substring(0, 8)).ToLowerInvariant())"
    try {
        $consumer = Set-WmiInstance -Namespace $namespace -Class CommandLineEventConsumer -Arguments @{
            Name = $name
            CommandLineTemplate = "cmd.exe /c echo $Nonce"
        } -ErrorAction Stop
        $success = $null -ne $consumer
        $data = [pscustomobject]@{
            wmi = [pscustomobject]@{
                name = $name
                class = 'CommandLineEventConsumer'
                namespace = $namespace
                created = $success
            }
        }
        if (-not $SkipCleanup) {
            Remove-EdrWmiInstance -Namespace $namespace -Class CommandLineEventConsumer -Name $name
        }
        return New-EdrBehaviorResult -Success $success -Verification 'independent' `
            -Detail "创建 WMI 事件消费者 $name 并验证。" -Data $data `
            -Cleanup (Get-EdrCleanupResult -Status 'succeeded' -Detail '删除临时 EventConsumer。') `
            -Errors $(if ($success) { @() } else { @('WMI 事件消费者创建失败。') })
    }
    catch {
        return New-EdrBehaviorResult -Success $false -Verification 'error' -Detail "WMI 操作失败：$($_.Exception.Message)" `
            -Errors @($_.Exception.Message) -Skip 'WMI_OPERATION_FAILED'
    }
}

function Invoke-EdrWmiEventFilter {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $namespace = 'root\subscription'
    $name = "EdrTelem_$(($Nonce.Substring(0, 8)).ToLowerInvariant())"
    try {
        $filter = Set-WmiInstance -Namespace $namespace -Class __EventFilter -Arguments @{
            Name = $name
            EventNamespace = 'root\cimv2'
            QueryLanguage = 'WQL'
            Query = "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name='edrtelem-nonexistent'"
        } -ErrorAction Stop
        $success = $null -ne $filter
        $data = [pscustomobject]@{
            wmi = [pscustomobject]@{
                name = $name
                class = '__EventFilter'
                namespace = $namespace
                query = $filter.Query
                created = $success
            }
        }
        if (-not $SkipCleanup) {
            Remove-EdrWmiInstance -Namespace $namespace -Class __EventFilter -Name $name
        }
        return New-EdrBehaviorResult -Success $success -Verification 'independent' `
            -Detail "创建 WMI 事件过滤器 $name 并验证。" -Data $data `
            -Cleanup (Get-EdrCleanupResult -Status 'succeeded' -Detail '删除临时 EventFilter。') `
            -Errors $(if ($success) { @() } else { @('WMI 事件过滤器创建失败。') })
    }
    catch {
        return New-EdrBehaviorResult -Success $false -Verification 'error' -Detail "WMI 操作失败：$($_.Exception.Message)" `
            -Errors @($_.Exception.Message) -Skip 'WMI_OPERATION_FAILED'
    }
}

function Invoke-EdrBitsJob {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $source = Join-Path $WorkDir "edrtelem-bits-source-$Nonce.txt"
    $target = Join-Path $WorkDir "edrtelem-bits-target-$Nonce.txt"
    [System.IO.File]::WriteAllText($source, "EdrTelemBits $Nonce", (New-Object System.Text.UTF8Encoding($false)))
    $jobName = "EdrTelem_$(($Nonce.Substring(0, 8)).ToLowerInvariant())"
    try {
        Import-Module BitsTransfer -ErrorAction Stop
        Start-BitsTransfer -Source $source -Destination $target -DisplayName $jobName -ErrorAction Stop | Out-Null
        $success = Test-Path -LiteralPath $target
        $data = [pscustomobject]@{
            bits = [pscustomobject]@{
                job_name = $jobName
                source = $source
                destination = $target
                bytes_total = $(if ($success) { (Get-Item -LiteralPath $target).Length } else { 0 })
                completed = $success
            }
        }
        return New-EdrBehaviorResult -Success $success -Verification 'independent' `
            -Detail "通过 BITS 本地作业复制文件：$jobName。" -Data $data `
            -Errors $(if ($success) { @() } else { @('BITS 作业完成后目标文件不存在。') })
    }
    catch {
        return New-EdrBehaviorResult -Success $false -Verification 'error' -Detail "BITS 作业失败：$($_.Exception.Message)" `
            -Errors @($_.Exception.Message) -Skip 'BITS_UNAVAILABLE'
    }
}

function Invoke-EdrPowerShellScriptBlock {
    param([Parameter(Mandatory = $true)]$WorkDir, [Parameter(Mandatory = $true)][string]$Nonce, [string]$ScenarioId, [string]$ServiceName, [int]$UsbWaitSeconds, [bool]$ConfirmManual, [bool]$SkipCleanup)
    $script = "`$marker = 'EdrTelemScriptBlock $Nonce'; `$marker"
    $result = [scriptblock]::Create($script).Invoke()
    $text = ($result | Out-String).Trim()
    $success = $text.Contains($Nonce)
    $scriptBlockId = $null
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104 } -MaxEvents 5 -ErrorAction SilentlyContinue
        $recent = $events | Where-Object { $_.Message -match $Nonce } | Select-Object -First 1
        if ($recent) { $scriptBlockId = $recent.Properties[3].Value }
    }
    catch { }
    $data = [pscustomobject]@{
        powershell = [pscustomobject]@{
            script_block = $script
            script_block_id = $scriptBlockId
            executed = $success
            log_verified = $null -ne $scriptBlockId
        }
    }
    return New-EdrBehaviorResult -Success $success -Verification $(if ($scriptBlockId) { 'independent' } else { 'api' }) `
        -Detail "执行包含 nonce 的脚本块并验证结果；脚本块日志事件验证=$(if ($scriptBlockId) { '成功' } else { '未读取到' })。" -Data $data `
        -Errors $(if ($success) { @() } else { @('脚本块执行结果不包含 nonce。') })
}
