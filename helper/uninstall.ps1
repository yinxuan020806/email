#requires -Version 5.1
<#
.SYNOPSIS
    卸载 Email Helper：杀进程、删 URL 协议、删开机自启、删安装目录。

.PARAMETER InstallDir
    自定义安装目录，默认 ``$env:LOCALAPPDATA\EmailHelper``。

.PARAMETER KeepConfig
    保留 ``$env:APPDATA\EmailHelper`` 下的 config.json 与日志。
    默认会一并删除。

.EXAMPLE
    .\uninstall.ps1
    .\uninstall.ps1 -KeepConfig
#>

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\EmailHelper",
    [switch]$KeepConfig
)

$ErrorActionPreference = "Continue"

# 1. 杀进程
$running = Get-Process -Name "EmailHelper" -ErrorAction SilentlyContinue
if ($running) {
    Write-Host "==> 停止 Helper 进程" -ForegroundColor Yellow
    $running | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 400
}

# 2. 删开机自启
$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
try {
    Remove-ItemProperty -Path $runKey -Name "EmailHelper" -ErrorAction SilentlyContinue
    Write-Host "==> 已移除开机自启" -ForegroundColor Green
} catch { }

# 3. 删 URL 协议
$baseKey = "HKCU:\Software\Classes\emailhelper"
if (Test-Path $baseKey) {
    Remove-Item -Path $baseKey -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "==> 已移除 emailhelper:// URL 协议" -ForegroundColor Green
}

# 4. 删 .exe 与安装目录
if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
    Write-Host "==> 已删除 $InstallDir" -ForegroundColor Green
}

# 5. 配置目录
$configDir = Join-Path $env:APPDATA "EmailHelper"
if (-not $KeepConfig -and (Test-Path $configDir)) {
    Remove-Item -Recurse -Force $configDir -ErrorAction SilentlyContinue
    Write-Host "==> 已删除配置目录 $configDir" -ForegroundColor Green
} elseif ($KeepConfig) {
    Write-Host "==> 保留配置目录 $configDir (-KeepConfig)" -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " 卸载完成" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
