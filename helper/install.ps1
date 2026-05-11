#requires -Version 5.1
<#
.SYNOPSIS
    安装 Email Helper：复制 .exe / 注册 URL 协议 / 启用开机自启 / 立即启动。

.DESCRIPTION
    用户拿到 EmailHelper.exe + install.ps1 + uninstall.ps1（在同一目录里），
    右键 install.ps1 → "用 PowerShell 运行"，约 3 秒后系统托盘出现 Helper 图标。

    完全用 HKCU 注册表，不需要管理员权限。

.PARAMETER InstallDir
    自定义安装目录，默认 ``$env:LOCALAPPDATA\EmailHelper``。

.PARAMETER NoStart
    安装后不立即启动（默认安装完会自动起一份）。

.PARAMETER NoAutostart
    不写开机自启注册表项（默认会写）。

.EXAMPLE
    .\install.ps1
    .\install.ps1 -InstallDir "D:\Apps\EmailHelper"
    .\install.ps1 -NoAutostart
#>

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\EmailHelper",
    [switch]$NoStart,
    [switch]$NoAutostart
)

$ErrorActionPreference = "Stop"

$here    = Split-Path -Parent $MyInvocation.MyCommand.Definition
$exeName = "EmailHelper.exe"
$exeSrc  = Join-Path $here $exeName

if (-not (Test-Path $exeSrc)) {
    Write-Error "未找到 $exeSrc，请把 install.ps1 和 $exeName 放在同一目录。"
    exit 1
}

Write-Host "==> 安装目录: $InstallDir" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$exeDst = Join-Path $InstallDir $exeName

# 如果旧版本进程还在跑，先杀掉再覆盖
$running = Get-Process -Name "EmailHelper" -ErrorAction SilentlyContinue
if ($running) {
    Write-Host "==> 检测到旧 Helper 进程，先停止" -ForegroundColor Yellow
    $running | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}

Copy-Item -Force $exeSrc $exeDst
Write-Host "==> 已复制 $exeName 到 $exeDst" -ForegroundColor Green

# ---- 注册 emailhelper:// URL 协议 (HKCU) -----------------------------

$proto    = "emailhelper"
$baseKey  = "HKCU:\Software\Classes\$proto"
$cmdKey   = "$baseKey\shell\open\command"
$iconKey  = "$baseKey\DefaultIcon"

New-Item -Path $baseKey -Force | Out-Null
Set-ItemProperty -Path $baseKey -Name "(Default)"   -Value "URL:Email Helper"
Set-ItemProperty -Path $baseKey -Name "URL Protocol" -Value ""
New-Item -Path $iconKey -Force | Out-Null
Set-ItemProperty -Path $iconKey -Name "(Default)" -Value "$exeDst,0"
New-Item -Path $cmdKey -Force | Out-Null
Set-ItemProperty -Path $cmdKey -Name "(Default)" -Value ('"' + $exeDst + '" "%1"')
Write-Host "==> 已注册 URL 协议 emailhelper://" -ForegroundColor Green

# ---- 开机自启 ------------------------------------------------------------

if (-not $NoAutostart) {
    $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    Set-ItemProperty -Path $runKey -Name "EmailHelper" `
        -Value ('"' + $exeDst + '" --silent')
    Write-Host "==> 已启用开机自启" -ForegroundColor Green
} else {
    Write-Host "==> 跳过开机自启 (-NoAutostart)" -ForegroundColor DarkYellow
}

# ---- 立即启动 ------------------------------------------------------------

if (-not $NoStart) {
    Start-Process -FilePath $exeDst -ArgumentList "--silent"
    Write-Host "==> 已启动 Helper（后台 + 系统托盘）" -ForegroundColor Green
} else {
    Write-Host "==> 跳过自动启动 (-NoStart)" -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " 安装完成" -ForegroundColor Green
Write-Host " 位置 : $exeDst"
Write-Host ""
Write-Host " 下一步：" -ForegroundColor Yellow
Write-Host "  1. 检查系统托盘是否出现 Email Helper 图标"
Write-Host "  2. 用 xiaoxuan 账号登录 Web 面板"
Write-Host "  3. 点侧边栏「📬 邮箱助手」→「🚀 启动助手」完成首次绑定"
Write-Host ""
Write-Host " 卸载：右键 uninstall.ps1 → 用 PowerShell 运行"
Write-Host "============================================" -ForegroundColor Cyan
