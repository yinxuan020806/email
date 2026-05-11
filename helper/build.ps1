#requires -Version 5.1
<#
.SYNOPSIS
    把 helper/ 打包成单文件 EmailHelper.exe。

.DESCRIPTION
    自动创建虚拟环境、装依赖、跑 PyInstaller、把产物拷到 static/helper/ 让
    Web 面板的「下载」按钮能直接给用户。

.PARAMETER Clean
    打包前先清理 build/ 与 dist/ 目录（默认增量）。

.PARAMETER VenvDir
    虚拟环境目录，默认 ``helper\.build_venv``。

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Clean
#>

param(
    [switch]$Clean,
    [string]$VenvDir = ""
)

$ErrorActionPreference = "Stop"

$here     = Split-Path -Parent $MyInvocation.MyCommand.Definition
$repoRoot = Split-Path -Parent $here
if (-not $VenvDir) { $VenvDir = Join-Path $here ".build_venv" }

$specFile  = Join-Path $here "EmailHelper.spec"
$buildDir  = Join-Path $here "build"
$distDir   = Join-Path $here "dist"
$mainPy    = Join-Path $here "main.py"
$staticOut = Join-Path $repoRoot "static\helper"

if ($Clean) {
    foreach ($p in @($buildDir, $distDir)) {
        if (Test-Path $p) {
            Write-Host "==> 清理 $p" -ForegroundColor Yellow
            Remove-Item -Recurse -Force $p -ErrorAction SilentlyContinue
        }
    }
}

# 1) venv
if (-not (Test-Path $VenvDir)) {
    Write-Host "==> 创建虚拟环境 $VenvDir" -ForegroundColor Cyan
    python -m venv $VenvDir
}
$python = Join-Path $VenvDir "Scripts\python.exe"
$pip    = Join-Path $VenvDir "Scripts\pip.exe"
if (-not (Test-Path $python)) {
    Write-Error "找不到 $python，venv 创建失败"
    exit 1
}

# 2) 装依赖
Write-Host "==> 升级 pip" -ForegroundColor Cyan
& $python -m pip install --upgrade pip wheel | Out-Null
Write-Host "==> 装 helper 依赖" -ForegroundColor Cyan
& $pip install -r (Join-Path $here "requirements.txt")
Write-Host "==> 装 PyInstaller" -ForegroundColor Cyan
& $pip install "pyinstaller>=6.0,<7"

# 3) 打包
Push-Location $here
try {
    if (Test-Path $specFile) {
        Write-Host "==> 用 $specFile 打包" -ForegroundColor Cyan
        & $python -m PyInstaller --noconfirm $specFile
    } else {
        Write-Host "==> 用 onefile 模式打包 main.py" -ForegroundColor Cyan
        & $python -m PyInstaller `
            --noconfirm `
            --onefile `
            --windowed `
            --name "EmailHelper" `
            --hidden-import "pystray._win32" `
            --hidden-import "PIL._tkinter_finder" `
            --paths $repoRoot `
            $mainPy
    }
}
finally {
    Pop-Location
}

# 4) 拷到 static/helper/
$exeBuilt = Join-Path $distDir "EmailHelper.exe"
if (-not (Test-Path $exeBuilt)) {
    Write-Error "打包产物不存在：$exeBuilt"
    exit 1
}
New-Item -ItemType Directory -Force -Path $staticOut | Out-Null
Copy-Item -Force $exeBuilt (Join-Path $staticOut "EmailHelper.exe")
Copy-Item -Force (Join-Path $here "install.ps1")   (Join-Path $staticOut "install.ps1")
Copy-Item -Force (Join-Path $here "uninstall.ps1") (Join-Path $staticOut "uninstall.ps1")
Write-Host "==> 已拷贝到 $staticOut" -ForegroundColor Green

$sizeMB = [math]::Round((Get-Item $exeBuilt).Length / 1MB, 1)
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " 打包完成" -ForegroundColor Green
Write-Host " EmailHelper.exe : $sizeMB MB"
Write-Host " 位置 : $exeBuilt"
Write-Host ""
Write-Host " 已自动同步到 Web 面板下载目录："
Write-Host "   $staticOut"
Write-Host "============================================" -ForegroundColor Cyan
