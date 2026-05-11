# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller 打包配置：把 helper/ 打成单文件 EmailHelper.exe

设计要点
--------
- ``datas``：把项目根 ``database/`` 与 ``core/`` 整个塞进 .exe（Stage 2 移植
  完 outlook 自动化后，helper actions 会用到这两个目录里的模块）。
- ``hiddenimports``：pystray 在 Windows 下用 ``pystray._win32``；
  PIL.ImageDraw / PIL.Image 是 pystray 启动时画图标用的；
  Stage 2 添加浏览器自动化时再加 ``cv2`` / ``pyautogui`` / ``numpy`` /
  ``collect_submodules('DrissionPage')``。
- ``console=False`` + ``windowed``：双击 .exe 不弹黑窗。
- ``upx=True``：体积压缩约 30%；如果用户机器装了奇怪杀软误报，
  可在打包命令上加 ``--upx-dir=...`` 或直接关掉。

打包命令（推荐走 build.ps1）：
    python -m PyInstaller --noconfirm helper/EmailHelper.spec
"""
import os

# 自动算出项目根目录（让 spec 在任何 checkout 路径下都能工作）
SPEC_DIR = os.path.dirname(os.path.abspath(SPEC))  # noqa: F821
PROJECT_ROOT = os.path.dirname(SPEC_DIR)

# Stage 1：仅打包 helper 模块自身 + database/helper_token.py + core/helper_registry.py
# Stage 2 移植 outlook_service.py 后会加 core/outlook_service.py 等
datas = [
    (os.path.join(PROJECT_ROOT, "database"), "database"),
    (os.path.join(PROJECT_ROOT, "core"), "core"),
]

hiddenimports = [
    "pystray._win32",
    "PIL.ImageDraw",
    "PIL.Image",
    # Stage 2 浏览器自动化的依赖：
    # "pyautogui",
    # "cv2",
    # "numpy",
]

try:
    from PyInstaller.utils.hooks import collect_data_files
    datas += collect_data_files("certifi")
except Exception:  # noqa: BLE001
    # 容许 PyInstaller 钩子缺失时 fall back（只是 SSL 证书可能要靠系统）
    pass

# Stage 2 解开下面这行让 DrissionPage 子模块自动注入
# from PyInstaller.utils.hooks import collect_submodules
# hiddenimports += collect_submodules("DrissionPage")


a = Analysis(  # noqa: F821
    [os.path.join(SPEC_DIR, "main.py")],
    pathex=[PROJECT_ROOT, SPEC_DIR],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)  # noqa: F821

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="EmailHelper",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,                # 无控制台窗口
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
