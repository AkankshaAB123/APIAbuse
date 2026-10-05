# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller specification file for ThreatGuard Windows Endpoint Security Agent.

Produces a single-file standalone executable (threatguard-agent.exe) that runs
independently of Python, Git, and VS Code.
"""

import sys
from pathlib import Path

block_cipher = None

repo_root = Path.cwd().resolve()

a = Analysis(
    [str(repo_root / "agents" / "windows" / "__main__.py")],
    pathex=[str(repo_root)],
    binaries=[],
    datas=[],
    hiddenimports=[
        "requests",
        "urllib3",
        "agents.windows",
        "agents.windows.config",
        "agents.windows.device",
        "agents.windows.telemetry",
        "agents.windows.api_client",
        "agents.windows.notifier",
        "agents.windows.monitor",
        "agents.windows.logging_config",
        "agents.windows.service",
        "servicemanager",
        "win32service",
        "win32serviceutil",
        "win32event",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "torch",
        "transformers",
        "sentence_transformers",
        "scipy",
        "numpy",
        "pandas",
        "xgboost",
        "matplotlib",
        "tkinter",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="threatguard-agent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
