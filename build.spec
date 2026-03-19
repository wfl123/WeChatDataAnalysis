# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.crypto import PyiBlockCipher

# ★ 打包前请修改为你自己的密钥（16/24/32位任意字符串）
# ★ 请勿将真实密钥提交到版本控制，可通过环境变量读取，例如:
# ★   import os; key = os.environ.get('WXKEY_BUILD_KEY', 'WxKey@2026#Secret')
block_cipher = PyiBlockCipher(key='WxKey@2026#Secret')

a = Analysis(
    ['01_wx_win.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'wx_find_and_copy',
        'psutil',
        'psutil._pswindows',
        'psutil._psutil_windows',
        'frida',
        'frida._frida',
        'winreg',
        'ctypes',
        'ctypes.wintypes',
        'threading',
        'concurrent.futures',
        'json',
        'shutil',
        'pathlib',
        'signal',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter', 'unittest', 'email', 'html',
        'http', 'urllib', 'xml', 'pydoc',
        'doctest', 'optparse', 'pickle',
        'numpy', 'pandas', 'matplotlib',
    ],
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
    name='WxKeyExtractor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    icon=None,
)
