# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

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
        'multiprocessing',
        'multiprocessing.reduction',
        'json',
        'shutil',
        'pathlib',
        'signal',
        'pickle',           # ★ 必须保留
        'copyreg',
        '_compat_pickle',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'unittest',
        'email',
        'html',
        'http',
        'urllib',
        'xml',
        'pydoc',
        'doctest',
        'optparse',
        # 'pickle',   ← 已删除！这是崩溃根因
        'numpy',
        'pandas',
        'matplotlib',
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
