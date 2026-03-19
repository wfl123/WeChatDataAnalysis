@echo off
chcp 65001 >nul
setlocal

set PYTHON=D:\APPLOAD\Anaconda\envs\modelscope_py39\python.exe
set SCRIPT_DIR=%~dp0

echo ========================================
echo  WxKeyExtractor 混淆打包脚本
echo ========================================
echo.

REM ── Step 1: 清理上次构建 ──────────────────────────────────
if exist dist   rd /s /q dist
if exist build  rd /s /q build
if exist dist_obf rd /s /q dist_obf

REM ── Step 2: 安装 pyarmor（如未安装）────────────────────────
%PYTHON% -m pip show pyarmor >nul 2>&1
if %errorlevel% neq 0 (
    echo [1/3] 安装 pyarmor...
    %PYTHON% -m pip install pyarmor --quiet
) else (
    echo [1/3] pyarmor 已安装，跳过
)

REM ── Step 3: pyarmor 混淆源码 ────────────────────────────────
echo [2/3] 混淆源码...
%PYTHON% -m pyarmor gen --output dist_obf 01_wx_win.py wx_find_and_copy.py
if %errorlevel% neq 0 (
    echo [WARN] pyarmor 混淆失败，使用原始源码打包（仍有 AES 加密保护）
    if not exist dist_obf mkdir dist_obf
    copy 01_wx_win.py dist_obf\01_wx_win.py >nul 2>&1
    copy wx_find_and_copy.py dist_obf\wx_find_and_copy.py >nul 2>&1
)

REM ── Step 4: PyInstaller 打包（含 AES 加密）──────────────────
echo [3/3] PyInstaller 打包（AES 加密字节码）...
cd dist_obf
%PYTHON% -m PyInstaller ..\build.spec --clean --noconfirm
cd ..

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] 打包失败！
    pause
    exit /b 1
)

REM ── 复制产物到根目录 dist ───────────────────────────────────
if not exist dist mkdir dist
copy dist_obf\dist\WxKeyExtractor.exe dist\WxKeyExtractor.exe >nul

echo.
echo ========================================
echo  打包完成！
echo  输出: dist\WxKeyExtractor.exe
echo  保护: pyarmor 混淆 + AES 字节码加密
echo ========================================
echo.
dir dist\WxKeyExtractor.exe
pause
