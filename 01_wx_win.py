#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wx_key_extractor.py — 微信 4.0+ 数据库密钥一键提取工具
支持版本: WeChat 4.0.x ~ 4.1.x 及以上 (Windows x64)
依赖: pip install frida psutil
"""

import sys
import ctypes
import ctypes.wintypes
import time
import threading
import os
import shutil
import json
import signal
import logging as _logging
import traceback as _traceback
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── 获取 exe/脚本实际所在目录（全局，最先定义）────────────────────────────────
def _get_exe_dir() -> Path:
    """打包后 __file__ 指向临时目录，必须用 sys.executable。"""
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent.resolve()
    return Path(__file__).parent.resolve()


# ── 运行日志（写入 exe 同目录）────────────────────────────────────────────────
def _setup_file_log() -> Path:
    """把所有 print/stderr 同步写入日志文件，返回日志路径。"""
    log_dir  = _get_exe_dir()
    log_name = datetime.now().strftime("WxKeyExtractor_%Y%m%d_%H%M%S.log")
    log_path = log_dir / log_name

    class _Tee:
        def __init__(self, stream, fp):
            self._s = stream
            self._f = fp
        def write(self, data):
            self._s.write(data)
            try:
                self._f.write(data)
                self._f.flush()
            except Exception:
                pass
        def flush(self):
            self._s.flush()
            try:
                self._f.flush()
            except Exception:
                pass
        def fileno(self):
            return self._s.fileno()

    try:
        _fp        = open(log_path, "a", encoding="utf-8", buffering=1)
        sys.stdout = _Tee(sys.__stdout__, _fp)
        sys.stderr = _Tee(sys.__stderr__, _fp)
    except Exception as e:
        print(f"[WARN] 日志文件创建失败: {e}", flush=True)
        return log_path

    print(f"[日志] 运行日志 → {log_path}", flush=True)
    return log_path


def _setup_exception_hook():
    """全局异常捕获，确保崩溃堆栈写入日志并停留5秒供查看。"""
    def _hook(exc_type, exc_value, exc_tb):
        msg = "".join(_traceback.format_exception(exc_type, exc_value, exc_tb))
        print(f"\n{'='*64}", flush=True)
        print(f"[FATAL] 未捕获异常:\n{msg}", flush=True)
        print(f"{'='*64}", flush=True)
        time.sleep(5)
    sys.excepthook = _hook


# ── 立即初始化日志和异常捕获 ──────────────────────────────────────────────────
_LOG_PATH = _setup_file_log()
_setup_exception_hook()

# ── 平台检查 ──────────────────────────────────────────────────────────────────
if sys.platform != "win32":
    print("[FATAL] 仅支持 Windows")
    sys.exit(1)

# ── 导入路径探测 & 拷贝模块 ───────────────────────────────────────────────────
try:
    _script_dir = str(_get_exe_dir())
    if _script_dir not in sys.path:
        sys.path.insert(0, _script_dir)
    from wx_find_and_copy import (
        find_wechat_root_dirs,
        copy_wechat_all_files,
        save_copy_report,
    )
    _HAS_FINDER = True
except ImportError as _e:
    print(f"[WARN] wx_find_and_copy 导入失败: {_e}")
    _HAS_FINDER = False

# ──────────────────────────────────────────────────────────────
# Windows API
# ──────────────────────────────────────────────────────────────
kernel32 = ctypes.windll.kernel32
psapi    = ctypes.windll.psapi
ver_dll  = ctypes.windll.version
user32   = ctypes.windll.user32

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ           = 0x0010
TH32CS_SNAPPROCESS        = 0x00000002
WM_COMMAND                = 0x0111

class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", ctypes.wintypes.DWORD),
        ("EntryPoint",  ctypes.c_void_p),
    ]

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",              ctypes.wintypes.DWORD),
        ("cntUsage",            ctypes.wintypes.DWORD),
        ("th32ProcessID",       ctypes.wintypes.DWORD),
        ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID",        ctypes.wintypes.DWORD),
        ("cntThreads",          ctypes.wintypes.DWORD),
        ("th32ParentProcessID", ctypes.wintypes.DWORD),
        ("pcPriClassBase",      ctypes.c_long),
        ("dwFlags",             ctypes.wintypes.DWORD),
        ("szExeFile",           ctypes.c_char * 260),
    ]

class VS_FIXEDFILEINFO(ctypes.Structure):
    _fields_ = [
        ("dwSignature",        ctypes.c_uint32),
        ("dwStrucVersion",     ctypes.c_uint32),
        ("dwFileVersionMS",    ctypes.c_uint32),
        ("dwFileVersionLS",    ctypes.c_uint32),
        ("dwProductVersionMS", ctypes.c_uint32),
        ("dwProductVersionLS", ctypes.c_uint32),
        ("dwFileFlagsMask",    ctypes.c_uint32),
        ("dwFileFlags",        ctypes.c_uint32),
        ("dwFileOS",           ctypes.c_uint32),
        ("dwFileType",         ctypes.c_uint32),
        ("dwFileSubtype",      ctypes.c_uint32),
        ("dwFileDateMS",       ctypes.c_uint32),
        ("dwFileDateLS",       ctypes.c_uint32),
    ]

# psapi argtypes
psapi.EnumProcessModules.restype  = ctypes.wintypes.BOOL
psapi.EnumProcessModules.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
    ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD)]
psapi.GetModuleBaseNameA.restype  = ctypes.wintypes.DWORD
psapi.GetModuleBaseNameA.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.wintypes.DWORD]
psapi.GetModuleInformation.restype  = ctypes.wintypes.BOOL
psapi.GetModuleInformation.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p,
    ctypes.POINTER(MODULEINFO), ctypes.wintypes.DWORD]
psapi.GetModuleFileNameExW.restype  = ctypes.wintypes.DWORD
psapi.GetModuleFileNameExW.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.wintypes.DWORD]

kernel32.OpenProcess.restype  = ctypes.c_void_p
kernel32.OpenProcess.argtypes = [
    ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
kernel32.CloseHandle.restype  = ctypes.wintypes.BOOL
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
kernel32.ReadProcessMemory.restype  = ctypes.wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.CreateToolhelp32Snapshot.restype  = ctypes.c_void_p
kernel32.CreateToolhelp32Snapshot.argtypes = [
    ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]
kernel32.Process32First.restype  = ctypes.wintypes.BOOL
kernel32.Process32First.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32Next.restype   = ctypes.wintypes.BOOL
kernel32.Process32Next.argtypes  = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32)]

user32.FindWindowW.restype  = ctypes.c_void_p
user32.FindWindowW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
user32.SendMessageW.restype  = ctypes.c_long
user32.SendMessageW.argtypes = [
    ctypes.c_void_p, ctypes.wintypes.UINT,
    ctypes.wintypes.WPARAM, ctypes.wintypes.LPARAM]
user32.EnumWindows.restype  = ctypes.wintypes.BOOL
user32.GetWindowThreadProcessId.restype  = ctypes.wintypes.DWORD
user32.GetWindowThreadProcessId.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.wintypes.DWORD)]
user32.GetClassNameW.restype  = ctypes.c_int
user32.GetClassNameW.argtypes = [
    ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]

# ──────────────────────────────────────────────────────────────
# 版本配置表
# ──────────────────────────────────────────────────────────────
VERSION_CONFIGS = [
    {
        "desc":         "> 4.1.6.14",
        "ver_min":      (4, 1, 6, 14),
        "ver_max":      None,
        "ver_excl_min": True,
        "pattern": bytes([
            0x24, 0x50, 0x48, 0xC7, 0x45, 0x00, 0xFE, 0xFF,
            0xFF, 0xFF, 0x44, 0x89, 0xCF, 0x44, 0x89, 0xC3,
            0x49, 0x89, 0xD6, 0x48, 0x89, 0xCE, 0x48, 0x89,
        ]),
        "mask":   "xxxxxxxxxxxxxxxxxxxxxxxx",
        "offset": -3,
    },
    {
        "desc":         ">= 4.1.4 && <= 4.1.6.14",
        "ver_min":      (4, 1, 4, 0),
        "ver_max":      (4, 1, 6, 14),
        "ver_excl_min": False,
        "pattern": bytes([
            0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48,
            0x89, 0x74, 0x00, 0x18, 0x48, 0x89, 0x7C, 0x00,
            0x20, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x50, 0x41,
        ]),
        "mask":   "xxxxxxxxxx?xxxx?xxxxxxxx",
        "offset": -3,
    },
    {
        "desc":         "< 4.1.4 (4.0.x ~ 4.1.3.x)",
        "ver_min":      (4, 0, 0, 0),
        "ver_max":      (4, 1, 3, 9999),
        "ver_excl_min": False,
        "pattern": bytes([
            0x24, 0x50, 0x48, 0xC7, 0x45, 0x00, 0xFE, 0xFF,
            0xFF, 0xFF, 0x44, 0x89, 0xCF, 0x44, 0x89, 0xC3,
            0x49, 0x89, 0xD6, 0x48, 0x89, 0xCE, 0x48, 0x89,
        ]),
        "mask":   "xxxxxxxxxxxxxxxxxxxxxxxx",
        "offset": -0xF,
    },
]

# ──────────────────────────────────────────────────────────────
# frida JS
# ──────────────────────────────────────────────────────────────
FRIDA_JS = r"""
'use strict';
var TARGET_ADDR  = ptr("TARGET_ADDR_PLACEHOLDER");
var KEY_SIZE     = 32;
var OFF_KEY_PTR  = 0x08;
var OFF_KEY_SIZE = 0x10;
var _captured    = false;

function isValidKey(arr) {
    if (arr.length < KEY_SIZE) return false;
    var allZero = true, allFF = true;
    for (var i = 0; i < KEY_SIZE; i++) {
        if (arr[i] !== 0)    allZero = false;
        if (arr[i] !== 0xFF) allFF   = false;
    }
    return !allZero && !allFF;
}
function tryReadKey(p) {
    try {
        if (!p || p.isNull()) return null;
        var b = new Uint8Array(p.readByteArray(KEY_SIZE));
        if (!isValidKey(b)) return null;
        var h = "";
        for (var i = 0; i < KEY_SIZE; i++) h += b[i].toString(16).padStart(2,'0');
        return h;
    } catch(e) { return null; }
}
var _icp = Interceptor.attach(TARGET_ADDR, {
    onEnter: function(args) {
        if (_captured) return;
        var k = null;
        try {
            var rdx = args[1];
            var ksz = rdx.add(OFF_KEY_SIZE).readU64().toNumber();
            if (ksz === KEY_SIZE) {
                k = tryReadKey(rdx.add(OFF_KEY_PTR).readPointer());
                if (k) { _emit(k,'precise_rdx'); return; }
            }
        } catch(e) {}
        var regs = [args[0],args[1],args[2],args[3]];
        var offs = [0,4,8,0x10,0x18,0x20,0x28,0x30,0x38,0x40,0x48,0x50,0x58,0x60];
        for (var ri = 0; ri < regs.length && !_captured; ri++) {
            k = tryReadKey(regs[ri]);
            if (k) { _emit(k,'direct_arg'+ri); return; }
            for (var oi = 0; oi < offs.length && !_captured; oi++) {
                try {
                    var p1 = regs[ri].add(offs[oi]).readPointer();
                    k = tryReadKey(p1);
                    if (k) { _emit(k,'arg'+ri+'[0x'+offs[oi].toString(16)+']'); return; }
                    for (var oi2 = 0; oi2 < offs.length && !_captured; oi2++) {
                        try {
                            var p2 = p1.add(offs[oi2]).readPointer();
                            k = tryReadKey(p2);
                            if (k) { _emit(k,'arg'+ri+'[0x'+offs[oi].toString(16)+'][0x'+offs[oi2].toString(16)+']'); return; }
                        } catch(e) {}
                    }
                } catch(e) {}
            }
        }
        try {
            var r2 = args[1];
            send({type:'miss', keySize: r2.add(OFF_KEY_SIZE).readU64().toNumber(), rdx: r2.toString()});
        } catch(e) {}
    }
});
function _emit(key, method) {
    if (_captured) return;
    _captured = true;
    _icp.detach();
    send({type:'key', key:key, method:method});
}
send({type:'ready', addr: TARGET_ADDR.toString()});
"""

# ──────────────────────────────────────────────────────────────
# 日志工具
# ──────────────────────────────────────────────────────────────
def _ts():
    return datetime.now().strftime("%H:%M:%S")
def log_info(msg):   print(f"[{_ts()}] [INFO]  {msg}", flush=True)
def log_ok(msg):     print(f"[{_ts()}] [ OK ]  {msg}", flush=True)
def log_warn(msg):   print(f"[{_ts()}] [WARN]  {msg}", flush=True)
def log_err(msg):    print(f"[{_ts()}] [ERR ]  {msg}", flush=True)
def log_step(n,t,m): print(f"[{_ts()}] [{n}/{t}]  {m}", flush=True)

# ──────────────────────────────────────────────────────────────
# 心跳计时器
# ──────────────────────────────────────────────────────────────
class HeartbeatTimer:
    def __init__(self, interval=15, prefix="等待中", hint="程序运行正常，未卡死"):
        self._interval = interval
        self._prefix   = prefix
        self._hint     = hint
        self._stop     = threading.Event()
        self._t        = threading.Thread(target=self._run, daemon=True)
        self._start    = time.time()
    def start(self):
        self._start = time.time(); self._t.start(); return self
    def stop(self):
        self._stop.set(); self._t.join(timeout=2)
    def _run(self):
        tick = 0
        while not self._stop.wait(timeout=self._interval):
            tick += 1
            e = int(time.time()-self._start); m,s = divmod(e,60)
            print(f"  {'◐◓◑◒'[tick%4]}  [{_ts()}] {self._prefix} "
                  f"— 已等待 {m:02d}:{s:02d}  ({self._hint})", flush=True)

# ────────────────────────────────────���─────────────────────────
# 磁盘检查
# ──────────────────────────────────────────────────────────────
def check_disk_space(dest_dir, required_bytes, label=""):
    try:
        stat = shutil.disk_usage(dest_dir)
        if stat.free < required_bytes:
            log_err(f"磁盘不足！需要 {required_bytes/1024/1024:.1f} MB，"
                    f"可用 {stat.free/1024/1024:.1f} MB ({label})")
            return False
        log_info(f"磁盘检查通过  需要 {required_bytes/1024/1024:.1f} MB，"
                 f"可用 {stat.free/1024/1024:.1f} MB")
        return True
    except Exception as e:
        log_warn(f"磁盘检查异常（跳过）: {e}"); return True

# ──────────────────────────────────────────────────────────────
# 输出目录
# ──────────────────────────────────────────────────────────────
def create_output_dir() -> str:
    base = _get_exe_dir()                          # ← 使用顶部统一定义
    name = datetime.now().strftime("wx_%Y%m%d_%H%M%S")
    out  = base / name
    try:
        out.mkdir(parents=True, exist_ok=True)
        abs_path = str(out.resolve())
    except PermissionError:
        fallback = Path.home() / "Desktop" / name
        fallback.mkdir(parents=True, exist_ok=True)
        abs_path = str(fallback.resolve())
        log_warn("权限不足，已降级到桌面")
    log_ok("输出目录已创建")
    w = max(len(abs_path)+6, 54)
    print(f"\n  ┌{'─'*w}┐")
    print(f"  │  📁 输出目录: {abs_path:<{w-16}}│")
    print(f"  └{'─'*w}┘\n")
    return abs_path

# ──────────────────────────────────────────────────────────────
# 保存密钥
# ──────────────────────────────────────────────────────────────
def save_key_result(out_dir, key, version, pid, method):
    now    = datetime.now()
    pragma = f"PRAGMA key = \"x'{key}'\";"
    lines  = [
        "="*60, "  微信数据库密钥提取结果", "="*60,
        f"  提取时间  : {now.strftime('%Y-%m-%d %H:%M:%S')}",
        f"  微信版本  : {version}",
        f"  进程 PID  : {pid}",
        f"  捕获方式  : {method}",
        "", f"  密钥 HEX  : {key}", "",
        "  SQLCipher PRAGMA 语句:", f"  {pragma}", "",
        "  数据库路径示例:",
        r"  %LOCALAPPDATA%\Tencent\WeChat\xwechat_files\<wxid>\db_storage\\",
        "="*60,
    ]
    errors = []
    for fname, content in [
        ("key_result.txt",  "\n".join(lines)+"\n"),
        ("key_result.json", json.dumps({
            "extract_time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "wechat_version": version, "pid": pid,
            "capture_method": method, "key_hex": key, "pragma": pragma,
        }, ensure_ascii=False, indent=2)),
    ]:
        path = os.path.join(out_dir, fname)
        try:
            with open(path, "w", encoding="utf-8") as f: f.write(content)
            log_ok(f"已保存 → {path}")
        except OSError as e:
            err = f"写入 {fname} 失败: {e}"; log_err(err); errors.append(err)
    return errors

# ──────────────────────────────────────────────────────────────
# 进程 & 模块工具
# ──────────────────────────────────────────────────────────────
def find_wechat_pids():
    pids = []
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == ctypes.c_void_p(-1).value:
        return pids
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    if kernel32.Process32First(snap, ctypes.byref(entry)):
        while True:
            try:
                name = entry.szExeFile.decode("gbk", errors="ignore").lower()
            except Exception:
                name = ""
            if name == "weixin.exe":
                pids.append(entry.th32ProcessID)
            if not kernel32.Process32Next(snap, ctypes.byref(entry)):
                break
    kernel32.CloseHandle(snap)
    return pids

def get_module_info(pid, mod_name):
    hProc = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not hProc: return None
    try:
        hMods = (ctypes.c_void_p * 1024)()
        cb    = ctypes.wintypes.DWORD(0)
        if not psapi.EnumProcessModules(
                hProc, ctypes.cast(hMods, ctypes.POINTER(ctypes.c_void_p)),
                ctypes.sizeof(hMods), ctypes.byref(cb)):
            return None
        for i in range(cb.value // ctypes.sizeof(ctypes.c_void_p)):
            hMod = hMods[i]
            if not hMod: continue
            buf = ctypes.create_string_buffer(260)
            if psapi.GetModuleBaseNameA(hProc, hMod, buf, 260) == 0: continue
            if buf.value.decode("gbk", errors="ignore").lower() != mod_name.lower():
                continue
            info = MODULEINFO()
            if not psapi.GetModuleInformation(
                    hProc, hMod, ctypes.byref(info), ctypes.sizeof(info)):
                continue
            path = ctypes.create_unicode_buffer(512)
            psapi.GetModuleFileNameExW(hProc, hMod, path, 512)
            return (info.lpBaseOfDll, info.SizeOfImage, path.value)
    finally:
        kernel32.CloseHandle(hProc)
    return None

def get_dll_version(dll_path):
    size = ver_dll.GetFileVersionInfoSizeW(dll_path, None)
    if not size: return ""
    buf = ctypes.create_string_buffer(size)
    if not ver_dll.GetFileVersionInfoW(dll_path, 0, size, buf): return ""
    p, cb = ctypes.c_void_p(), ctypes.c_uint()
    if not ver_dll.VerQueryValueW(buf, "\\", ctypes.byref(p), ctypes.byref(cb)):
        return ""
    if not p.value or cb.value < ctypes.sizeof(VS_FIXEDFILEINFO): return ""
    fi = ctypes.cast(p, ctypes.POINTER(VS_FIXEDFILEINFO)).contents
    return (f"{(fi.dwProductVersionMS>>16)&0xFFFF}."
            f"{(fi.dwProductVersionMS)&0xFFFF}."
            f"{(fi.dwProductVersionLS>>16)&0xFFFF}."
            f"{(fi.dwProductVersionLS)&0xFFFF}")

def ver_tuple(s):
    try: return tuple(int(x) for x in s.split("."))
    except: return (0,0,0,0)

def ver_cmp(a, b):
    for x, y in zip(a, b):
        if x < y: return -1
        if x > y: return  1
    return 0

def select_config(ver_str):
    v = ver_tuple(ver_str)
    for cfg in VERSION_CONFIGS:
        excl  = cfg["ver_excl_min"]
        lower = (ver_cmp(v, cfg["ver_min"]) > 0 if excl
                 else ver_cmp(v, cfg["ver_min"]) >= 0)
        upper = (True if cfg["ver_max"] is None
                 else ver_cmp(v, cfg["ver_max"]) <= 0)
        if lower and upper: return cfg
    return None

def pattern_scan(pid, base, size, pattern, mask, chunk=1*1024*1024):
    assert len(pattern) == len(mask)
    hProc = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not hProc: return []
    results = []; pat_len = len(pattern)
    try:
        offset = 0
        while offset < size:
            read_sz = min(chunk + pat_len, size - offset)
            buf     = ctypes.create_string_buffer(read_sz)
            bread   = ctypes.c_size_t(0)
            ok = kernel32.ReadProcessMemory(
                hProc, ctypes.c_void_p(base + offset),
                buf, read_sz, ctypes.byref(bread))
            n = bread.value
            if ok and n >= pat_len:
                data = buf.raw[:n]
                for i in range(n - pat_len + 1):
                    if all(mask[j]=='?' or data[i+j]==pattern[j]
                           for j in range(pat_len)):
                        results.append(base + offset + i)
            offset += chunk
    finally:
        kernel32.CloseHandle(hProc)
    return results

def locate_target_function(pid):
    log_info(f"正在分析 PID = {pid} ...")
    mod = get_module_info(pid, "Weixin.dll")
    if not mod:
        log_err("未找到 Weixin.dll"); return None, None
    base, size, dll_path = mod
    log_info(f"Weixin.dll  基址: 0x{base:016X}  大小: 0x{size:08X}")
    log_info(f"路径: {dll_path}")
    ver = get_dll_version(dll_path)
    if not ver:
        log_err("无法读取版本信息"); return None, None
    log_info(f"微信版本: {ver}")
    cfg = select_config(ver)
    hb  = HeartbeatTimer(8, "正在扫描 Weixin.dll 特征码", "内存扫描中，请勿关闭").start()
    try:
        if cfg:
            log_info(f"版本配置: {cfg['desc']}")
            hits = pattern_scan(pid, base, size, cfg["pattern"], cfg["mask"])
        else:
            log_warn(f"版本 {ver} 无预置配置，尝试自适应...")
            hits = []
            for fc in VERSION_CONFIGS:
                hits = pattern_scan(pid, base, size, fc["pattern"], fc["mask"])
                if len(hits) == 1:
                    cfg = fc
                    log_ok(f"自适应命中 → {fc['desc']}")
                    break
    finally:
        hb.stop()
    if not hits:
        log_err("特征码未命中"); return None, None
    if len(hits) > 1:
        log_warn(f"命中 {len(hits)} 处（期望唯一）")
        for h in hits:
            print(f"  0x{h:016X}  RVA=0x{h-base:X}")
        return None, None
    match  = hits[0]; target = match + cfg["offset"]
    log_ok(f"特征码命中: 0x{match:016X}  RVA=0x{match-base:X}")
    log_ok(f"目标函数:   0x{target:016X}  RVA=0x{target-base:X}")
    return target, ver

# ──────────────────────────────────────────────────────────────
# 微信窗口操作
# ──────────────────────────────────────────────────────────────
def find_wechat_main_hwnd(pid):
    found = [None]
    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL,
                                      ctypes.c_void_p, ctypes.c_void_p)
    def cb(hwnd, _):
        pid_buf = ctypes.wintypes.DWORD(0)
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_buf))
        if pid_buf.value == pid:
            cls = ctypes.create_unicode_buffer(64)
            user32.GetClassNameW(hwnd, cls, 64)
            if "wechat" in cls.value.lower():
                found[0] = hwnd; return False
        return True
    user32.EnumWindows(WNDENUMPROC(cb), 0)
    return found[0]

def try_trigger_relogin(pid):
    try:
        hwnd = find_wechat_main_hwnd(pid)
        if hwnd:
            for cmd_id in [0x6C5, 0x6C6, 0x830, 0x83E]:
                user32.SendMessageW(hwnd, WM_COMMAND, cmd_id, 0)
            return True
    except Exception: pass
    return False

# ──────────────────────────────────────────────────────────────
# frida Hook
# ──────────────────────────────────────────────────────────────
def run_hook(pid, target_addr, timeout=300, auto_trigger=False):
    try:
        import frida
    except ImportError:
        log_err("frida 未安装: pip install frida"); return None, "unknown"

    js          = FRIDA_JS.replace("TARGET_ADDR_PLACEHOLDER", hex(target_addr))
    key_event   = threading.Event()
    captured    = {"key": None, "method": "unknown"}
    miss_count  = [0]
    session_ref = [None]
    hb_wait_ref = [None]

    def on_message(message, _data):
        if key_event.is_set(): return
        if message.get("type") == "error":
            log_err(f"[frida JS] {message.get('description','')}"); return
        if message.get("type") != "send": return
        p = message.get("payload", {}); t = p.get("type")

        if t == "ready":
            log_ok(f"Hook 安装成功，目标: {p.get('addr')}")

        elif t == "key":
            if key_event.is_set(): return
            captured["key"]    = p["key"]
            captured["method"] = p.get("method", "?")
            key_event.set()
            if hb_wait_ref[0]:
                hb_wait_ref[0].stop()
            print(f"\n{'='*64}", flush=True)
            print(f"  🎉  成功捕获到数据库密钥！", flush=True)
            print(f"{'='*64}", flush=True)
            print(f"  密钥 HEX : {p['key']}", flush=True)
            print(f"  捕获方式 : {p.get('method','?')}", flush=True)
            print(f"  PRAGMA   : PRAGMA key = \"x'{p['key']}'\";", flush=True)
            print(f"{'='*64}\n", flush=True)

        elif t == "miss":
            miss_count[0] += 1
            if miss_count[0] <= 3:
                log_warn(f"函数触发未命中密钥 (keySize={p.get('keySize','?')})")
            elif miss_count[0] == 4:
                log_warn("miss 过多，后续不再打印...")

    orig_sigint = signal.getsignal(signal.SIGINT)
    def _sigint(sig, frame):
        log_warn("收到 Ctrl+C，正在退出...")
        key_event.set()
        if session_ref[0]:
            try: session_ref[0].detach()
            except: pass
        signal.signal(signal.SIGINT, orig_sigint)
        sys.exit(1)
    signal.signal(signal.SIGINT, _sigint)

    try:
        log_info(f"正在附加 frida 到 PID {pid} ...")
        session = frida.attach(pid); session_ref[0] = session
        script  = session.create_script(js)
        script.on("message", on_message)

        hb_inject = HeartbeatTimer(5, "frida 注入中", "正在安装 Hook，未卡死").start()
        script.load()
        t0 = time.time()
        while (time.time() - t0) < 10 and not key_event.is_set():
            time.sleep(0.1)
        hb_inject.stop()

        if key_event.is_set() and captured["key"] is None:
            return None, "interrupted"

        print("\n" + "╔" + "═"*62 + "���", flush=True)
        print("║  ⚡  Hook 已就绪！请在微信中执行以下操作之一:           ║", flush=True)
        print("║  ① 点击头像 → 切换账号 → 重新登录                     ║", flush=True)
        print("║  ② 菜单 → 退出登录 → 重新登录                         ║", flush=True)
        print("║  ③ 完全退出微信后重新启动并登录                        ║", flush=True)
        print("║  ⚠️  已登录状态不触发密钥函数，必须重新登录！           ║", flush=True)
        print("╚" + "═"*62 + "╝\n", flush=True)

        if auto_trigger:
            log_info("尝试自动发送切换账号命令...")
            if try_trigger_relogin(pid): log_ok("已发送切换账号命令")
            else: log_warn("自动触发失败，请手动操作")

        hb_wait = HeartbeatTimer(15, "等待微信重新登录",
                                  "程序运行正常，请在微信中操作").start()
        hb_wait_ref[0] = hb_wait

        deadline = time.time() + timeout
        while not key_event.is_set() and time.time() < deadline:
            remain = int(deadline - time.time())
            if remain % 60 == 0 and remain > 0 and remain != timeout:
                log_info(f"还在等待... 剩余 {remain} 秒")
            time.sleep(0.5)

        if hb_wait_ref[0]:
            hb_wait_ref[0].stop()

        if not captured["key"]:
            if miss_count[0] == 0:
                log_warn(f"超时 {timeout}s，函数从未被调用，请确认已重新登录")
            else:
                log_warn(f"超时，函数调用 {miss_count[0]} 次但未读到有效密钥")

    except Exception as e:
        err = str(e); log_err(f"frida 异常: {err}")
        if "access" in err.lower() or "permission" in err.lower():
            log_err("→ 请以管理员权限运行")
        elif "inject" in err.lower():
            log_err("→ 注入失败，请关闭杀毒软件")
    finally:
        if session_ref[0]:
            def _detach():
                try: session_ref[0].detach(); log_info("frida 已在后台分离完成")
                except: pass
            threading.Thread(target=_detach, daemon=True).start()
        signal.signal(signal.SIGINT, orig_sigint)

    return captured["key"], captured["method"]

# ──────────────────────────────────────────────────────────────
# 生成特征码
# ──────────────────────────────────────────────────────────────
def generate_sig_from_rva(pid, rva_str, sig_len=32):
    rva = int(rva_str, 16) if rva_str.startswith("0x") else int(rva_str)
    mod = get_module_info(pid, "Weixin.dll")
    if not mod: log_err("无法获取 Weixin.dll"); return
    base, _, _ = mod
    hProc = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not hProc: log_err("OpenProcess 失败"); return
    buf   = ctypes.create_string_buffer(sig_len)
    bread = ctypes.c_size_t(0)
    ok    = kernel32.ReadProcessMemory(
        hProc, ctypes.c_void_p(base + rva), buf, sig_len, ctypes.byref(bread))
    kernel32.CloseHandle(hProc)
    if not ok or bread.value < sig_len: log_err("读取内存失败"); return
    data = list(buf.raw[:bread.value])
    pat, msk = [], []; i = 0
    while i < len(data):
        b = data[i]
        if b in (0xE8, 0xE9):
            pat += [b,0,0,0,0]; msk += ['x','?','?','?','?']; i += 5
        elif 0x70 <= b <= 0x7F:
            pat += [b,0]; msk += ['x','?']; i += 2
        elif b==0x0F and i+1<len(data) and 0x80<=data[i+1]<=0x8F:
            pat += [b,data[i+1],0,0,0,0]; msk += ['x','x','?','?','?','?']; i += 6
        else:
            pat.append(b); msk.append('x'); i += 1
    p24 = pat[:24]; m24 = "".join(msk[:24])
    print("\n"+"="*64)
    print("  生成特征码 — 粘贴到 VERSION_CONFIGS 最前面")
    print("="*64)
    print(f"""    {{
        "desc":         "新版本 > X.X.X.X",
        "ver_min":      (X, X, X, X),
        "ver_max":      None,
        "ver_excl_min": True,
        "pattern": bytes([{", ".join(f"0x{b:02X}" for b in p24)}]),
        "mask":    "{m24}",
        "offset":  -3,
    }},""")
    print("="*64)

# ──────────────────────────────────────────────────────────────
# 全局线程数
# ──────────────────────────────────────────────────────────────
COPY_WORKERS = 8

# ──────────────────────────────────────────────────────────────
# 主入口
# ──────────────────────────────────────────────────────────────
def main():
    global COPY_WORKERS
    import argparse
    parser = argparse.ArgumentParser(
        description="wx_key_extractor — 微信数据库密钥提取",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  WxKeyExtractor.exe                          密钥提取 + 全量拷贝
  WxKeyExtractor.exe --key-only               仅提取密钥
  WxKeyExtractor.exe --workers 16             设置并发线程数
  WxKeyExtractor.exe --auto-trigger           自动发送切换账号命令
  WxKeyExtractor.exe --pid 12345              指定 PID
  WxKeyExtractor.exe --timeout 600            超时600秒
  WxKeyExtractor.exe --locate-only            仅定位函数地址
  WxKeyExtractor.exe --gen-sig 0x5AAB2D0      生成特征码
        """)
    parser.add_argument("--pid",          type=int,  default=None)
    parser.add_argument("--timeout",      type=int,  default=300)
    parser.add_argument("--locate-only",  action="store_true")
    parser.add_argument("--auto-trigger", action="store_true")
    parser.add_argument("--key-only",     action="store_true")
    parser.add_argument("--workers",      type=int,  default=COPY_WORKERS,
                        help=f"小文件并发线程数（默认{COPY_WORKERS}）")
    parser.add_argument("--gen-sig",      type=str,  default=None)
    args = parser.parse_args()
    COPY_WORKERS = args.workers

    print("=" * 64, flush=True)
    print("  wx_key_extractor  —  微信数据库密钥提取工具", flush=True)
    print("  仅供个人数据备份与技术研究，请遵守相关法律法规", flush=True)
    print(f"  启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", flush=True)
    print(f"  日志文件: {_LOG_PATH}", flush=True)
    print("=" * 64, flush=True)

    # Step 1
    log_step(1, 5, "查找微信进程...")
    pids = [args.pid] if args.pid else find_wechat_pids()
    if not pids:
        log_err("未找到 Weixin.exe，请先启动微信"); sys.exit(1)
    log_ok(f"找到微信进程 PID: {pids}")
    pid = min(pids)
    if len(pids) > 1:
        log_info(f"多进程，选主进程 PID={pid}（--pid 可指定）")

    if args.gen_sig:
        generate_sig_from_rva(pid, args.gen_sig); sys.exit(0)

    # Step 2
    log_step(2, 5, "扫描 Weixin.dll 定位密钥函数...")
    target_addr, ver = locate_target_function(pid)
    if not target_addr:
        log_err("函数定位失败"); sys.exit(1)
    if args.locate_only:
        log_ok(f"函数地址: 0x{target_addr:016X}"); sys.exit(0)

    # Step 3
    log_step(3, 5, "安装 frida Hook，等待登录触发密钥...")
    key, method = run_hook(pid, target_addr,
                           timeout=args.timeout,
                           auto_trigger=args.auto_trigger)
    if not key:
        log_err("未捕获到密钥，退出"); sys.exit(1)

    # Step 4
    log_step(4, 5, "创建输出目录并保存密钥...")
    out_dir = create_output_dir()
    errs = save_key_result(out_dir, key, ver or "unknown", pid, method)
    if errs:
        log_warn(f"密钥保存出现 {len(errs)} 个错误")

    # Step 5
    if args.key_only:
        log_info("--key-only 模式，跳过拷贝")
    else:
        log_step(5, 5, "搜索微信数据目录并拷贝所有文件...")

        if not _HAS_FINDER:
            log_err("wx_find_and_copy 模块未找到，跳过拷贝")
            log_warn(f"可单独运行拷贝: python wx_find_and_copy.py --dest \"{out_dir}\"")
        else:
            src_roots = find_wechat_root_dirs(pid=pid)

            if src_roots:
                log_info(f"找到 {len(src_roots)} 个微信数据根目录:")
                for r in src_roots: print(f"    {r}", flush=True)
            else:
                log_warn("未自动找到微信数据目录，可手动指定:")
                log_warn(f"  python wx_find_and_copy.py --src <路径> --dest \"{out_dir}\"")

            if src_roots:
                stats = copy_wechat_all_files(out_dir, src_roots, workers=COPY_WORKERS)
                save_copy_report(out_dir, stats, src_roots)
                log_ok(f"拷贝完成  成功:{stats['copied']:,}  "
                       f"跳过:{stats['skipped']:,}  失败:{stats['failed']:,}  "
                       f"总计:{stats['total_bytes']/1024/1024:.1f} MB")
                if stats["failed"] > 0:
                    log_warn(f"{stats['failed']} 个文件失败（详见 copy_report.txt）")

    print(flush=True)
    print("=" * 64, flush=True)
    print("  ✅  全部完成！", flush=True)
    print(f"  📁 输出目录: {out_dir}", flush=True)
    print(f"  🔑 密钥 HEX: {key}", flush=True)
    print(f"  📄 日志文件: {_LOG_PATH}", flush=True)
    print("=" * 64, flush=True)


if __name__ == "__main__":
    main()
