#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""wx_find_and_copy.py — 微信数据目录探测 & 文件拷贝工具

独立运行，不依赖项目其他模块。仅支持 Windows。

用法:
    python wx_find_and_copy.py                         # 自动探测 + 拷贝
    python wx_find_and_copy.py --find-only             # 仅探测，不拷贝
    python wx_find_and_copy.py --src D:\\微信文件\\xwechat_files
    python wx_find_and_copy.py --dest E:\\backup
    python wx_find_and_copy.py --workers 16
    python wx_find_and_copy.py --debug
"""

import argparse
import os
import shutil
import sys
import time
import threading
import concurrent.futures as _cf
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Tuple   # ★ 兼容 Python 3.9

# ── 可选依赖 ──────────────────────────────────────────────────────────────────
try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

# winreg 只在 Windows 下存在
try:
    import winreg
    _HAS_WINREG = True
except ImportError:
    _HAS_WINREG = False

# ── 全局调试标志 ───────────────────────────────────────────────────────────────
_DEBUG = False

SMALL_FILE_THRESHOLD = 4 * 1024 * 1024  # 4 MB

# db 文件扩展名集合（加密数据库，完整性最重要，优先拷贝）
_DB_EXTENSIONS = {'.db', '.db3', '.sqlite', '.sqlitedb', '.db-shm', '.db-wal'}

# 磁盘扫描关键词（策略3）
_SCAN_KEYWORDS = {
    "xwechat_files", "WeChat Files", "WeChatFiles",
    "wechat_files", "微信文件", "WeChat", "Tencent",
}


# ══════════════════════════════════════════════════════════════════════════════
# 日志辅助
# ══════════════════════════════════════════════════════════════════════════════

def _log(tag: str, msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{tag}] {msg}", flush=True)


def log_ok(msg: str)   -> None: _log(" OK ", msg)
def log_err(msg: str)  -> None: _log("ERR ", msg)
def log_warn(msg: str) -> None: _log("WARN", msg)
def log_info(msg: str) -> None: _log("INFO", msg)
def log_dbg(msg: str)  -> None:
    if _DEBUG:
        _log("DBG ", msg)


# ══════════════════════════════════════════════════════════════════════════════
# 微信根目录判断
# ══════════════════════════════════════════════════════════════════════════════

def _looks_like_wechat_root(path: str) -> bool:
    if not os.path.isdir(path):
        return False

    if os.path.isdir(os.path.join(path, "db_storage")):
        log_dbg(f"  ✓ 直接含 db_storage: {path}")
        return True

    try:
        entries = os.listdir(path)
    except PermissionError:
        return False

    for entry in entries:
        entry_path = os.path.join(path, entry)
        if not os.path.isdir(entry_path):
            continue

        if entry.startswith("wxid_"):
            log_dbg(f"  ✓ 含 wxid_ 子目录: {entry_path}")
            return True

        try:
            sub_entries = os.listdir(entry_path)
        except PermissionError:
            continue

        if "db_storage" in sub_entries:
            log_dbg(f"  ✓ 子目录含 db_storage: {entry_path}")
            return True
        if "Msg" in sub_entries:
            log_dbg(f"  ✓ 子目录含 Msg: {entry_path}")
            return True

    return False


# ══════════════════════════════════════════════════════════════════════════════
# 策略1：注册表
# ══════════════════════════════════════════════════════════════════════════════

def _strategy_registry() -> List[str]:
    if not _HAS_WINREG:
        log_dbg("策略1 跳过：winreg 不可用")
        return []

    candidates = []
    reg_path = r"Software\Tencent\WeChat"
    log_info("策略1：读取注册表 HKCU\\" + reg_path)

    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path)
    except FileNotFoundError:
        log_warn("  注册表键不存在，跳过策略1")
        return []
    except OSError as e:
        log_warn(f"  注册表读取失败: {e}")
        return []

    try:
        idx = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, idx)
                log_dbg(f"  注册表键: {name!r} = {value!r}")
                if isinstance(value, str) and os.path.isdir(value):
                    candidates.append(value)
                idx += 1
            except OSError:
                break
    finally:
        winreg.CloseKey(key)

    results = []
    for c in candidates:
        if _looks_like_wechat_root(c):
            log_ok(f"  策略1 找到: {c}")
            results.append(c)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# 策略2：psutil
# ═══════════════════════════════��══════════════════════════════════════════════

_WECHAT_PATH_KEYWORDS = ("xwechat_files", "WeChat Files", "WeChatFiles",
                          "wechat_files", "微信文件")


def _extract_prefix_by_keyword(filepath: str, keyword: str) -> Optional[str]:  # ★ 改这里
    lower    = filepath.lower() if keyword.isascii() else filepath
    kw_lower = keyword.lower()  if keyword.isascii() else keyword
    idx = lower.find(kw_lower)
    if idx == -1:
        return None
    end     = idx + len(keyword)
    sep_idx = filepath.find(os.sep, end)
    if sep_idx == -1:
        return filepath[:end]
    return filepath[:sep_idx]


def _open_files_with_timeout(proc, timeout: int = 5) -> list:
    with _cf.ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(proc.open_files)
        try:
            return fut.result(timeout=timeout)
        except _cf.TimeoutError:
            log_dbg(f"  进程 {proc.pid} open_files() 超时，跳过")
            return []
        except Exception:
            return []


def _strategy_psutil(retry: int = 3, retry_interval: float = 10.0) -> List[str]:
    if not _HAS_PSUTIL:
        log_dbg("策略2 跳过：psutil 未安装")
        return []

    for attempt in range(1, retry + 1):
        log_info(f"策略2：psutil 扫描 Weixin.exe（第 {attempt}/{retry} 次）")

        wx_procs = []
        try:
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    if proc.info["name"] and proc.info["name"].lower() == "weixin.exe":
                        wx_procs.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass

        if not wx_procs:
            log_warn("  未找到 Weixin.exe 进程")
            if attempt < retry:
                log_info(f"  {retry_interval:.0f}s 后重试...")
                time.sleep(retry_interval)
            continue

        log_info(f"  找到 {len(wx_procs)} 个 Weixin.exe 进程")

        found_paths: set = set()
        for proc in wx_procs:
            try:
                cwd = proc.cwd()
                if cwd:
                    found_paths.add(cwd)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            for fobj in _open_files_with_timeout(proc, timeout=6):
                fpath = fobj.path
                for kw in _WECHAT_PATH_KEYWORDS:
                    prefix = _extract_prefix_by_keyword(fpath, kw)
                    if prefix:
                        found_paths.add(prefix)
                        break

        results = [p for p in found_paths if _looks_like_wechat_root(p)]
        for r in results:
            log_ok(f"  策略2 找到: {r}")

        if results:
            return results

        if attempt < retry:
            log_warn(f"  未找到有效目录，{retry_interval:.0f}s 后重试...")
            time.sleep(retry_interval)

    log_warn("  策略2 全部重试失败")
    return []


# ══════════════════════════════════════════════════════════════════════════════
# 策略3：全盘扫描
# ══════════════════════════════════════════════════════════════════════════════

def _iter_drives() -> List[str]:
    drives = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = f"{letter}:\\"
        if os.path.isdir(drive):
            drives.append(drive)
    return drives


def _strategy_disk_scan() -> List[str]:
    log_info("策略3：全盘符暴力扫描（3层深度）")
    results = []

    for drive in _iter_drives():
        queue = [(drive, 0)]
        while queue:
            current, depth = queue.pop(0)
            if depth >= 3:
                continue
            try:
                entries = os.listdir(current)
            except (PermissionError, OSError):
                continue

            for entry in entries:
                entry_path = os.path.join(current, entry)
                if not os.path.isdir(entry_path):
                    continue

                if any(kw.lower() in entry.lower() for kw in _SCAN_KEYWORDS):
                    if _looks_like_wechat_root(entry_path):
                        log_ok(f"  策略3 找到: {entry_path}")
                        if entry_path not in results:
                            results.append(entry_path)

                if depth < 3:
                    queue.append((entry_path, depth + 1))

    return results


# ══════════════════════════════════════════════════════════════════════════════
# 策略4：常用路径兜底
# ══════════════════════════════════════════════════════════════════════════════

_COMMON_REL_PATHS = [
    r"Tencent\WeChat\WeChat Files",
    r"Tencent\WeChat",
    r"Tencent\xwechat_files",
    r"xwechat_files",
    r"WeChat Files",
    r"WeChatFiles",
    r"微信文件\xwechat_files",
    r"微信文件\WeChat Files",
    r"微信文件",
    r"Tencent Files",
]
_ENV_VARS = ["%LOCALAPPDATA%", "%APPDATA%", "%USERPROFILE%"]


def _strategy_common_paths() -> List[str]:
    log_info("策略4：常用路径穷举（兜底）")
    base_dirs = []
    for ev in _ENV_VARS:
        expanded = os.path.expandvars(ev)
        if expanded != ev and os.path.isdir(expanded):
            base_dirs.append(expanded)
    base_dirs.extend(_iter_drives())

    results = []
    for base in base_dirs:
        for rel in _COMMON_REL_PATHS:
            candidate = os.path.join(base, rel)
            if _looks_like_wechat_root(candidate):
                log_ok(f"  策略4 找到: {candidate}")
                if candidate not in results:
                    results.append(candidate)
    return results


# ══════════════════════════════════════════════════════════════════════════════
# 主探测函数
# ══════════════════════════════════════════════════════════════════════════════

def find_wechat_root_dirs(pid: int = 0, debug: bool = False,
                          src: Optional[str] = None) -> List[str]:  # ★ 改这里
    global _DEBUG
    if debug:
        _DEBUG = True

    if src:
        log_info(f"策略0：使用手动指定路径 {src}")
        if os.path.isdir(src):
            return [src]
        else:
            log_err(f"  路径不存在: {src}")
            return []

    log_info("正在多策略搜索微信数据目录...")

    all_results: List[str] = []
    seen: set = set()

    def _add(paths: List[str], label: str) -> None:
        for p in paths:
            key = os.path.normcase(os.path.abspath(p))
            if key not in seen:
                seen.add(key)
                all_results.append(p)
        if all_results:
            log_ok(f"[{label}] 找到 {len(all_results)} 个目录")

    _add(_strategy_registry(), "注册表")

    if not all_results:
        log_info("前置策略未找到，启动 psutil 扫描（最多等待约30秒）...")
        _add(_strategy_psutil(retry=3, retry_interval=10.0), "psutil")

    if not all_results:
        log_info("前两种策略未找到，启动磁盘扫描（稍慢）...")
        _add(_strategy_disk_scan(), "磁盘扫描")

    if not all_results:
        _add(_strategy_common_paths(), "常用路径")

    if all_results:
        log_info(f"找到 {len(all_results)} 个微信数据根目录:")
        for r in all_results:
            print(f"    {r}", flush=True)
    else:
        log_warn("所有策略均未找到微信数据目录")

    return all_results


def find_wechat_root(src: Optional[str] = None) -> Optional[str]:  # ★ 改这里
    results = find_wechat_root_dirs(src=src)
    return results[0] if results else None


# ══════════════════════════════════════════════════════════════════════════════
# 磁盘空间预检
# ══════════════════════════════════════════════════════════════════════════════

def _check_disk_space(dest_dir: str, required_bytes: int) -> bool:
    try:
        usage = shutil.disk_usage(dest_dir)
        free  = usage.free
        if free < required_bytes:
            log_err(f"磁盘空间不足！剩余 {free/1024/1024:.1f} MB，"
                    f"需要 {required_bytes/1024/1024:.1f} MB")
            return False
        return True
    except OSError as e:
        log_warn(f"磁盘空间检查失败: {e}")
        return True


# ══════════════════════════════════════════════════════════════════════════════
# 文件收集
# ══════════════════════════════════════════════════════════════════════════════

def _collect_files(src_dir: str) -> List[Tuple[str, int]]:
    files = []
    for root, _dirs, filenames in os.walk(src_dir):
        for fname in filenames:
            fpath = os.path.join(root, fname)
            try:
                size = os.path.getsize(fpath)
                files.append((fpath, size))
            except OSError:
                files.append((fpath, 0))
    return files


# ══════════════════════════════════════════════════════════════════════════════
# 拷贝功能
# ══════════════════════════════════════════════════════════════════════════════

class _CopyStats:
    def __init__(self) -> None:
        self._lock        = threading.Lock()
        self.copied       = 0
        self.skipped      = 0
        self.failed       = 0
        self.copied_bytes = 0
        self.errors: List[str] = []

    def record_copied(self, size: int) -> None:
        with self._lock:
            self.copied += 1
            self.copied_bytes += size

    def record_skipped(self) -> None:
        with self._lock:
            self.skipped += 1

    def record_failed(self, msg: str) -> None:
        with self._lock:
            self.failed += 1
            self.errors.append(msg)


def _copy_one(src: str, dest: str, size: int, stats: _CopyStats) -> None:
    try:
        if os.path.exists(dest) and os.path.getsize(dest) == size:
            stats.record_skipped()
            return
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(src, dest)
        stats.record_copied(size)
    except PermissionError as e:
        stats.record_failed(f"权限拒绝 {src}: {e}")
    except OSError as e:
        stats.record_failed(f"拷贝失败 {src}: {e}")


def _render_progress(copied_count: int, total_count: int, copied_bytes: int,
                     total_bytes: int, speed_bps: float,
                     last_line_len: int) -> str:
    pct    = copied_count / max(total_count, 1)
    filled = int(20 * pct)
    bar    = "█" * filled + "░" * (20 - filled)
    cmb    = copied_bytes / 1024 / 1024
    tmb    = total_bytes  / 1024 / 1024

    if speed_bps >= 1024 * 1024:
        spd = f"{speed_bps/1024/1024:.1f} MB/s"
    elif speed_bps >= 1024:
        spd = f"{speed_bps/1024:.0f} KB/s"
    else:
        spd = f"{int(speed_bps)} B/s"

    remain = total_bytes - copied_bytes
    if speed_bps > 0:
        eta_s = remain / speed_bps
        eta   = (f"剩余约 {int(eta_s//60)}分{int(eta_s%60)}秒"
                 if eta_s >= 60 else f"剩余约 {int(eta_s)}秒")
    else:
        eta = "计算中..."

    line = (f"  [{bar}] {copied_count}/{total_count}  "
            f"{cmb:.1f}/{tmb:.1f}MB  ⚡{spd}  {eta}   ")
    pad = max(0, last_line_len - len(line))
    return line + " " * pad


def copy_wechat_data(src_dir: str, dest_dir: str, workers: int = 8) -> dict:
    """db文件优先，小文件并发，大文件顺序。"""
    log_info("收集文件列表...")
    all_files   = _collect_files(src_dir)
    total_count = len(all_files)
    total_bytes = sum(s for _, s in all_files)

    if total_count == 0:
        log_warn("源目录中未找到任何文件")
        return {"copied": 0, "skipped": 0, "failed": 0, "copied_bytes": 0, "errors": []}

    log_info(f"扫描完成：共 {total_count:,} 个文件  {total_bytes/1024/1024:.1f} MB")

    required = int(total_bytes * 1.05) + 100 * 1024 * 1024
    if not _check_disk_space(dest_dir, required):
        return {"copied": 0, "skipped": 0, "failed": 0,
                "copied_bytes": 0, "errors": ["磁盘空间不足，中止拷贝"]}

    stats = _CopyStats()

    db_files    = [(s, z) for s, z in all_files
                   if os.path.splitext(s)[1].lower() in _DB_EXTENSIONS]
    small_files = [(s, z) for s, z in all_files
                   if os.path.splitext(s)[1].lower() not in _DB_EXTENSIONS
                   and z < SMALL_FILE_THRESHOLD]
    large_files = [(s, z) for s, z in all_files
                   if os.path.splitext(s)[1].lower() not in _DB_EXTENSIONS
                   and z >= SMALL_FILE_THRESHOLD]

    log_info(f"  db文件（数据库文件）: {len(db_files):,} 个  → 优先顺序拷贝")
    log_info(f"  小文件（<4MB）      : {len(small_files):,} 个  → {workers} 线程并发")
    log_info(f"  大文件（≥4MB）      : {len(large_files):,} 个  → 单线程顺序")

    def _dest_path(src: str) -> str:
        return os.path.join(dest_dir, os.path.relpath(src, src_dir))

    progress_lock      = threading.Lock()
    last_line_len      = [0]
    speed_window_bytes = [0]
    speed_window_start = [time.monotonic()]
    current_speed      = [0.0]
    done_count         = [0]

    def _update_progress(size: int) -> None:
        now = time.monotonic()
        with progress_lock:
            done_count[0]         += 1
            speed_window_bytes[0] += size
            elapsed = now - speed_window_start[0]
            if elapsed >= 1.0:
                current_speed[0]      = speed_window_bytes[0] / elapsed
                speed_window_bytes[0] = 0
                speed_window_start[0] = now
            line = _render_progress(done_count[0], total_count,
                                    stats.copied_bytes, total_bytes,
                                    current_speed[0], last_line_len[0])
            print(f"\r{line}", end="", flush=True)
            last_line_len[0] = len(line)

    # ── 第1优先：db 文件 ────────────────────────────────────────
    if db_files:
        log_info("[1/3] 优先拷贝 db 文件...")
        for src, size in db_files:
            _copy_one(src, _dest_path(src), size, stats)
            _update_progress(size)

    # ── 第2优先：小文件并发 ─────────────────────────────────────
    if small_files:
        log_info(f"[2/3] 拷贝小文件（{workers} 线程）...")
        def _task(item: Tuple[str, int]) -> None:
            src, size = item
            _copy_one(src, _dest_path(src), size, stats)
            _update_progress(size)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for _ in as_completed([pool.submit(_task, item) for item in small_files]):
                pass

    # ── 第3优先：大文件顺序 ─────────────────────────────────────
    if large_files:
        log_info("[3/3] 拷贝大文件...")
        for src, size in large_files:
            _copy_one(src, _dest_path(src), size, stats)
            _update_progress(size)

    print()
    return {"copied": stats.copied, "skipped": stats.skipped,
            "failed": stats.failed, "copied_bytes": stats.copied_bytes,
            "errors": stats.errors}


# ══════════════════════════════════════════════════════════════════════════════
# 多目录拷贝（供 01_wx_win.py 调用）
# ══════════════════════════════════════════════════════════════════════════════

def copy_wechat_all_files(out_dir: str, src_roots: List[str],
                          workers: int = 8) -> dict:
    if not src_roots:
        log_warn("未传入源目录，跳过拷贝")
        return {"copied": 0, "skipped": 0, "failed": 0, "total_bytes": 0, "errors": []}

    dest_root = os.path.join(out_dir, "wechat_backup")
    os.makedirs(dest_root, exist_ok=True)

    all_stats: dict = {"copied": 0, "skipped": 0, "failed": 0,
                       "total_bytes": 0, "errors": []}

    for src_dir in src_roots:
        src_name = os.path.basename(src_dir.rstrip("\\/"))
        dest_dir = os.path.join(dest_root, src_name)
        os.makedirs(dest_dir, exist_ok=True)

        result = copy_wechat_data(src_dir, dest_dir, workers=workers)
        all_stats["copied"]      += result["copied"]
        all_stats["skipped"]     += result["skipped"]
        all_stats["failed"]      += result["failed"]
        all_stats["total_bytes"] += result.get("copied_bytes", 0)
        all_stats["errors"]      += result["errors"]

    return all_stats


# ══════════════════════════════════════════════════════════════════════════════
# 拷贝报告
# ══════════════════════════════════════════════════════════════════════════════

def save_copy_report(out_dir: str, stats: dict, src_roots: List[str]) -> None:
    total_mb = stats.get("total_bytes", 0) / 1024 / 1024
    lines = [
        "=" * 60, "  微信数据拷贝报告", "=" * 60,
        f"  拷贝时间  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  源目录数  : {len(src_roots)}",
        *[f"    {r}" for r in src_roots],
        "",
        f"  已拷贝    : {stats['copied']:,} 个文件 ({total_mb:.1f} MB)",
        f"  已跳过    : {stats['skipped']:,} 个文件（大小相同）",
        f"  失败      : {stats['failed']:,} 个文件",
    ]
    if stats.get("errors"):
        lines += ["", "  错误列表:"]
        for i, err in enumerate(stats["errors"][:30], 1):
            lines.append(f"    {i}. {err}")
        if len(stats["errors"]) > 30:
            lines.append(f"    ... 共 {len(stats['errors'])} 条")
    lines.append("=" * 60)

    path = os.path.join(out_dir, "copy_report.txt")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        log_ok(f"拷贝报告已写入: {path}")
    except OSError as e:
        log_warn(f"写入拷贝报告失败: {e}")


def _write_report(dest_dir: str, src_dir: str, result: dict) -> None:
    save_copy_report(dest_dir, {
        "total_bytes": result.get("copied_bytes", 0),
        "copied":  result["copied"],
        "skipped": result["skipped"],
        "failed":  result["failed"],
        "errors":  result["errors"],
    }, [src_dir])


# ══════════════════════════════════════════════════════════════════════════════
# 诊断输出
# ══════════════════════════════════════════════════════════════════════════════

def _print_diagnostics() -> None:
    print("\n" + "=" * 60)
    print("  ⚠  所有策略均未找到微信数据目录")
    print("=" * 60)
    print("\n  请尝试以下方案：\n")
    print("  1. 手动指定路径（推荐）：")
    print(r"     python wx_find_and_copy.py --src D:\微信文件\xwechat_files")
    print("\n  2. 开启调试模式查看详细扫描过程：")
    print("     python wx_find_and_copy.py --debug")
    print("\n  3. 常见微信数据目录位置参考：")
    print(r"     - C:\Users\<用户名>\Documents\WeChat Files")
    print(r"     - C:\Users\<用户名>\AppData\Roaming\Tencent\WeChat")
    print(r"     - D:\微信文件\xwechat_files")
    print(r"     - D:\WeChat Files")
    print("\n  4. 在微信客户端 → 设置 → 文件管理 中查看数据存储路径\n")
    print("=" * 60)


# ═════════════════════��════════════════════════════════════════════════════════
# CLI 入口（独立运行）
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    global _DEBUG

    parser = argparse.ArgumentParser(
        description="微信数据目录探测 & 文件拷贝工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--src",       metavar="DIR", help="直接指定微信数据源目录")
    parser.add_argument("--dest",      metavar="DIR", help="目标目录")
    parser.add_argument("--workers",   type=int, default=8, metavar="N")
    parser.add_argument("--find-only", action="store_true")
    parser.add_argument("--debug",     action="store_true")
    args = parser.parse_args()

    if args.debug:
        _DEBUG = True

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║      微信数据目录探测 & 拷贝工具  wx_find_and_copy.py    ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    src_dir = find_wechat_root(args.src)
    if not src_dir:
        _print_diagnostics()
        sys.exit(1)

    print(f"\n  📂 找到微信数据目录: {src_dir}\n")

    if args.find_only:
        log_info("--find-only 模式，跳过拷贝。")
        sys.exit(0)

    if args.dest:
        dest_dir = args.dest
    else:
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest_dir = str(Path(__file__).parent.resolve() / f"wechat_backup_{ts}")

    os.makedirs(dest_dir, exist_ok=True)
    dest_dir = str(Path(dest_dir).resolve())
    print(f"  📁 目标目录: {dest_dir}\n")

    result = copy_wechat_data(src_dir, dest_dir, workers=args.workers)

    print()
    log_ok(f"拷贝完成：{result['copied']} 已拷贝，"
           f"{result['skipped']} 已跳过，{result['failed']} 失败")
    _write_report(dest_dir, src_dir, result)

    if result["errors"]:
        log_warn(f"共 {len(result['errors'])} 个错误，详见 copy_report.txt")


if __name__ == "__main__":
    main()
