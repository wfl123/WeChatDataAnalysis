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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

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
    """
    判断给定路径是否是微信数据根目录。
    满足以下任一条件：
      - 包含 wxid_ 开头的子目录
      - 子目录内含 db_storage 目录
      - 子目录内含 Msg 目录
      - 目录内直接含 db_storage 目录
    """
    if not os.path.isdir(path):
        return False

    # 直接含 db_storage
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

        # wxid_ 开头的子目录
        if entry.startswith("wxid_"):
            log_dbg(f"  ✓ 含 wxid_ 子目录: {entry_path}")
            return True

        # 子目录内含 db_storage 或 Msg
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
# 策略1：注册表多路径探测
# ══════════════════════════════════════════════════════════════════════════════

def _strategy_registry() -> list[str]:
    """读取 HKCU\\Software\\Tencent\\WeChat 下所有值，尝试找到数据根目录。"""
    if not _HAS_WINREG:
        log_dbg("策略1 跳过：winreg 不可用（非 Windows 环境）")
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
                    log_dbg(f"  → 是有效目录，加入候选")
                    candidates.append(value)
                idx += 1
            except OSError:
                break
    finally:
        winreg.CloseKey(key)

    results = []
    for c in candidates:
        log_dbg(f"  验证候选: {c}")
        if _looks_like_wechat_root(c):
            log_ok(f"  策略1 找到: {c}")
            results.append(c)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# 策略2：psutil 进程工作目录 + 打开文件列表
# ══════════════════════════════════════════════════════════════════════════════

_WECHAT_PATH_KEYWORDS = ("xwechat_files", "WeChat Files", "WeChatFiles",
                          "wechat_files", "微信文件")


def _extract_prefix_by_keyword(filepath: str, keyword: str) -> str | None:
    """从文件路径中提取关键词前缀（含关键词目录本身）。"""
    lower = filepath.lower() if keyword.isascii() else filepath
    kw_lower = keyword.lower() if keyword.isascii() else keyword
    idx = lower.find(kw_lower)
    if idx == -1:
        return None
    end = idx + len(keyword)
    # 截取到关键词目录结尾
    # 找到关键词后的第一个路径分隔符
    sep_idx = filepath.find(os.sep, end)
    if sep_idx == -1:
        return filepath[:end]
    return filepath[:sep_idx]


def _strategy_psutil() -> list[str]:
    """用 psutil 找 Weixin.exe 进程，从打开的文件路径中提取候选目录。"""
    if not _HAS_PSUTIL:
        log_dbg("策略2 跳过：psutil 未安装")
        return []

    log_info("策略2：用 psutil 扫描 Weixin.exe 进程")
    wx_procs = []
    try:
        for proc in psutil.process_iter(["pid", "name"]):
            if proc.info["name"] and proc.info["name"].lower() == "weixin.exe":
                wx_procs.append(proc)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    if not wx_procs:
        log_warn("  未找到 Weixin.exe 进程，跳过策略2")
        return []

    log_info(f"  找到 {len(wx_procs)} 个 Weixin.exe 进程")

    found_paths = set()
    for proc in wx_procs:
        try:
            # 工作目录
            cwd = proc.cwd()
            log_dbg(f"  进程 {proc.pid} cwd: {cwd}")
            if cwd:
                found_paths.add(cwd)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        try:
            open_files = proc.open_files()
            log_dbg(f"  进程 {proc.pid} 打开文件数: {len(open_files)}")
            for fobj in open_files:
                fpath = fobj.path
                for kw in _WECHAT_PATH_KEYWORDS:
                    prefix = _extract_prefix_by_keyword(fpath, kw)
                    if prefix:
                        log_dbg(f"  → 提取候选路径: {prefix}  (来自 {fpath})")
                        found_paths.add(prefix)
                        break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    results = []
    for p in found_paths:
        log_dbg(f"  验证候选: {p}")
        if _looks_like_wechat_root(p):
            log_ok(f"  策略2 找到: {p}")
            results.append(p)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# 策略3：全盘符暴力扫描（3层深度）
# ══════════════════════════════════════════════════════════════════════════════

def _iter_drives() -> list:
    """枚举所有可用盘符。"""
    drives = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = f"{letter}:\\"
        if os.path.isdir(drive):
            drives.append(drive)
    return drives


def _strategy_disk_scan() -> list[str]:
    """枚举所有盘符，深度3层扫描包含关键词的目录。"""
    log_info("策略3：全盘符暴力扫描（3层深度）")
    drives = _iter_drives()
    log_dbg(f"  发现盘符: {drives}")

    results = []

    for drive in drives:
        log_dbg(f"  扫描盘符: {drive}")
        # BFS，深度3层
        queue = [(drive, 0)]
        while queue:
            current, depth = queue.pop(0)
            if depth >= 3:
                continue
            try:
                entries = os.listdir(current)
            except PermissionError:
                continue
            except OSError:
                continue

            for entry in entries:
                entry_path = os.path.join(current, entry)
                if not os.path.isdir(entry_path):
                    continue

                # 检查名称是否含关键词
                matched_kw = None
                for kw in _SCAN_KEYWORDS:
                    if kw.lower() in entry.lower():
                        matched_kw = kw
                        break

                if matched_kw:
                    log_dbg(f"  命中关键词 {matched_kw!r}: {entry_path}")
                    if _looks_like_wechat_root(entry_path):
                        log_ok(f"  策略3 找到: {entry_path}")
                        if entry_path not in results:
                            results.append(entry_path)

                if depth < 3:
                    queue.append((entry_path, depth + 1))

    return results


# ══════════════════════════════════════════════════════════════════════════════
# 策略4：常用路径穷举（兜底）
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


def _strategy_common_paths() -> list[str]:
    """枚举常见路径组合作为最后兜底策略。"""
    log_info("策略4：常用路径穷举（兜底）")

    base_dirs = []
    for ev in _ENV_VARS:
        expanded = os.path.expandvars(ev)
        if expanded != ev and os.path.isdir(expanded):
            base_dirs.append(expanded)

    for drive in _iter_drives():
        base_dirs.append(drive)

    results = []
    for base in base_dirs:
        for rel in _COMMON_REL_PATHS:
            candidate = os.path.join(base, rel)
            log_dbg(f"  检查: {candidate}")
            if _looks_like_wechat_root(candidate):
                log_ok(f"  策略4 找到: {candidate}")
                if candidate not in results:
                    results.append(candidate)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# 主探测函数
# ══════════════════════════════════════════════════════════════════════════════

def find_wechat_root(src: str | None = None) -> str | None:
    """
    按策略0→1→2→3→4顺序探测微信数据根目录。
    找到第一个有效路径即返回。
    """
    # 策略0：用户手动指定
    if src:
        log_info(f"策略0：使用手动指定路径 {src}")
        if os.path.isdir(src):
            log_ok(f"  路径存在: {src}")
            return src
        else:
            log_err(f"  路径不存在: {src}")
            return None

    # 策略1
    results = _strategy_registry()
    if results:
        return results[0]

    # 策略2
    results = _strategy_psutil()
    if results:
        return results[0]

    # 策略3
    results = _strategy_disk_scan()
    if results:
        return results[0]

    # 策略4
    results = _strategy_common_paths()
    if results:
        return results[0]

    return None


# ══════════════════════════════════════════════════════════════════════════════
# 磁盘空间预检
# ══════════════════════════════════════════════════════════════════════════════

def _check_disk_space(dest_dir: str, required_bytes: int) -> bool:
    """检查目标目录所在盘剩余空间是否足够。"""
    try:
        usage = shutil.disk_usage(dest_dir)
        free = usage.free
        log_dbg(f"  磁盘剩余: {free / 1024 / 1024:.1f} MB，需要: {required_bytes / 1024 / 1024:.1f} MB")
        if free < required_bytes:
            log_err(
                f"磁盘空间不足！剩余 {free / 1024 / 1024:.1f} MB，"
                f"需要 {required_bytes / 1024 / 1024:.1f} MB"
            )
            return False
        return True
    except OSError as e:
        log_warn(f"磁盘空间检查失败: {e}")
        return True  # 无法检查时放行


# ══════════════════════════════════════════════════════════════════════════════
# 文件收集
# ══════════════════════════════════════════════════════════════════════════════

def _collect_files(src_dir: str) -> list[tuple[str, int]]:
    """递归收集源目录中所有文件，返回 (src_path, size) 列表。"""
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
    """线程安全的拷贝统计。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.copied = 0
        self.skipped = 0
        self.failed = 0
        self.copied_bytes = 0
        self.errors: list = []

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
    """拷贝单个文件（跳过已存在且大小相同的文件）。"""
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


def _render_progress(
    copied_count: int,
    total_count: int,
    copied_bytes: int,
    total_bytes: int,
    speed_bps: float,
    last_line_len: int,
) -> str:
    pct = copied_count / max(total_count, 1)
    bar_len = 20
    filled = int(bar_len * pct)
    bar = "█" * filled + "░" * (bar_len - filled)

    copied_mb = copied_bytes / 1024 / 1024
    total_mb = total_bytes / 1024 / 1024

    if speed_bps >= 1024 * 1024:
        speed_str = f"{speed_bps / 1024 / 1024:.1f} MB/s"
    elif speed_bps >= 1024:
        speed_str = f"{speed_bps / 1024:.0f} KB/s"
    else:
        speed_str = f"{int(speed_bps)} B/s"

    remain_bytes = total_bytes - copied_bytes
    if speed_bps > 0:
        eta_s = remain_bytes / speed_bps
        if eta_s >= 60:
            eta_str = f"剩余约 {int(eta_s // 60)}分{int(eta_s % 60)}秒"
        else:
            eta_str = f"剩余约 {int(eta_s)}秒"
    else:
        eta_str = "计算中..."

    line = (
        f"  [{bar}] {copied_count}/{total_count}  "
        f"{copied_mb:.1f}/{total_mb:.1f}MB  "
        f"⚡{speed_str}  {eta_str}   "
    )
    # 补空格清除残留字符
    pad = max(0, last_line_len - len(line))
    return line + " " * pad


def copy_wechat_data(
    src_dir: str,
    dest_dir: str,
    workers: int = 8,
) -> dict:
    """
    多线程拷贝微信数据目录到目标目录。
    db文件优先顺序拷贝，小文件并发，大文件顺序。返回统计字典。
    """
    log_info("收集文件列表...")
    all_files   = _collect_files(src_dir)
    total_count = len(all_files)
    total_bytes = sum(s for _, s in all_files)

    if total_count == 0:
        log_warn("源目录中未找到任何文件")
        return {"copied": 0, "skipped": 0, "failed": 0, "copied_bytes": 0, "errors": []}

    log_info(f"扫描完成：共 {total_count:,} 个文件  {total_bytes/1024/1024:.1f} MB")

    # 磁盘空间预检（源文件总大小 × 1.05 + 100 MB）
    required = int(total_bytes * 1.05) + 100 * 1024 * 1024
    if not _check_disk_space(dest_dir, required):
        return {"copied": 0, "skipped": 0, "failed": 0,
                "copied_bytes": 0, "errors": ["磁盘空间不足，中止拷贝"]}

    stats = _CopyStats()

    # 三类文件分类
    db_files    = [(s, z) for s, z in all_files
                   if os.path.splitext(s)[1].lower() in _DB_EXTENSIONS]
    small_files = [(s, z) for s, z in all_files
                   if os.path.splitext(s)[1].lower() not in _DB_EXTENSIONS
                   and z < SMALL_FILE_THRESHOLD]
    large_files = [(s, z) for s, z in all_files
                   if os.path.splitext(s)[1].lower() not in _DB_EXTENSIONS
                   and z >= SMALL_FILE_THRESHOLD]

    log_info(f"  db文件（数据库文件）: {len(db_files):,} 个  → 优先顺序拷贝")
    log_info(f"  小文件（<4MB）: {len(small_files):,} 个  → {workers} 线程并发")
    log_info(f"  大文件（≥4MB）: {len(large_files):,} 个  → 单线程顺序")

    # 构建目标路径
    def _dest_path(src: str) -> str:
        rel = os.path.relpath(src, src_dir)
        return os.path.join(dest_dir, rel)

    # 进度跟踪
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

            line = _render_progress(
                done_count[0], total_count,
                stats.copied_bytes,
                total_bytes,
                current_speed[0],
                last_line_len[0],
            )
            print(f"\r{line}", end="", flush=True)
            last_line_len[0] = len(line)

    # ── 第1优先：db 文件顺序拷贝 ───────────────────────────────────────────
    if db_files:
        log_info(f"[1/3] 优先拷贝 db 文件...")
        for src, size in db_files:
            _copy_one(src, _dest_path(src), size, stats)
            _update_progress(size)

    # ── 第2优先：小文件多线程并发 ──────────────────────────────────────────
    if small_files:
        log_info(f"[2/3] 拷贝小文件（{workers} 线程）...")

        def _task(item):
            src, size = item
            _copy_one(src, _dest_path(src), size, stats)
            _update_progress(size)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_task, item) for item in small_files]
            for _ in as_completed(futures):
                pass  # 进度已在 _task 中更新

    # ── 第3优先：大文件顺序拷贝 ────────────────────────────────────────────
    if large_files:
        log_info(f"[3/3] 拷贝大文件...")
        for src, size in large_files:
            _copy_one(src, _dest_path(src), size, stats)
            _update_progress(size)

    print()  # 换行

    return {
        "copied": stats.copied,
        "skipped": stats.skipped,
        "failed": stats.failed,
        "copied_bytes": stats.copied_bytes,
        "errors": stats.errors,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 拷贝报告
# ══════════════════════════════════════════════════════════════════════════════

def _write_report(dest_dir: str, src_dir: str, result: dict) -> None:
    report_path = os.path.join(dest_dir, "copy_report.txt")
    lines = [
        "=" * 60,
        "  微信数据拷贝报告",
        "=" * 60,
        f"  拷贝时间  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  源目录    : {src_dir}",
        f"  目标目录  : {dest_dir}",
        "",
        f"  已拷贝    : {result['copied']} 个文件 "
        f"({result.get('copied_bytes', 0) / 1024 / 1024:.1f} MB)",
        f"  已跳过    : {result['skipped']} 个文件（大小相同）",
        f"  失败      : {result['failed']} 个文件",
    ]
    if result["errors"]:
        lines += ["", "  错误列表:"]
        for i, err in enumerate(result["errors"], 1):
            lines.append(f"    {i}. {err}")
    lines.append("=" * 60)

    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        log_ok(f"拷贝报告已写入: {report_path}")
    except OSError as e:
        log_warn(f"写入拷贝报告失败: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# 诊断输出（所有策略均失败时）
# ══════════════════════════════════════════════════════════════════════════════

def _print_diagnostics() -> None:
    print()
    print("=" * 60)
    print("  ⚠  所有策略均未找到微信数据目录")
    print("=" * 60)
    print()
    print("  请尝试以下方案：")
    print()
    print("  1. 手动指定路径（推荐）：")
    print(r"     python wx_find_and_copy.py --src D:\微信文件\xwechat_files")
    print()
    print("  2. 开启调试模式查看详细扫描过程：")
    print("     python wx_find_and_copy.py --debug")
    print()
    print("  3. 常见微信数据目录位置参考：")
    print(r"     - C:\Users\<用户名>\Documents\WeChat Files")
    print(r"     - C:\Users\<用户名>\AppData\Roaming\Tencent\WeChat")
    print(r"     - D:\微信文件\xwechat_files")
    print(r"     - D:\WeChat Files")
    print()
    print("  4. 在微信客户端 → 设置 → 文件管理 中查看数据存储路径")
    print()
    print("=" * 60)


# ══════════════════════════════════════════════════════════════════════════════
# CLI 入口
# ══════════════════════════════════════════════════════════════════════════════

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="微信数据目录探测 & 文件拷贝工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--src", metavar="DIR",
        help="直接指定微信数据源目录（跳过自动探测）",
    )
    parser.add_argument(
        "--dest", metavar="DIR",
        help="目标目录（默认：脚本目录下 wechat_backup_<日期时分秒>/）",
    )
    parser.add_argument(
        "--workers", type=int, default=8, metavar="N",
        help="小文件并发线程数（默认 8）",
    )
    parser.add_argument(
        "--find-only", action="store_true",
        help="仅探测目录，不执行拷贝",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="打印详细调试信息",
    )
    return parser


def main() -> None:
    global _DEBUG

    parser = _build_parser()
    args = parser.parse_args()

    if args.debug:
        _DEBUG = True

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║      微信数据目录探测 & 拷贝工具  wx_find_and_copy.py    ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    # ── 探测阶段 ──────────────────────────────────────────────────────────
    src_dir = find_wechat_root(args.src)

    if not src_dir:
        _print_diagnostics()
        sys.exit(1)

    print()
    print("  ┌─────────────────────────────────────────────────────────┐")
    print(f"  │  📂 找到微信数据目录: {src_dir}")
    print("  └─────────────────────────────────────────────────────────┘")
    print()

    if args.find_only:
        log_info("--find-only 模式，跳过拷贝。")
        sys.exit(0)

    # ── 目标目录 ──────────────────────────────────────────────────────────
    if args.dest:
        dest_dir = args.dest
    else:
        script_dir = Path(__file__).parent.resolve()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest_dir = str(script_dir / f"wechat_backup_{ts}")

    os.makedirs(dest_dir, exist_ok=True)
    dest_dir = str(Path(dest_dir).resolve())

    print("  ┌─────────────────────────────────────────────────────────┐")
    print(f"  │  📁 目标目录: {dest_dir}")
    print("  └─────────────────────────────────────────────────────────┘")
    print()

    # ── 拷贝阶段 ──────────────────────────────────────────────────────────
    result = copy_wechat_data(src_dir, dest_dir, workers=args.workers)

    print()
    log_ok(
        f"拷贝完成：{result['copied']} 已拷贝，"
        f"{result['skipped']} 已跳过，"
        f"{result['failed']} 失败"
    )

    _write_report(dest_dir, src_dir, result)

    if result["errors"]:
        log_warn(f"共 {len(result['errors'])} 个错误，详见 copy_report.txt")


if __name__ == "__main__":
    main()
