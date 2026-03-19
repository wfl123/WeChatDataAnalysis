"""01_wx_win.py — 微信数据密钥提取工具（Windows）

支持自动探测微信进程、提取加密密钥，并自动拷贝微信数据文件。

用法:
    python 01_wx_win.py                # 完整流程（密钥提取 + 拷贝）
    python 01_wx_win.py --key-only     # 仅提取密钥，不拷贝
    python 01_wx_win.py --workers 16   # 指定拷贝线程数
    python 01_wx_win.py --dest E:\\backup  # 指定拷贝目标目录
    python 01_wx_win.py --debug        # 打印详细调试信息
"""

import argparse
import ctypes
import json
import os
import signal
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# ── 可选依赖 ──────────────────────────────────────────────────────────────────
try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

try:
    import frida
    _HAS_FRIDA = True
except ImportError:
    _HAS_FRIDA = False

# winreg 只在 Windows 下存在
try:
    import winreg
    _HAS_WINREG = True
except ImportError:
    _HAS_WINREG = False

# ── 从同目录加载 wx_find_and_copy ─────────────────────────────────────────────
def _get_exe_dir() -> str:
    """获取可执行文件或脚本所在目录（兼容 PyInstaller 打包环境）。"""
    if getattr(sys, "frozen", False):
        # PyInstaller 打包后 sys.executable 是 exe 路径
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


_script_dir = _get_exe_dir()
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

try:
    from wx_find_and_copy import (
        find_wechat_root,
        copy_wechat_data,
        _write_report,
    )
    _HAS_FINDER = True
except ImportError:
    _HAS_FINDER = False

# ── 全局配置 ──────────────────────────────────────────────────────────────────
COPY_WORKERS = 8
_DEBUG = False

# ── WeChat 特征码（用于在进程内存中定位密钥）────────────────────────────────
# 不同版本 WeChat 的内存特征
_KEY_PATTERNS = [
    # WeChat 3.x / xwechat
    b"\x8b\x45\xfc\x8b\x55\xf8",
    b"\xff\x15",
]

# Frida 注入脚本（提取 SQLCipher 密钥）
_FRIDA_SCRIPT = r"""
'use strict';

// 搜索 sqlite3_key / sqlite3_key_v2 调用，拦截密钥参数
var targets = ['sqlite3_key', 'sqlite3_key_v2'];

targets.forEach(function(name) {
    var sym = Module.findExportByName(null, name);
    if (!sym) return;

    Interceptor.attach(sym, {
        onEnter: function(args) {
            // sqlite3_key(db, pKey, nKey)
            // sqlite3_key_v2(db, zDbName, pKey, nKey)
            var isV2 = (name === 'sqlite3_key_v2');
            var keyPtr  = isV2 ? args[2] : args[1];
            var keyLen  = isV2 ? args[3].toInt32() : args[2].toInt32();
            if (keyLen <= 0 || keyLen > 256) return;
            try {
                var keyBytes = keyPtr.readByteArray(keyLen);
                var keyHex   = Array.from(new Uint8Array(keyBytes))
                    .map(b => b.toString(16).padStart(2, '0')).join('');
                send({type: 'key', func: name, hex: keyHex, len: keyLen});
            } catch(e) {
                send({type: 'err', msg: e.toString()});
            }
        }
    });
});

send({type: 'ready'});
"""


# ══════════════════════════════════════════════════════════════════════════════
# 日志辅助
# ══════════════════════════════════════════════════════════════════════════════

def _log(tag: str, msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{tag}] {msg}", flush=True)


def log_ok(msg: str)     -> None: _log(" OK ", msg)
def log_err(msg: str)    -> None: _log("ERR ", msg)
def log_warn(msg: str)   -> None: _log("WARN", msg)
def log_info(msg: str)   -> None: _log("INFO", msg)
def log_step(n: int, total: int, msg: str) -> None:
    _log("STEP", f"[{n}/{total}] {msg}")
def log_dbg(msg: str) -> None:
    if _DEBUG:
        _log("DBG ", msg)


# ══════════════════════════════════════════════════════════════════════════════
# 权限检查
# ══════════════════════════════════════════════════════════════════════════════

def _is_admin() -> bool:
    """检查是否以管理员权限运行。"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _request_admin() -> None:
    """请求提升为管理员权限（重新启动）。"""
    if not _is_admin():
        log_warn("当前未以管理员身份运行，正在请求提权...")
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
        except Exception as e:
            log_err(f"请求提权失败: {e}")
        sys.exit(0)


# ══════════════════════════════════════════════════════════════════════════════
# 进程探测
# ══════════════════════════════════════════════════════════════════════════════

def _find_wechat_pid() -> int:
    """查找 Weixin.exe 进程 PID，返回第一个找到的 PID，未找到返回 0。"""
    if not _HAS_PSUTIL:
        log_warn("psutil 未安装，无法自动查找微信进程")
        return 0

    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if proc.info["name"] and proc.info["name"].lower() == "weixin.exe":
                log_info(f"找到微信进程: PID={proc.info['pid']}")
                return proc.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return 0


# ══════════════════════════════════════════════════════════════════════════════
# Frida 密钥提取
# ══════════════════════════════════════════════════════════════════════════════

def _extract_key_frida(pid: int, timeout: int = 30) -> str | None:
    """
    用 Frida 注入目标进程，拦截 sqlite3_key 调用获取密钥。
    返回十六进制密钥字符串，超时或失败返回 None。
    """
    if not _HAS_FRIDA:
        log_warn("frida 未安装，跳过 Frida 密钥提取")
        return None

    result_key = [None]
    done_event = threading.Event()

    def _on_message(message, _data):
        if message.get("type") != "send":
            return
        payload = message.get("payload", {})
        if payload.get("type") == "key":
            result_key[0] = payload["hex"]
            log_ok(f"Frida 拦截到密钥 ({payload['len']} bytes) via {payload['func']}")
            done_event.set()
        elif payload.get("type") == "ready":
            log_info("Frida 脚本注入成功，等待微信打开数据库...")
        elif payload.get("type") == "err":
            log_warn(f"Frida 脚本错误: {payload.get('msg')}")

    session = None
    script = None
    try:
        log_info(f"Frida 附加到 PID {pid}...")
        session = frida.attach(pid)
        script = session.create_script(_FRIDA_SCRIPT)
        script.on("message", _on_message)
        script.load()

        log_info(f"等待密钥拦截（最多 {timeout} 秒）...")
        log_info("提示：请在微信中打开任意聊天记录以触发数据库解密")
        done_event.wait(timeout=timeout)

    except frida.ProcessNotFoundError:
        log_err(f"进程 PID={pid} 不存在")
    except frida.PermissionError:
        log_err("Frida 注入被拒绝，请以管理员身份运行")
    except Exception as e:
        log_err(f"Frida 错误: {e}")
    finally:
        if script:
            try:
                script.unload()
            except Exception:
                pass
        if session:
            try:
                session.detach()
            except Exception:
                pass

    return result_key[0]


# ══════════════════════════════════════════════════════════════════════════════
# 结果保存
# ══════════════════════════════════════════════════════════════════════════════

def _save_key_result(out_dir: str, pid: int, key_hex: str) -> None:
    """将密钥结果写入 key_result.txt 和 key_result.json。"""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 纯文本格式
    txt_path = os.path.join(out_dir, "key_result.txt")
    lines = [
        "=" * 60,
        "  微信数据库密钥提取结果",
        "=" * 60,
        f"  提取时间  : {ts}",
        f"  目标 PID  : {pid}",
        f"  密钥（hex）: {key_hex}",
        "",
        "  使用方法：",
        "    在 DB Browser for SQLite / sqlcipher 中打开数据库时，",
        '    选择 "Raw key" 并填入上方密钥（含 0x 前缀或不含均可）',
        "=" * 60,
    ]
    try:
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        log_ok(f"密钥已保存: {txt_path}")
    except OSError as e:
        log_warn(f"写入 key_result.txt 失败: {e}")

    # JSON 格式（方便程序读取）
    json_path = os.path.join(out_dir, "key_result.json")
    data = {
        "timestamp": ts,
        "pid": pid,
        "key_hex": key_hex,
        "key_hex_prefixed": f"0x{key_hex}",
    }
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        log_ok(f"密钥已保存: {json_path}")
    except OSError as e:
        log_warn(f"写入 key_result.json 失败: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# 主流程
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    global COPY_WORKERS, _DEBUG

    parser = argparse.ArgumentParser(
        description="微信数据密钥提取工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--key-only", action="store_true",
        help="仅提取密钥，跳过文件拷贝",
    )
    parser.add_argument(
        "--workers", type=int, default=8, metavar="N",
        help="拷贝线程数（默认 8）",
    )
    parser.add_argument(
        "--dest", metavar="DIR",
        help="拷贝目标目录（默认：脚本目录下 wx_<日期时间>/）",
    )
    parser.add_argument(
        "--pid", type=int, default=0, metavar="PID",
        help="手动指定微信进程 PID（默认自动查找）",
    )
    parser.add_argument(
        "--timeout", type=int, default=30, metavar="SEC",
        help="Frida 等待密钥超时秒数（默认 30）",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="打印详细调试信息",
    )
    args = parser.parse_args()

    COPY_WORKERS = args.workers
    if args.debug:
        _DEBUG = True

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║          微信数据密钥提取工具  01_wx_win.py              ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    # 设置输出目录
    if args.dest:
        out_dir = args.dest
    else:
        ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = os.path.join(_script_dir, f"wx_{ts_str}")

    os.makedirs(out_dir, exist_ok=True)
    out_dir = str(Path(out_dir).resolve())
    log_info(f"输出目录: {out_dir}")

    # ── Step 1: 权限检查 ──────────────────────────────────────────────────
    log_step(1, 5, "检查运行权限...")
    if not _is_admin():
        log_warn("未检测到管理员权限，部分功能可能受限")
        log_warn("建议右键以管理员身份运行")
    else:
        log_ok("以管理员权限运行")

    # ── Step 2: 查找微信进程 ──────────────────────────────────────────────
    log_step(2, 5, "查找微信进程...")
    pid = args.pid if args.pid else _find_wechat_pid()

    if not pid:
        log_err("未找到微信进程（Weixin.exe），请确保微信已启动")
        log_warn("如需手动指定 PID，请使用: --pid <PID>")
        sys.exit(1)

    log_ok(f"目标进程 PID: {pid}")

    # ── Step 3: 提取密钥 ──────────────────────────────────────────────────
    log_step(3, 5, "提取微信数据库密钥...")

    if not _HAS_FRIDA:
        log_err("frida 未安装，无法提取密钥")
        log_warn("请运行: pip install frida frida-tools")
        sys.exit(1)

    key_hex = _extract_key_frida(pid, timeout=args.timeout)

    if not key_hex:
        log_err("密钥提取失败（超时或未拦截到）")
        log_warn("请确保微信已登录并打开了聊天记录")
        sys.exit(1)

    log_ok(f"密钥: {key_hex}")

    # ── Step 4: 保存密钥 ──────────────────────────────────────────────────
    log_step(4, 5, "保存密钥结果...")
    _save_key_result(out_dir, pid, key_hex)

    # ── Step 5: 搜索并拷贝微信数据 ───────────────────────────────────────
    if args.key_only:
        log_info("--key-only 模式，跳过拷贝")
    else:
        log_step(5, 5, "搜索微信数据目录并拷贝所有文件...")

        if not _HAS_FINDER:
            log_err("未找到 wx_find_and_copy.py，请将其与本脚本放在同一目录")
            log_warn("可单独运行拷贝:")
            log_warn(f'  python wx_find_and_copy.py --dest "{out_dir}"')
        else:
            src_dir = find_wechat_root()

            if src_dir:
                log_info(f"找到微信数据目录: {src_dir}")
            else:
                log_warn("未自动找到微信数据目录，可手动指定:")
                log_warn(f'  python wx_find_and_copy.py --src <微信数据路径> --dest "{out_dir}"')

            if src_dir:
                copy_dest = os.path.join(out_dir, "wechat_backup")
                os.makedirs(copy_dest, exist_ok=True)

                result = copy_wechat_data(src_dir, copy_dest, workers=COPY_WORKERS)
                _write_report(copy_dest, src_dir, result)

                log_ok(
                    f"拷贝完成  成功:{result['copied']:,}  "
                    f"跳过:{result['skipped']:,}  失败:{result['failed']:,}  "
                    f"总计:{result.get('copied_bytes', 0) / 1024 / 1024:.1f} MB"
                )
                if result["failed"] > 0:
                    log_warn(f"{result['failed']} 个文件失败（详见 copy_report.txt）")

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║                      完成！                              ║")
    print(f"║  输出目录: {out_dir[:46]:<46} ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()


if __name__ == "__main__":
    # 捕获 Ctrl+C
    signal.signal(signal.SIGINT, lambda *_: (print("\n已中止"), sys.exit(0)))
    main()
