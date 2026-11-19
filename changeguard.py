"""
ChangeGuard —— AI 变更追踪 + 风险审查

工作流：
  1. snapshot → 快照当前项目所有文件哈希（每个项目根目录单独存储）
  2. check / report → 对比变化，标记风险（包括已删除文件）

快照存放位置：
  $CHANGEGUARD_HOME/snapshots/<根目录哈希>.json
  未设置 CHANGEGUARD_HOME 时默认为 ~/.zcode/changeguard
"""

import hashlib
import json
import os
import re
import sys
from datetime import datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Optional

REPORT_NAME = "changeguard_report.md"

# 忽略的目录名（按路径组件精确匹配，不做子串匹配）
IGNORE_DIR_NAMES = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".next", "dist", "build", ".zcode", "miaoxiang", ".npm", ".cache",
}

# 忽略的文件名（精确匹配）
IGNORE_FILE_NAMES = {
    ".DS_Store", "etf_diagnose_report.md", "etf_opportunities.md", REPORT_NAME,
}

# 忽略的文件名通配符
IGNORE_FILE_GLOBS = ["*.pyc"]

# 高风险文件模式（对相对路径做 re.search，按路径匹配，删除的文件同样适用）
HIGH_RISK_PATTERNS = [
    (r"(^|/)\.env$", "🔴 环境变量文件"),
    (r"(^|/)\.env\..+$", "🔴 环境配置"),
    (r"(^|/)[^/]+\.(pem|key|p12|pfx)$", "🔴 密钥/证书文件"),
    (r"(^|/)Dockerfile(\..+)?$", "🟡 Docker 配置"),
    (r"(^|/)(docker|compose)[^/]*\.ya?ml$", "🟡 Docker 配置"),
    (r"(^|/)package\.json$", "🟡 依赖配置"),
    (r"(^|/)prisma/.*\.prisma$", "🟡 数据库 Schema"),
    (r"\.sh$", "🟡 Shell 脚本"),
    (r"(^|/)Makefile$", "🟡 构建脚本"),
    (r"(^|/)config[^/]*\.json$", "🟡 配置文件"),
]

# 风险内容检测（只扫描仍然存在的新增/修改文件）
RISK_CONTENT = [
    (r'(?:api[_-]?key|apikey|secret|token|password)\s*[=:]\s*["\']?[a-zA-Z0-9_\-]{16,}["\']?',
     "🔴 疑似密钥/密码泄露"),
    (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
     "🔴 私钥泄露"),
    (r'sk-[a-zA-Z0-9_\-]{20,}',
     "🔴 OpenAI/Claude API Key"),
]


# ═══════════════════════════════════════════════
#  存储位置（按项目根目录分开）
# ═══════════════════════════════════════════════

def storage_dir() -> Path:
    override = os.environ.get("CHANGEGUARD_HOME")
    base = Path(override) if override else Path.home() / ".zcode" / "changeguard"
    return base / "snapshots"


def _resolve_root(root: Optional[Path]) -> Path:
    return (root or Path.cwd()).resolve()


def root_key(root: Path) -> str:
    """根目录的稳定哈希，用作快照文件名。"""
    return hashlib.sha256(str(_resolve_root(root)).encode("utf-8")).hexdigest()[:16]


def snapshot_path(root: Path) -> Path:
    return storage_dir() / f"{root_key(root)}.json"


# ═══════════════════════════════════════════════
#  忽略规则（按路径组件匹配）
# ═══════════════════════════════════════════════

def _is_ignored(rel_parts: tuple) -> bool:
    """rel_parts 是相对根目录的路径组件，例如 ('src', 'dist', 'a.js')。"""
    *dirs, name = rel_parts
    if any(d in IGNORE_DIR_NAMES for d in dirs):
        return True
    if name in IGNORE_FILE_NAMES:
        return True
    return any(fnmatch(name, g) for g in IGNORE_FILE_GLOBS)


def _iter_files(root: Path):
    """遍历项目文件，忽略的目录会被整棵剪掉（不进入 node_modules 等）。"""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORE_DIR_NAMES)
        base = Path(dirpath)
        for fn in sorted(filenames):
            p = base / fn
            rel = p.relative_to(root)
            if _is_ignored(rel.parts):
                continue
            if p.is_symlink() or not p.is_file():
                continue
            yield rel.as_posix(), p


# ═══════════════════════════════════════════════
#  快照引擎
# ═══════════════════════════════════════════════

def _hash_file(path: Path) -> str:
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()[:16]
    except Exception:
        return "ERROR"


def _file_info(path: Path) -> dict:
    return {
        "hash": _hash_file(path),
        "size": path.stat().st_size,
        "mtime": path.stat().st_mtime,
    }


def snapshot(root: Optional[Path] = None) -> dict:
    """创建指定项目根目录的文件快照（只影响该根目录的快照文件）。"""
    root = _resolve_root(root)
    files = {rel: _file_info(p) for rel, p in _iter_files(root)}
    snap = {
        "root": str(root),
        "time": datetime.now().isoformat(),
        "files": files,
    }
    path = snapshot_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
    return snap


def load_snapshot(root: Optional[Path] = None) -> Optional[dict]:
    """加载该根目录的快照；快照里记录的根目录不一致时视为不存在。"""
    root = _resolve_root(root)
    path = snapshot_path(root)
    if not path.exists():
        return None
    snap = json.loads(path.read_text(encoding="utf-8"))
    if snap.get("root") != str(root):
        return None
    return snap


# ═══════════════════════════════════════════════
#  变更检测
# ═══════════════════════════════════════════════

def detect_changes(root: Optional[Path] = None) -> dict:
    """对比快照和当前状态，返回变更列表。"""
    root = _resolve_root(root)
    snap = load_snapshot(root)
    if not snap:
        return {"error": "请先运行 snapshot 创建快照"}

    old_files = snap["files"]
    new_files = {rel: _file_info(p) for rel, p in _iter_files(root)}

    added = set(new_files) - set(old_files)
    removed = set(old_files) - set(new_files)
    changed = []
    for rel in set(old_files) & set(new_files):
        if old_files[rel]["hash"] != new_files[rel]["hash"]:
            changed.append({
                "file": rel,
                "old_size": old_files[rel]["size"],
                "new_size": new_files[rel]["size"],
                "delta": new_files[rel]["size"] - old_files[rel]["size"],
            })

    big_deletes = []
    for rel in removed:
        old_size = old_files[rel]["size"]
        if old_size > 1000:  # >1KB
            big_deletes.append({"file": rel, "old_size": old_size})

    return {
        "added": sorted(added),
        "removed": sorted(removed),
        "changed": sorted(changed, key=lambda c: abs(c["delta"]), reverse=True),
        "big_deletes": big_deletes,
        "total_files": len(new_files),
        "snapshot_time": snap["time"],
    }


# ═══════════════════════════════════════════════
#  风险检测
# ═══════════════════════════════════════════════

def detect_risks(root: Optional[Path] = None) -> list[dict]:
    """扫描变更中的风险。删除的文件也会按路径检查高风险模式。"""
    root = _resolve_root(root)
    changes = detect_changes(root)
    if "error" in changes:
        return []
    risks = []

    # 高风险路径：新增、修改、删除的文件都检查（删除的文件只能按路径判断）
    path_hits = set(changes["added"]) | set(changes["removed"])
    path_hits |= {c["file"] for c in changes["changed"]}
    for rel in sorted(path_hits):
        for pattern, label in HIGH_RISK_PATTERNS:
            if re.search(pattern, rel):
                status = "已删除" if rel in changes["removed"] else "新增/修改"
                risks.append({"file": rel, "risk": f"{label}（{status}）", "level": "high"})
                break

    # 大文件删除
    for d in changes["big_deletes"]:
        risks.append({
            "file": d["file"],
            "risk": f"🔴 删除大文件（{d['old_size']:,}字节）",
            "level": "critical",
        })

    # 内容风险扫描：只读仍然存在的新增/修改文件
    readable = set(changes["added"]) | {c["file"] for c in changes["changed"]}
    for rel in sorted(readable):
        filepath = root / rel
        if not filepath.is_file() or filepath.stat().st_size > 50000:
            continue
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for pattern, label in RISK_CONTENT:
            if re.search(pattern, content, re.IGNORECASE):
                risks.append({"file": rel, "risk": label, "level": "critical"})
                break

    return risks


# ═══════════════════════════════════════════════
#  报告
# ═══════════════════════════════════════════════

def generate_report(root: Optional[Path] = None) -> str:
    """生成完整的变更审查报告。"""
    root = _resolve_root(root)
    changes = detect_changes(root)
    if "error" in changes:
        return f"❌ {changes['error']}"
    risks = detect_risks(root)

    lines = [
        "# 🔍 AI 变更审查报告",
        "",
        f"**快照时间**：{changes['snapshot_time']}",
        f"**检查时间**：{datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**文件总数**：{changes['total_files']}",
        "",
    ]

    added_n = len(changes["added"])
    removed_n = len(changes["removed"])
    changed_n = len(changes["changed"])
    risk_n = len(risks)

    lines.append("## 📊 变更摘要")
    lines.append(f"- 🟢 新增：{added_n} 个文件")
    lines.append(f"- 🔴 删除：{removed_n} 个文件")
    lines.append(f"- 🟡 修改：{changed_n} 个文件")
    if risk_n > 0:
        lines.append(f"- ⚠️ 风险项：**{risk_n}** 个")
    lines.append("")

    if risks:
        lines.append("## ⚠️ 风险警告")
        lines.append("")
        for r in risks:
            lines.append(f"- {r['risk']}：`{r['file']}`")
        lines.append("")

    if changes["changed"]:
        lines.append("## 📝 文件修改（按变动大小排序）")
        lines.append("")
        for c in changes["changed"][:15]:
            sign = "+" if c["delta"] >= 0 else ""
            lines.append(f"- `{c['file']}` ({c['old_size']:,} → {c['new_size']:,}, {sign}{c['delta']:,} 字节)")
        if len(changes["changed"]) > 15:
            lines.append(f"- ... 还有 {len(changes['changed']) - 15} 个文件")
        lines.append("")

    if changes["added"]:
        lines.append(f"## 🟢 新增文件（{len(changes['added'])}）")
        lines.append("")
        for f in changes["added"][:10]:
            lines.append(f"- `{f}`")
        if len(changes["added"]) > 10:
            lines.append(f"- ... 还有 {len(changes['added']) - 10} 个")
        lines.append("")

    if risk_n == 0:
        lines.append("## ✅ 安全结论")
        lines.append("未检测到风险项。所有变更看起来正常。")
    else:
        lines.append("## ⚠️ 需要人工审查")
        lines.append(f"发现 {risk_n} 个风险项，请在合并前逐条检查。")

    return "\n".join(lines)


# ═══════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print("用法: changeguard [snapshot|check|report] [项目目录]")
        return

    cmd = sys.argv[1]
    root = _resolve_root(Path(sys.argv[2]) if len(sys.argv) > 2 else None)

    if cmd == "snapshot":
        snap = snapshot(root)
        print(f"✅ 已快照 {len(snap['files'])} 个文件（{root}）")

    elif cmd == "check":
        changes = detect_changes(root)
        if "error" in changes:
            print(f"❌ {changes['error']}")
        else:
            print(f"📊 {changes['total_files']} 个文件，"
                  f"+{len(changes['added'])} -{len(changes['removed'])} "
                  f"~{len(changes['changed'])}")

    elif cmd == "report":
        report = generate_report(root)
        print(report)
        out = root / REPORT_NAME
        out.write_text(report, encoding="utf-8")
        print(f"\n📄 已保存: {out}")

    else:
        print("未知命令: " + cmd)


if __name__ == "__main__":
    main()
