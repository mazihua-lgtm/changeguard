"""ChangeGuard 测试：快照按根目录隔离、删除文件风险、按路径组件忽略。"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("changeguard", ROOT_DIR / "changeguard.py")
cg = importlib.util.module_from_spec(spec)
sys.modules["changeguard"] = cg
spec.loader.exec_module(cg)


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """每个测试使用独立的快照存储目录，不污染真实的 ~/.zcode。"""
    monkeypatch.setenv("CHANGEGUARD_HOME", str(tmp_path / "cg_home"))
    return tmp_path / "cg_home"


def write(root: Path, rel: str, text: str = "hello\n") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


# ───────────── 1. 快照按根目录隔离 ─────────────

def test_snapshot_path_differs_per_root(tmp_path):
    a = tmp_path / "proj_a"
    b = tmp_path / "proj_b"
    a.mkdir()
    b.mkdir()
    assert cg.snapshot_path(a) != cg.snapshot_path(b)
    assert cg.snapshot_path(a).parent == cg.storage_dir()


def test_snapshot_path_is_stable_for_same_root(tmp_path):
    assert cg.snapshot_path(tmp_path) == cg.snapshot_path(tmp_path)


def test_snapshot_of_one_root_does_not_overwrite_another(tmp_path):
    a = tmp_path / "proj_a"
    b = tmp_path / "proj_b"
    write(a, "a.txt", "A")
    write(b, "b.txt", "B")
    cg.snapshot(a)
    cg.snapshot(b)
    assert set(cg.load_snapshot(a)["files"]) == {"a.txt"}
    assert set(cg.load_snapshot(b)["files"]) == {"b.txt"}


def test_check_in_other_root_without_snapshot_reports_error(tmp_path):
    a = tmp_path / "proj_a"
    b = tmp_path / "proj_b"
    write(a, "a.txt")
    b.mkdir()
    cg.snapshot(a)
    assert "error" in cg.detect_changes(b)


def test_snapshot_records_root_and_is_json(tmp_path):
    write(tmp_path, "x.txt")
    cg.snapshot(tmp_path)
    data = json.loads(cg.snapshot_path(tmp_path).read_text(encoding="utf-8"))
    assert data["root"] == str(tmp_path.resolve())
    assert "x.txt" in data["files"]


def test_load_snapshot_rejects_mismatched_root(tmp_path):
    write(tmp_path, "x.txt")
    cg.snapshot(tmp_path)
    path = cg.snapshot_path(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["root"] = "/somewhere/else"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert cg.load_snapshot(tmp_path) is None


def test_default_storage_under_home_when_env_unset(monkeypatch, tmp_path):
    monkeypatch.delenv("CHANGEGUARD_HOME", raising=False)
    monkeypatch.setattr(cg.Path, "home", classmethod(lambda cls: tmp_path))
    assert cg.storage_dir() == tmp_path / ".zcode" / "changeguard" / "snapshots"


# ───────────── 2. 删除文件的风险检测 ─────────────

def test_deleted_env_file_is_flagged(tmp_path):
    write(tmp_path, ".env", "DEBUG=1\n")
    cg.snapshot(tmp_path)
    (tmp_path / ".env").unlink()
    risks = cg.detect_risks(tmp_path)
    assert any(r["file"] == ".env" and "已删除" in r["risk"] for r in risks)


def test_deleted_dockerfile_is_flagged(tmp_path):
    write(tmp_path, "Dockerfile", "FROM python\n")
    cg.snapshot(tmp_path)
    (tmp_path / "Dockerfile").unlink()
    risks = cg.detect_risks(tmp_path)
    assert any(r["file"] == "Dockerfile" for r in risks)


def test_deleted_nested_env_is_flagged(tmp_path):
    write(tmp_path, "svc/.env.production", "X=1\n")
    cg.snapshot(tmp_path)
    (tmp_path / "svc/.env.production").unlink()
    risks = cg.detect_risks(tmp_path)
    assert any(r["file"] == "svc/.env.production" for r in risks)


def test_deleted_private_key_is_flagged(tmp_path):
    write(tmp_path, "certs/server.pem", "not really a key\n")
    cg.snapshot(tmp_path)
    (tmp_path / "certs/server.pem").unlink()
    risks = cg.detect_risks(tmp_path)
    assert any(r["file"] == "certs/server.pem" for r in risks)


def test_deleted_plain_file_is_not_high_risk(tmp_path):
    write(tmp_path, "notes.txt", "hi\n")
    cg.snapshot(tmp_path)
    (tmp_path / "notes.txt").unlink()
    risks = cg.detect_risks(tmp_path)
    assert not any(r["file"] == "notes.txt" for r in risks)


def test_deleted_large_file_is_critical(tmp_path):
    write(tmp_path, "big.dat", "x" * 2000)
    cg.snapshot(tmp_path)
    (tmp_path / "big.dat").unlink()
    risks = cg.detect_risks(tmp_path)
    assert any(r["file"] == "big.dat" and r["level"] == "critical" for r in risks)


def test_deleted_file_content_is_not_read(tmp_path):
    """已删除的文件不能再读取内容；只按路径判断。"""
    write(tmp_path, "old.txt", "sk-abcdefghijklmnopqrstuvwxyz123456\n")
    cg.snapshot(tmp_path)
    (tmp_path / "old.txt").unlink()
    risks = cg.detect_risks(tmp_path)
    assert not any(r["file"] == "old.txt" and r["level"] == "critical" and "Key" in r["risk"] for r in risks)


def test_added_env_with_secret_is_flagged(tmp_path):
    cg.snapshot(tmp_path)
    write(tmp_path, ".env", "OPENAI=sk-abcdefghijklmnopqrstuvwxyz123456\n")
    risks = cg.detect_risks(tmp_path)
    assert any(r["file"] == ".env" and r["level"] == "critical" for r in risks)


# ───────────── 3. 按路径组件忽略 ─────────────

@pytest.mark.parametrize("rel", [
    "distance.py",
    "devenv.md",
    "src/distance.py",
    "docs/devenv_notes.md",
    "builder.py",
    "mydist/readme.md",
    "venvtools/run.py",
])
def test_similar_names_are_not_ignored(rel):
    assert not cg._is_ignored(tuple(rel.split("/")))


@pytest.mark.parametrize("rel", [
    "node_modules/x/index.js",
    "src/node_modules/a.js",
    ".git/config",
    "app/dist/bundle.js",
    "pkg/__pycache__/m.cpython-312.pyc",
    "sub/build/out.txt",
    ".venv/lib/a.py",
])
def test_ignored_directory_components_are_skipped(rel):
    assert cg._is_ignored(tuple(rel.split("/")))


def test_pyc_glob_ignored_anywhere():
    assert cg._is_ignored(("a", "b", "c.pyc"))


def test_ignored_file_names_match_exactly():
    assert cg._is_ignored(("etf_opportunities.md",))
    assert not cg._is_ignored(("my_etf_opportunities.md",))


def test_snapshot_includes_similar_names_and_skips_real_ignores(tmp_path):
    write(tmp_path, "distance.py")
    write(tmp_path, "devenv.md")
    write(tmp_path, "node_modules/pkg/index.js")
    write(tmp_path, "dist/app.js")
    snap = cg.snapshot(tmp_path)
    assert "distance.py" in snap["files"]
    assert "devenv.md" in snap["files"]
    assert not any(k.startswith("node_modules") for k in snap["files"])
    assert not any(k.startswith("dist/") for k in snap["files"])


def test_ignored_directory_is_not_walked(tmp_path, monkeypatch):
    write(tmp_path, "node_modules/deep/a.js")
    write(tmp_path, "keep.txt")
    visited = []
    real_walk = cg.os.walk

    def spy(top, *a, **k):
        for dirpath, dirnames, filenames in real_walk(top, *a, **k):
            visited.append(dirpath)
            yield dirpath, dirnames, filenames

    monkeypatch.setattr(cg.os, "walk", spy)
    cg.snapshot(tmp_path)
    assert not any("node_modules" in v for v in visited)


# ───────────── 4. 其余回归 ─────────────

def test_changed_file_detected(tmp_path):
    write(tmp_path, "a.txt", "one\n")
    cg.snapshot(tmp_path)
    write(tmp_path, "a.txt", "two two\n")
    changes = cg.detect_changes(tmp_path)
    assert [c["file"] for c in changes["changed"]] == ["a.txt"]


def test_added_file_detected(tmp_path):
    cg.snapshot(tmp_path)
    write(tmp_path, "new.txt")
    assert cg.detect_changes(tmp_path)["added"] == ["new.txt"]


def test_report_runs_and_lists_risks(tmp_path):
    write(tmp_path, ".env", "A=1\n")
    cg.snapshot(tmp_path)
    (tmp_path / ".env").unlink()
    report = cg.generate_report(tmp_path)
    assert "风险警告" in report
    assert ".env" in report


def test_report_without_snapshot_returns_error(tmp_path):
    assert cg.generate_report(tmp_path).startswith("❌")
