"""paths.py — 路径常量。ROOT=~/tools(数据不动:projects/loot 仍在 ROOT 下),BASE=redops 包目录"""
import os
from pathlib import Path

BASE = Path(__file__).resolve().parent   # ~/tools/redops
ROOT = BASE.parent                       # ~/tools
WEB = BASE / "web"
PROJECTS = ROOT / "projects"; PROJECTS.mkdir(parents=True, exist_ok=True)
ACTIVE = PROJECTS / "active.json"
LOOT = ROOT / "loot"
RUNS = LOOT / "runs"; RUNS.mkdir(parents=True, exist_ok=True)
BIN = ROOT / "bin"

# PATH 前置:tools/bin 须在 .local/bin 之前(同名脚本优先用仓库版);先 prepend 的会后置,故顺序反写
for _p in (Path.home() / ".local/bin", Path.home() / "tools/bin"):
    os.environ["PATH"] = f"{_p}:{os.environ.get('PATH', '')}"
