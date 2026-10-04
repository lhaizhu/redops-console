"""project.py — 多项目工作区 + state.py CLI 客户端 + 历史记账(数据层;不依赖 engine/intel)
交战状态:state.json 唯一写者 bin/state.py(薄 shim → redops.state);任何状态故障都不影响执行"""
import json, os, re, subprocess, sys, tempfile, threading, time
from pathlib import Path
from .paths import PROJECTS, ACTIVE, RUNS, BIN

STATE_PY = BIN / "state.py"   # 薄 shim,CLI 契约不变
SCOPE_PY = BIN / "scope.py"   # 薄 shim,CLI 契约不变

def proj_dir(name=""):
    """返回激活项目目录(校验名字合法,防穿越);无激活返回 None"""
    if not ACTIVE.exists(): return None
    try: name = name or json.loads(ACTIVE.read_text()).get("name", "")
    except Exception: return None
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", name): return None
    d = PROJECTS / name
    return d if d.is_dir() else None

def proj_create(name, **fields):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", name or ""):
        raise ValueError("项目名限 1-32 位字母数字._-")
    d = PROJECTS / name
    if d.exists(): raise ValueError(f"项目已存在: {name}")
    (d / "loot" / "runs").mkdir(parents=True)
    (d / "creds.csv").write_text("时间,类型,主体,域,值(密码/NT哈希/票据路径),来源,已知权限,用过没,备注\n", encoding="utf-8")
    (d / "notes.md").write_text(f"# 项目 {name} — 流程时间线\n\n> 每次执行自动追加;手工复盘直接往下写\n\n", encoding="utf-8")
    domains = [{"name": fields.get("domain", ""), "dcip": fields.get("dcip", ""), "dcfqdn": fields.get("dcfqdn", "")}]
    domains = [x for x in domains if x["name"]]
    proj = {"name": name, "domain": fields.get("domain", ""), "dcip": fields.get("dcip", ""),
            "dcfqdn": fields.get("dcfqdn", ""), "me": fields.get("me", ""), "domains": domains,
            "created": time.strftime("%Y-%m-%d %H:%M")}
    (d / "project.json").write_text(json.dumps(proj, ensure_ascii=False, indent=2), encoding="utf-8")
    _atomic_write_text(ACTIVE, json.dumps({"name": name}))
    return proj

def _atomic_write_text(path, text):
    """tmp+os.replace 原子写文本:并发读者不会读到半截 JSON(激活项目切换等)"""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)

def proj_add_domain(name, dom, dcip="", dcfqdn=""):
    """向激活/指定项目追加域(多域场景);重复域名报错"""
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", name or ""):
        raise ValueError("项目名限 1-32 位字母数字._-")
    d = PROJECTS / name
    pj = d / "project.json"
    proj = json.loads(pj.read_text(encoding="utf-8"))
    domains = proj.get("domains", [])
    if any(x["name"].lower() == dom.lower() for x in domains):
        raise ValueError(f"域已存在: {dom}")
    domains.append({"name": dom, "dcip": dcip, "dcfqdn": dcfqdn})
    proj["domains"] = domains
    if not proj.get("domain"): proj.update(domain=dom, dcip=dcip, dcfqdn=dcfqdn)
    pj.write_text(json.dumps(proj, ensure_ascii=False, indent=2), encoding="utf-8")
    return proj

NOTE_MAX, NOTE_KEEP = 2000, 1000  # notes.md 轮转:超上限保留尾部并置标记

def proj_note(proj, line):
    np = proj / "notes.md"
    with open(np, "a", encoding="utf-8") as f:
        f.write(f"- {time.strftime('%m-%d %H:%M')} {line}\n")
    _rotate_notes(np)

def _rotate_notes(np):
    """notes.md 超 NOTE_MAX 行 → 保留尾 NOTE_KEEP 行,首行置轮转标记(临时文件+os.replace 原子改写);fail-safe"""
    try:
        lines = np.read_text(encoding="utf-8", errors="ignore").splitlines(keepends=True)
        if len(lines) <= NOTE_MAX:
            return
        cut = len(lines) - NOTE_KEEP
        tmp = np.with_name(np.name + ".tmp")
        tmp.write_text(f"> (旧记录已轮转,共截断 {cut} 行)\n" + "".join(lines[-NOTE_KEEP:]), encoding="utf-8")
        os.replace(tmp, np)
    except Exception:
        pass

def _state_dir(proj):
    """状态目录:激活项目优先;无项目退回全局 loot(项目外也能记账)"""
    return proj if proj else RUNS.parent

def _state(projdir, *args):
    """调 bin/state.py;超时/异常绝不抛出,返回 (rc, stdout)"""
    try:
        r = subprocess.run([sys.executable, str(STATE_PY), str(projdir), *[str(a) for a in args]],
                           capture_output=True, text=True, timeout=10)
        return r.returncode, (r.stdout or "").strip()
    except Exception:
        return -1, ""

def _tried_ts(projdir, key):
    """best-effort 读 tried[key].ts(check 子命令不回显时间戳);失败 None"""
    try:
        return json.loads((Path(projdir) / "state.json").read_text(encoding="utf-8"))["tried"][key]["ts"]
    except Exception:
        return None

def _has_scope(projdir):
    """scope.txt 存在且至少一条有效允许行(对齐 scope.py「无文件/空」语义;供无目标参数时判空)"""
    try:
        for l in (Path(projdir) / "scope.txt").read_text(encoding="utf-8").splitlines():
            l = l.strip()
            if l and not l.startswith(("#", "!")):
                return True
    except OSError:
        pass
    return False

_HIST_LOCK = threading.Lock()  # history.jsonl 进程内唯一写者锁:轮转读-改写与追加整体互斥,不丢并发条目

def hist(entry, runs_root=None):
    hp = (runs_root or RUNS) / "history.jsonl"
    with _HIST_LOCK:
        try:  # 轮转:已超 1000 行 → 留尾 500 再追加(mkstemp 临时名+os.replace 原子换);故障不影响记账
            if hp.exists():
                with open(hp, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                if len(lines) > 1000:
                    fd, tmp = tempfile.mkstemp(dir=hp.parent, prefix=".hist-")
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        f.write("".join(lines[-500:]))
                    os.replace(tmp, hp)
        except OSError:
            pass
        with open(hp, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def hist_entries(hp, n):
    """读 history.jsonl 尾 n 行;单行损坏跳过,不拖垮整个端点"""
    if not hp.exists(): return []
    out = []
    for l in hp.read_text().splitlines()[-n:]:
        try: out.append(json.loads(l))
        except ValueError: pass
    return out

def run_roots():
    """全局 runs 目录 + 各项目 loot/runs(/api/log、/api/stop 共用根白名单)"""
    return [RUNS.resolve()] + [d.resolve() for d in PROJECTS.glob("*/loot/runs")]

RUNS_KEEP = 300  # 每个 runs 根保留的最新运行目录数,更老的打包进 archive/ 后删除

def prune_runs(root, keep=RUNS_KEEP):
    """runs 目录轮转:超出 keep 的最旧目录打包到 loot/archive/runs-YYYYMM.tar.gz 后删除。
    证据不丢(压缩归档),磁盘有界。fail-safe:任何异常都不影响调用方。返回 (归档数, 归档路径或None)。"""
    import tarfile
    try:
        dirs = sorted((d for d in root.iterdir() if d.is_dir()), key=lambda d: d.stat().st_mtime)
        old = dirs[:-keep] if len(dirs) > keep else []
        if not old:
            return 0, None
        arc_dir = root.parent / "archive"; arc_dir.mkdir(exist_ok=True)
        arc = arc_dir / time.strftime("runs-%Y%m%d-%H%M%S.tar.gz")
        with tarfile.open(arc, "w:gz") as tf:   # gzip 不支持追加,每次轮转独立归档
            for d in old:
                tf.add(d, arcname=d.name)
        for d in old:
            import shutil; shutil.rmtree(d, ignore_errors=True)
        return len(old), arc
    except Exception:
        return 0, None

def prune_all_runs():
    """启动钩子:所有 runs 根轮转;有动作的项目记 notes。"""
    for root in run_roots():
        n, arc = prune_runs(root)
        if n and root != RUNS.resolve():  # 全局根只轮转,不记项目笔记
            proj_note(root.parent.parent, f"🧹 runs 轮转:归档 {n} 个旧运行目录 → {arc.name}")
