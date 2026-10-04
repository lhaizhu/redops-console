#!/usr/bin/env python3
"""regress.py — 永久回归包: python3 -m redops.tests.regress
全流程隔离:一切写操作落在 /tmp 临时树(临时 PROJECTS/RUNS 模块补丁 + 临时 HOME + stub PATH),
绝不触碰真实 ~/tools/projects、loot 与 redops/config.json|bh.json(末尾有哈希比对作证)。
每个用例一个函数(@case 登记);全绿打印 REGRESS-ALL-OK,任一失败列出失败项并非零退出。"""
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import traceback
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent          # redops/
ROOT = BASE.parent                                     # ~/tools
BIN = ROOT / "bin"
STATE_PY, SCOPE_PY = BIN / "state.py", BIN / "scope.py"
REPORT_SH, CRACK_SYNC = BIN / "report.sh", BIN / "crack-sync.sh"

def _sha(p):
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return None

# 隔离证据基线:必须在 import redops 之前取(导入 config 可能在配置缺失时落盘默认值)
REAL_HASHES = {str(p): _sha(p) for p in (BASE / "config.json", BASE / "bh.json")}

from redops import config, engine, intel, project, server  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="redops-regress-"))
PROJS = TMP / "projects"
RUNS = TMP / "loot" / "runs"

CASES = []

def case(fn):
    CASES.append(fn)
    return fn

def ck(cond, msg):
    if not cond:
        raise AssertionError(msg)

def _env(extra=None):
    e = dict(os.environ)
    e["PYTHONPATH"] = str(ROOT) + os.pathsep + e.get("PYTHONPATH", "")
    if extra:
        e.update(extra)
    return e

def py(script, *args, env=None):
    """跑 python CLI(state.py/scope.py),stdout/stderr 收回"""
    return subprocess.run(["python3", str(script), *args],
                          capture_output=True, text=True, env=_env(env), timeout=60)

def bash(script, *args, env=None, cwd=None):
    return subprocess.run(["bash", str(script), *args],
                          capture_output=True, text=True, env=_env(env), cwd=cwd, timeout=120)

CSV_HEADER = ["时间", "类型", "主体", "域", "值", "来源", "已知权限", "用过没", "备注"]

def csv_write(d, rows):
    with open(d / "creds.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(CSV_HEADER)
        w.writerows(rows)

def csv_append(d, row):
    new = not (d / "creds.csv").exists()
    with open(d / "creds.csv", "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new:
            w.writerow(CSV_HEADER)
        w.writerow(row)

_P1 = None
def active_proj():
    """隔离补丁:paths/config 模块常量重指 /tmp 临时树;建激活项目 p1。幂等,返回 p1 目录"""
    global _P1
    if _P1:
        return _P1
    PROJS.mkdir(parents=True, exist_ok=True)
    RUNS.mkdir(parents=True, exist_ok=True)
    project.PROJECTS = server.PROJECTS = PROJS
    project.ACTIVE = server.ACTIVE = PROJS / "active.json"
    project.RUNS = server.RUNS = engine.RUNS = RUNS
    config.CONFIG = TMP / "config.json"
    config.CONFIG.write_text(json.dumps(config.CFG_DEFAULTS, ensure_ascii=False, indent=2), encoding="utf-8")
    config.BH_JSON = engine.BH_JSON = server.BH_JSON = TMP / "bh.json"
    config.CFG["ai_enabled"] = False  # 默认关:agent brief 403 的前置
    d = PROJS / "p1"
    (d / "loot" / "runs").mkdir(parents=True, exist_ok=True)
    (d / "project.json").write_text(json.dumps(
        {"name": "p1", "domain": "lab.local", "dcip": "10.0.0.9", "domains": []}, ensure_ascii=False),
        encoding="utf-8")
    (d / "notes.md").write_text("# 项目 p1\n", encoding="utf-8")
    (PROJS / "active.json").write_text(json.dumps({"name": "p1"}), encoding="utf-8")
    _P1 = d
    return d

_FAKE = None
def fakehome():
    """临时 HOME:tools/bin 软链真实 bin,tools/projects|loot 为临时真目录(脚本按 $HOME/tools 寻址)"""
    global _FAKE
    if _FAKE:
        return _FAKE
    fh = TMP / "fakehome"
    (fh / "tools").mkdir(parents=True)
    os.symlink(BIN, fh / "tools" / "bin")
    (fh / "tools" / "projects").mkdir()
    (fh / "tools" / "loot").mkdir()
    _FAKE = fh
    return fh

# ─── 1. state.py CLI ───────────────────────────────────────────────
@case
def t_state_cli():
    """state.py CLI: tried/phase/cred add/use(含 vhash)/cred get 最新优先/summary"""
    d = TMP / "stateproj"
    d.mkdir()
    s = lambda *a: py(STATE_PY, str(d), *a)  # noqa: E731
    ck(s("tried", "check", "k1").returncode == 1, "未记录的 tried key 应 rc=1")
    ck(s("tried", "mark", "k1", "0").returncode == 0, "tried mark 失败")
    ck(s("tried", "check", "k1").returncode == 0, "tried mark 后 check 应 rc=0")
    ck(s("phase", "check", "P1").returncode == 1, "未完成 phase 应 rc=1")
    ck(s("phase", "mark", "P1", "loot/x.txt").returncode == 0, "phase mark 失败")
    ck(s("phase", "check", "P1").returncode == 0, "phase mark 后 check 应 rc=0")
    r = s("phase", "artifact", "P1")
    ck(r.returncode == 0 and r.stdout.strip() == "loot/x.txt", f"phase artifact 回显错: {r.stdout!r}")
    ck(s("cred", "add", "密码", "LAB\\alice", "LAB", "冒烟").returncode == 0, "cred add 失败")
    ck(s("cred", "add", "密码", "LAB\\alice", "LAB", "冒烟").returncode == 0, "cred add 重复登记应幂等 rc=0")
    ck(s("cred", "add", "密码", "LAB\\bob", "LAB", "冒烟", "SecretOld!").returncode == 0, "cred add(vhash) 失败")
    ck(s("cred", "add", "密码", "LAB\\carol", "LAB", "冒烟").returncode == 0, "cred add carol 失败")
    ck(s("cred", "add", "密码", "LAB\\dave", "LAB", "冒烟", "DaveOld!").returncode == 0, "cred add dave 失败")
    csv_write(d, [
        ["t", "密码", "LAB\\alice", "LAB", "Passw0rd!", "冒烟", "未知", "未用", ""],
        ["t", "密码", "LAB\\carol", "LAB", "CarolOld!", "冒烟", "未知", "未用", ""],
        ["t", "密码", "LAB\\carol", "LAB", "CarolNew!", "冒烟", "未知", "未用", ""],
        ["t", "密码", "LAB\\dave", "LAB", "DaveOld!", "冒烟", "未知", "未用", ""],
        ["t", "密码", "LAB\\dave", "LAB", "DaveNew!", "冒烟", "未知", "未用", ""],
    ])
    r = s("cred", "use", "Passw0rd!")  # 值原文只命中 creds.csv(state 不存值)
    ck(r.returncode == 0 and r.stdout.strip() == "1", f"cred use(csv 值) 命中数错: {r.stdout!r}")
    rows = list(csv.reader(open(d / "creds.csv", encoding="utf-8")))
    ck(rows[1][7] == "已用", "creds.csv 用过没列应翻成 已用")
    r = s("cred", "use", "alice")  # 主体子串命中 state
    ck(r.returncode == 0 and r.stdout.strip() == "1", f"cred use(主体) 命中数错: {r.stdout!r}")
    r = s("cred", "use", "SecretOld!")  # vhash 指纹命中 state(bob 无 csv 行)
    ck(r.returncode == 0 and r.stdout.strip() == "1", f"cred use(vhash) 命中数错: {r.stdout!r}")
    r = s("cred", "get", "carol")  # 无指纹:取 csv 最新一条,不取最旧
    ck(r.returncode == 0 and r.stdout.strip() == "密码\tCarolNew!", f"cred get 应取最新值: {r.stdout!r}")
    r = s("cred", "get", "dave")  # 有指纹:vhash 精确匹配优先于「最新」
    ck(r.returncode == 0 and r.stdout.strip() == "密码\tDaveOld!", f"cred get 应按 vhash 取值: {r.stdout!r}")
    ck(s("cred", "get", "ghost").returncode == 1, "cred get 不存在主体应 rc=1")
    r = s("summary")
    summ = json.loads(r.stdout)
    ck(summ["creds"] == 4, f"summary creds 应 4(重复 add 去重): {summ}")
    ck(summ["creds_used"] == 2, f"summary creds_used 应 2(alice+bob): {summ}")
    ck(summ["tried"] == 1 and summ["tried_ok"] == 1, f"summary tried 计数错: {summ}")
    ck(summ["phases"] == ["P1"], f"summary phases 错: {summ}")

# ─── 2. scope.py CLI ───────────────────────────────────────────────
@case
def t_scope_cli():
    """scope.py CLI: 范围内/外/排除优先/无文件(退出码 0/1/2)"""
    d = TMP / "scopeproj"
    d.mkdir()
    (d / "scope.txt").write_text("# 注释行\n10.0.0.0/24\n!10.0.0.5\ncorp.local\n\n", encoding="utf-8")
    s = lambda *a: py(SCOPE_PY, str(d), *a).returncode  # noqa: E731
    ck(s("10.0.0.9") == 0, "段内 IP 应放行 rc=0")
    ck(s("10.0.0.5") == 1, "! 排除应优先于允许 rc=1")
    ck(s("192.168.1.1") == 1, "段外 IP 应拒 rc=1")
    ck(s("10.0.1.0/24") == 1, "CIDR 目标不 ⊆ 允许段应拒 rc=1")
    ck(s("10.0.0.0/25") == 0, "CIDR 目标 ⊆ 允许段应放行 rc=0")
    ck(s("host.corp.local") == 0, "域名后缀子域应放行 rc=0")
    ck(s("corp.local") == 0, "域名后缀本身应放行 rc=0")
    ck(s("evil.com") == 1, "域外主机名应拒 rc=1")
    empty = TMP / "scopeproj-nofile"
    empty.mkdir()
    ck(py(SCOPE_PY, str(empty), "10.0.0.9").returncode == 2, "无 scope 文件应 rc=2")
    (empty / "scope.txt").write_text("# 只有注释\n", encoding="utf-8")
    ck(py(SCOPE_PY, str(empty), "10.0.0.9").returncode == 2, "空 scope(无有效允许行)应 rc=2")

# ─── 3. 引擎 ───────────────────────────────────────────────────────
@case
def t_engine_chain():
    """引擎合成链: cwd 交接 + checkpoint 双跑 skipped + when 跳过 + for_each 展开"""
    active_proj()
    # 链 A:cwd 交接(步间相对路径传文件)+ when 跳过,单跑
    chain_a = {"id": "reg-chain-a", "name": "回归链A", "params": [], "steps": [
        {"name": "prep", "cmd": "printf 'a\\nb\\n' > list.txt && echo hello > shared.txt"},
        {"name": "read", "cmd": "cat shared.txt"},
        {"name": "cond", "cmd": "echo SHOULD_NOT_RUN", "when": "file_exists:nope.txt"},
        {"name": "loop", "cmd": "echo item {{item}}",
         "for_each": {"from_file": "list.txt", "param": "item"}},
    ]}
    # 链 B:checkpoint 双跑。注意每次 run_chain 都是新 rundir,被 checkpoint 跳过的步不会再产文件,
    # 故 for_each 的 from_file 用绝对路径夹具(root / 绝对路径 = 绝对路径),双跑皆可读
    flist = TMP / "reg-lines.txt"
    flist.write_text("a\nb\n", encoding="utf-8")
    chain_b = {"id": "reg-chain-b", "name": "回归链B", "params": [], "steps": [
        {"name": "once", "cmd": "echo once", "checkpoint": "once"},
        {"name": "loop", "cmd": "echo item {{item}}", "checkpoint": "loop",
         "for_each": {"from_file": str(flist), "param": "item"}},
    ]}
    engine.CHAINS.extend([chain_a, chain_b])
    try:
        r1 = engine.run_chain("reg-chain-a", {})
        s1 = {st["step"]: st for st in r1["steps"]}
        ck(s1["prep"]["rc"] == 0, f"prep 步失败: {s1['prep']}")
        ck(s1["read"]["rc"] == 0 and "hello" in s1["read"]["out"],
           f"cwd 交接失败: read 步读不到 prep 的 shared.txt: {s1['read']}")
        ck(s1["cond"].get("skipped") == 1 and "when" in s1["cond"].get("reason", ""),
           f"when 不满足应标 skipped: {s1['cond']}")
        ck(s1["loop"].get("iterations") == 2 and s1["loop"]["rcs"] == [0, 0],
           f"for_each 应展开 2 行且全 rc=0: {s1['loop']}")
        ck("item a" in s1["loop"]["out"] and "item b" in s1["loop"]["out"],
           f"for_each 行值未代入: {s1['loop']['out']!r}")
        engine.run_chain("reg-chain-b", {})  # 第一跑:建立 checkpoint
        r2 = engine.run_chain("reg-chain-b", {})
        s2 = {st["step"]: st for st in r2["steps"]}
        ck(s2["once"].get("skipped") == 1 and "checkpoint" in s2["once"]["out"],
           f"第二跑 checkpoint 步应 skipped: {s2['once']}")
        ck("checkpoint 已完成" in s2["loop"]["out"] and s2["loop"]["rcs"] == [0, 0],
           f"for_each 行级 checkpoint 第二跑应跳过: {s2['loop']}")
    finally:
        engine.CHAINS.remove(chain_a)
        engine.CHAINS.remove(chain_b)

@case
def t_engine_run():
    """引擎 run(): sudo 缺密码 rc=2 清晰报错;{{cred:}} 水合成功/失败两路"""
    p = active_proj()
    r = engine.run("echo hi", {"id": "reg-sudo", "name": "回归 sudo", "sudo": True})
    ck(r["rc"] == 2 and "sudo" in r["out"] and "root" in r["out"],
       f"sudo 缺密码应 rc=2 且给新手可读报错: {r}")
    r = py(STATE_PY, str(p), "cred", "add", "密码", "LAB\\hydra", "LAB", "回归", "Hydra#Pass9")
    ck(r.returncode == 0, f"水合夹具 cred add 失败: {r.stderr}")
    csv_append(p, ["t", "密码", "LAB\\hydra", "LAB", "Hydra#Pass9", "回归", "未知", "未用", ""])
    t = {"id": "reg-echo", "name": "回归回声", "params": [], "timeout": 30}
    r = engine.run("echo secret={{cred:hydra}}", t)
    ck(r["rc"] == 0 and "Hydra#Pass9" in r["out"],
       f"水合成功路失败(rc/输出): rc={r['rc']} out={r['out'][:200]!r}")
    r = engine.run("echo {{cred:ghost}}", dict(t, id="reg-echo2"))
    ck(r["rc"] == 2 and "凭据不存在" in r["out"] and "ghost" in r["out"],
       f"水合失败路应 rc=2 报缺失主体: {r}")

# ─── 4. fail_hints ─────────────────────────────────────────────────
@case
def t_fail_hints():
    """fail_hints: 11 个签名命中(含 NoneType/BH、No entries、OBJECT_NAME_NOT_FOUND)+ 干净输出无 hint"""
    sigs = [
        ("[-] SMB STATUS_LOGON_FAILURE", "rid-brute"),
        ("STATUS_ACCOUNT_LOCKED_OUT", "锁定"),
        ("STATUS_PASSWORD_EXPIRED", "changepasswd"),
        ("SessionError: KDC_ERR_PREAUTH_FAILED", "KDC_ERR"),
        ("clock skew too great, abort", "对时"),
        ("evil-winrm throws WinRMAuthorizationError", "WinRM"),
        ("hashcat (v6): No hashes loaded", "hashqueue"),
        ("bind failed: Address already in use", "端口被占"),
        ("Traceback: 'NoneType' object has no attribute 'extend'", "BloodHound"),
        ("[*] No entries found in output", "可烤账户"),
        ("error STATUS_OBJECT_NAME_NOT_FOUND while atexec.py read back", "atexec"),
    ]
    for out, kw in sigs:
        h = intel.fail_hints(out)
        ck(h and kw in h, f"签名未命中或建议缺 {kw!r}: out={out!r} hints={h!r}")
    h = intel.fail_hints("STATUS_LOGON_FAILURE 然后 STATUS_ACCESS_DENIED")
    ck(h.count("[建议]") == 2, f"双签名应出两条建议: {h!r}")
    ck(intel.fail_hints("nmap done: 3 hosts up, all modules completed successfully") == "",
       "干净输出不应附任何建议")
    ck(intel.fail_hints("") == "", "空输出不应附任何建议")

# ─── 5. HTTP 矩阵 ──────────────────────────────────────────────────
@case
def t_http_matrix():
    """HTTP 矩阵: / 200、/api/tools 401/200、/bh.json 404、/api/log 穿越 404、配置 roundtrip、agent brief 403、board 形状"""
    active_proj()
    server.set_token("regtok")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), server.H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def req(method, path, tok=False, body=None):
        r = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method,
                                   data=(json.dumps(body).encode() if body is not None else None))
        if tok:
            r.add_header("X-RedOps-Token", "regtok")
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                return resp.status, resp.read().decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "ignore")

    try:
        c, b = req("GET", "/")
        ck(c == 200 and len(b) > 100, f"GET / 应 200 且有页面: {c}")
        c, _ = req("GET", "/api/tools")
        ck(c == 401, f"/api/tools 无 token 应 401: {c}")
        c, b = req("GET", "/api/tools", tok=True)
        ck(c == 200 and isinstance(json.loads(b).get("tools"), list), f"/api/tools 带 token 应 200+注册表: {c}")
        c, _ = req("GET", "/bh.json")
        ck(c == 404, f"静态白名单外 /bh.json 应 404: {c}")
        c, _ = req("GET", "/api/log?p=../../../../../etc/passwd", tok=True)
        ck(c == 404, f"/api/log 目录穿越应 404: {c}")
        c, b = req("POST", "/api/config", tok=True,
                   body={"proxy": "socks5://127.0.0.1:9050", "wordlist": "/tmp/reg-wl.txt"})
        ck(c == 200, f"POST /api/config 应 200: {c} {b[:120]!r}")
        c, b = req("GET", "/api/config", tok=True)
        cfg = json.loads(b)
        ck(c == 200 and cfg["proxy"] == "socks5://127.0.0.1:9050" and cfg["wordlist"] == "/tmp/reg-wl.txt",
           f"配置 roundtrip 读回不符: {cfg}")
        ck("9050" in (TMP / "config.json").read_text(encoding="utf-8"),
           "配置应落盘到临时树 config.json(而非真实配置)")
        c, _ = req("GET", "/api/agent/brief", tok=True)
        ck(c == 403, f"agent brief 默认(AI 关)应 403: {c}")
        c, b = req("GET", "/api/project/board", tok=True)
        bd = json.loads(b)
        ck(c == 200 and bd.get("name") == "p1"
           and all(k in bd for k in ("notes", "creds", "runs", "next", "queue")),
           f"board 形状不符: keys={sorted(bd)}")
    finally:
        srv.shutdown()
        srv.server_close()

# ─── 6. report.sh ──────────────────────────────────────────────────
@case
def t_report_sh():
    """report.sh: 相对路径(~/tools 下 bin/report.sh)与绝对路径调用,项目带 findings → 报告含 findings"""
    fh = fakehome()
    d = fh / "tools" / "projects" / "repproj"
    (d / "loot" / "runs").mkdir(parents=True)
    (d / "project.json").write_text(json.dumps(
        {"name": "repproj", "domain": "lab.local", "dcip": "", "domains": []}), encoding="utf-8")
    (d / "creds.csv").write_text(",".join(CSV_HEADER) + "\n", encoding="utf-8")
    r = py(STATE_PY, str(d), "finding", "add", "SMB 签名未强制", "高", "nxc 输出 signing:False", "10.0.0.5")
    ck(r.returncode == 0, f"findings 夹具登记失败: {r.stderr}")
    env = {"HOME": str(fh)}
    r = bash("bin/report.sh", "repproj", env=env, cwd=fh / "tools")  # 相对路径,从 ~/tools 跑
    ck(r.returncode == 0, f"相对路径调用失败: rc={r.returncode} err={r.stderr[-300:]!r}")
    ck("SMB 签名未强制" in (d / "report.md").read_text(encoding="utf-8"),
       "相对路径生成的 report.md 缺 findings")
    ck((d / "report.html").is_file(), "缺 report.html")
    (d / "report.md").unlink()
    r = bash(REPORT_SH, "repproj", env=env, cwd="/tmp")  # 绝对路径,异目录跑
    ck(r.returncode == 0, f"绝对路径调用失败: rc={r.returncode} err={r.stderr[-300:]!r}")
    ck("SMB 签名未强制" in (d / "report.md").read_text(encoding="utf-8"),
       "绝对路径生成的 report.md 缺 findings")

# ─── 7. crack-sync john 兜底 ───────────────────────────────────────
@case
def t_crack_sync_john():
    """crack-sync: john 兜底路径(stub hashcat 空输出 → stub john 出明文 → 台账+state 登记、队列剔除)"""
    fh = fakehome()
    d = fh / "tools" / "projects" / "crackproj"
    d.mkdir(parents=True)
    h = "$krb5asrep$23$alice@LAB.LOCAL:0123456789abcdef0123456789abcdef"
    (d / "hashqueue.txt").write_text(h + "\n", encoding="utf-8")
    stub = TMP / "stubbin"
    stub.mkdir(exist_ok=True)
    (stub / "hashcat").write_text("#!/bin/sh\n# stub: potfile 无命中,空输出逼出 john 兜底\nexit 0\n")
    (stub / "john").write_text("#!/bin/sh\n# stub john --show: 登录名:明文\necho 'alice@LAB.LOCAL:StubPass!123'\n")
    os.chmod(stub / "hashcat", 0o755)
    os.chmod(stub / "john", 0o755)
    env = {"HOME": str(fh), "PROJ_DIR": str(d), "PATH": f"{stub}:{os.environ['PATH']}"}
    r = bash(CRACK_SYNC, env=env)
    ck(r.returncode == 0, f"crack-sync 失败: rc={r.returncode} err={r.stderr[-300:]!r}")
    ck("1 已破" in r.stdout and "1 新增凭据" in r.stdout, f"汇总行不符: {r.stdout[-300:]!r}")
    csvtxt = (d / "creds.csv").read_text(encoding="utf-8")
    ck("StubPass!123" in csvtxt and "LAB.LOCAL\\alice" in csvtxt, f"台账缺 john 兜底明文: {csvtxt[-200:]!r}")
    ck(h not in (d / "hashqueue.txt").read_text(encoding="utf-8"), "已破哈希应移出队列")

# ─── 8. 隔离证据 ───────────────────────────────────────────────────
@case
def t_isolation():
    """隔离证据: 真实 redops/config.json 与 bh.json 全程未被触碰(哈希比对)"""
    for path, h0 in REAL_HASHES.items():
        ck(_sha(Path(path)) == h0, f"真实文件被改动: {path}")

def main():
    print(f"[*] 回归隔离树: {TMP}(结束自动清理)")
    fails = []
    try:
        for fn in CASES:
            label = fn.__doc__.strip()
            try:
                fn()
            except Exception as e:
                fails.append(label)
                print(f"  [✗] {label}\n      {type(e).__name__}: {e}")
                traceback.print_exc()
            else:
                print(f"  [✓] {label}")
        if fails:
            print(f"\n[✗] 回归失败 {len(fails)} 项:")
            for label in fails:
                print(f"  - {label}")
            return 1
        print("\nREGRESS-ALL-OK")
        return 0
    finally:
        shutil.rmtree(TMP, ignore_errors=True)

if __name__ == "__main__":
    sys.exit(main())
