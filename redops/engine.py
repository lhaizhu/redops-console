"""engine.py — 执行引擎:工具注册表/命令构建/scope 闸门/凭据水合/run/run_chain/后台 waiter/自动收割与回台"""
import hashlib, ipaddress, json, os, re, secrets, shlex, shutil, string, subprocess, sys, time
from pathlib import Path
from threading import Lock, Thread
from .paths import RUNS, WEB
from . import config
from .config import BH_JSON
from .project import (proj_dir, proj_note, _state_dir, _state, _tried_ts, _has_scope,
                      hist, SCOPE_PY, run_roots)
from .harvest import harvest, queue_hashes, RE_TGS_HASH, RE_BH_HVALUE, parse_certipy, parse_persist
from .intel import fail_hints

_REG_LOCK = Lock()  # 热加载互斥:重建索引期间读写不交错

def _load_registry():
    """读盘构建注册表;返回 (reg, tools, chains, verify_tids)。失败抛异常,由调用方处置"""
    reg = json.loads((WEB / "tools.json").read_text(encoding="utf-8"))
    tools = {t["id"]: t for t in reg["tools"]}
    chains = json.loads((WEB / "chains.json").read_text(encoding="utf-8"))["chains"]
    return reg, tools, chains, {tid for tid in tools if "verify" in tid}  # verify_tids:凭据验证类工具(如 nxc-verify)

def _reg_fingerprint():
    """两注册表文件 (mtime_ns, size) 指纹;文件缺失记 None(下次比对必然判变)"""
    def _st(p):
        try:
            s = p.stat()
            return (s.st_mtime_ns, s.st_size)
        except OSError:
            return None
    return (_st(WEB / "tools.json"), _st(WEB / "chains.json"))

try:  # 注册表损坏绝不能是裸 traceback:给清楚的中文错误再退出
    REG, TOOLS, CHAINS, VERIFY_TIDS = _load_registry()
except Exception as e:
    raise SystemExit(f"工具注册表加载失败: {e} — 请检查 redops/web/tools.json 与 chains.json 的 JSON 格式")
_reg_sig = _reg_fingerprint()

def maybe_reload():
    """注册表热加载(线程安全):(mtime,size) 变了才重读+重建索引(含 VERIFY_TIDS 等派生集合);
    读失败保旧表并 warn。返回是否发生重载"""
    global REG, TOOLS, CHAINS, VERIFY_TIDS, _reg_sig
    if _reg_fingerprint() == _reg_sig:
        return False
    with _REG_LOCK:
        sig = _reg_fingerprint()
        if sig == _reg_sig:
            return False
        try:
            reg, tools, chains, verify = _load_registry()
        except Exception as e:
            _reg_sig = sig  # 记下坏指纹避免每个请求反复重读刷 warn;修复后指纹再变自然重载
            print(f"[redops] 注册表热加载失败,保留旧表: {e}", file=sys.stderr)
            return False
        REG, TOOLS, CHAINS, VERIFY_TIDS = reg, tools, chains, verify
        _reg_sig = _reg_fingerprint()
        return True

PLACEHOLDER = re.compile(r"\{\{(\w+)\}\}")
TARGET_KEYS = {"target", "host", "dc", "dcip", "ip", "rhost", "cidr", "net", "range", "网段"}  # scope 闸门关心的目标味参数名(me/lhost=本机回连地址,不算目标,不查)
RE_CRED_HYDRATE = re.compile(r"\{\{cred:([^}]+)\}\}")  # cmd 模板内 {{cred:主体}} 凭据水合占位
SENS_KEYS = {"pass", "password", "pwd", "hash", "nt", "pfx_pass"}  # 凭据味参数名(配合 sens 标记)

# 启动自检:注册命令首词在 PATH 中找不到 → 标 warn(前端黄条提示)
SHELL_KW = {"for", "if", "while", "echo", "export", "cd", "sudo", "bash", "python3", "[", "xargs"}
def startup_checks():
    """注册命令首词在 PATH 中找不到 → 标 warn(前端黄条提示)。__main__ 启动时调用一次"""
    for _t in REG["tools"]:
        _words = shlex.split(_t["cmd"])
        while _words and re.match(r"^[A-Za-z_]\w*=", _words[0]): _words.pop(0)  # 跳过 VAR=val 前缀
        _first = os.path.expanduser(_words[0]) if _words else ""
        _t["warn"] = None if (not _first or _first in SHELL_KW or shutil.which(_first)
                              or ("/" in _first and Path(_first).exists())) else f"找不到二进制 {_words[0]}"


def adopt_orphan_runs(roots=None):
    """启动收养孤儿后台任务:rundir 有 pid 无 rc → 活进程只在 out.log 标注,死进程补 rc=-2;
    每个 runs 根汇总一行进项目 notes.md(无项目记根旁 notes.md)。全程 fail-safe,绝不阻断启动"""
    try:
        for root in (roots if roots is not None else run_roots()):
            try:
                adopted = 0
                for rundir in sorted(root.iterdir()):
                    try:
                        pidf, rcf = rundir / "pid", rundir / "rc"
                        if not rundir.is_dir() or not pidf.exists() or rcf.exists():
                            continue
                        pid = int(pidf.read_text().strip())
                        with open(rundir / "out.log", "a", encoding="utf-8") as f:
                            if Path(f"/proc/{pid}").exists():
                                f.write(f"\n[!] 服务重启,任务仍在运行(pid {pid}),可用 /api/stop 停止\n")
                            else:
                                rcf.write_text("-2")
                                f.write("\n[!] 服务重启前进程已退出,退出码未知(rc=-2)\n")
                        adopted += 1
                    except Exception:
                        pass
                if adopted:
                    proj = root.parent.parent  # 项目根 <name>/loot/runs → <name>;全局根则落在 ROOT(无 notes.md)
                    msg = f"🧹 服务重启收养 {adopted} 个孤儿后台任务"
                    if (proj / "notes.md").exists():
                        proj_note(proj, msg)
                    else:
                        with open(root.parent / "notes.md", "a", encoding="utf-8") as f:
                            f.write(f"- {time.strftime('%m-%d %H:%M')} {msg}\n")
            except Exception:
                pass
    except Exception:
        pass
def _set_timeout_mult(out):
    """netcheck 输出 export NET_TIMEOUT_MULT=<float> → 全局超时倍数(clamp 0.5–8)"""
    m = re.search(r"NET_TIMEOUT_MULT=([0-9]+(?:\.[0-9]+)?)", out or "")
    if m: config.set_timeout_mult(min(8.0, max(0.5, float(m.group(1)))))

def _timeout(base):
    """工具/链步骤超时 × 网络倍数(int,下限 30s)"""
    return max(30, int(base * config.TIMEOUT_MULT))

def _cred_use(projdir, param_specs, params):
    """执行成功后:凭据味参数原值(未 quote,≥6 字符)回写 cred use → state.used + creds.csv 已用"""
    for p in param_specs or []:
        if not (p.get("sens") or p["k"] in SENS_KEYS): continue
        v = str((params or {}).get(p["k"], "")).strip()
        if len(v) >= 6:
            _state(projdir, "cred", "use", v)

def _scope_validate(text):
    """逐行校验 scope 文本;返回错误消息或 None。规则:去 ! 前缀后须为 IP/CIDR 或域名"""
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"): continue
        v = s.lstrip("!")
        try:
            ipaddress.ip_network(v, strict=False); continue
        except ValueError: pass
        if re.fullmatch(r"\.?[a-z0-9.-]+", v, re.I): continue
        return f"scope 第{i}行无效: {s}"
    return None

def _scope_gate(projdir, params, readonly=False):
    """scope 闸门(仅项目激活时;全局模式不强制)。放行返回 None,拒绝返回错误 dict(403)。
    fail-closed:scope.py 超时/崩溃/异常退出码一律拒绝。"""
    if not projdir:
        return None
    cands = []
    for k, v in (params or {}).items():
        if str(k).lower() in TARGET_KEYS:
            v = str(v).strip()
            if v and v not in cands:
                cands.append(v)
    no_scope = False
    for v in cands:
        try:
            rc = subprocess.run([sys.executable, str(SCOPE_PY), str(projdir), v],
                                capture_output=True, timeout=5).returncode
        except Exception:
            return {"error": "scope 校验异常(超时/崩溃),已拒绝执行"}
        if rc == 1:
            return {"error": "目标超出 scope.txt"}
        if rc == 2:
            no_scope = True      # 无 scope 文件或为空
        elif rc != 0:
            return {"error": "scope 校验异常,已拒绝执行"}
    if not readonly and (no_scope or (not cands and not _has_scope(projdir))):
        return {"error": "无 scope.txt,仅允许只读工具(readonly)"}
    return None

def _when_ok(when, prev_rc, root):
    """链步骤 when 条件:file_exists:<相对链根路径> / rc:<N>(上一执行步 rc;首步恒真)。未知形态不阻断。"""
    if when.startswith("file_exists:"):
        return (root / when[len("file_exists:"):]).exists()
    if when.startswith("rc:"):
        try:
            want = int(when[3:])
        except ValueError:
            return True
        return (prev_rc if prev_rc is not None else 0) == want
    return True

def _hydrate_creds(cmd, sdir):
    """{{cred:主体}} 水合:state cred get 取值原文 shlex.quote 代入。
    返回 (cmd, 缺失主体或 None);state 异常(rc 非 0)按缺失处理。"""
    miss = []
    def rep(m):
        subj = m.group(1).strip()
        rc, out = _state(sdir, "cred", "get", subj)
        val = out.split("\t", 1)[1] if rc == 0 and "\t" in out else ""
        if val:
            return shlex.quote(val)
        miss.append(subj)
        return m.group(0)
    return RE_CRED_HYDRATE.sub(rep, cmd), (miss[0] if miss else None)

def build_values(param_specs, params):
    """校验必填并 shlex.quote;返回 (values, missing) — run_chain/build_cmd 共用"""
    values, missing = {}, []
    for p in param_specs:
        v = str(params.get(p["k"], p.get("def", ""))).strip()
        if not v and p.get("req"): missing.append(p["k"])
        values[p["k"]] = shlex.quote(v) if v else ""
    return values, missing

def _mk_rundir(parent, name):
    """建运行目录;同名(同秒)冲突时追加毫秒后缀"""
    d = parent / name
    try: d.mkdir(parents=True)
    except FileExistsError:
        d = parent / f"{name}-{int(time.time() * 1000) % 1000:03d}"
        d.mkdir(parents=True)
    return d

def run_chain(cid, params, sudo_pass="", use_proxy=False):
    """顺序执行链;失败即停(optional 除外);产物统一 chain-<id>-<ts>/
    (所有步骤共享链根 cwd 以便相对路径跨步传文件;步日志写根下 step<N>-<name>.log);
    param 含 auto:pass 且留空 → 服务端生成随机密码透传后续步骤"""
    chain = next((c for c in CHAINS if c["id"] == cid), None)
    if not chain: raise ValueError(f"链不存在: {cid}")
    params, generated = dict(params or {}), {}
    for p in chain.get("params", []):
        if p.get("auto") == "pass" and not str(params.get(p["k"], p.get("def", ""))).strip():
            params[p["k"]] = "".join(secrets.choice(string.ascii_letters + string.digits + "!@#%") for _ in range(16))
            generated[p["k"]] = params[p["k"]]
    values, missing = build_values(chain.get("params", []), params)
    if missing: raise ValueError("缺少必填参数: " + ", ".join(missing))
    if any(s.get("sudo") for s in chain.get("steps", [])) and not sudo_pass:
        raise ValueError("链含 sudo 步骤 → 执行台填写 sudo 密码后再跑")
    proj = proj_dir(); ts = time.strftime("%H%M%S"); sdir = _state_dir(proj)
    root = _mk_rundir((proj / "loot" / "runs") if proj else RUNS, f"chain-{cid}-{ts}")
    results = []
    hist({"ts": time.strftime("%m-%d %H:%M:%S"), "id": f"chain:{cid}", "name": f"🔗 {chain['name']}",
          "cmd": chain["id"], "params": dict(params or {}),  # 历史原文存储(用户要求不脱敏)
          "proj": proj.name if proj else ""}, (root.parent if proj else RUNS))
    if proj: proj_note(proj, f"🔗 启动链 **{chain['name']}** → `{root.name}/`")
    prev_rc = None  # 上一执行步 rc(when:"rc:N" 判定,首步视为 0)
    for i, step in enumerate(chain.get("steps", []), 1):
        slog = root / f"step{i}-{step.get('name','x')[:12]}.log"
        w = step.get("when")
        if w and not _when_ok(w, prev_rc, root):  # 条件步:不满足标 skipped 继续,不算失败
            results.append({"step": step["name"], "skipped": 1, "reason": "when 不满足",
                            "rc": 0, "out": "", "dir": str(root)})
            continue
        fe = step.get("for_each")
        if fe:  # 逐行展开:每行执行一次,params[fe.param]=行值;checkpoint 键带行值(重跑跳过已完成行)
            try:
                lines = [l.strip() for l in (root / fe["from_file"]).read_text(encoding="utf-8").splitlines()
                         if l.strip() and not l.strip().startswith("#")]
            except OSError as e:
                results.append({"step": step["name"], "rc": 2, "out": f"for_each 读文件失败: {e}", "dir": str(root)})
                prev_rc = 2
                if not step.get("optional"): break
                continue
            if len(lines) > 200:
                results.append({"step": step["name"], "rc": 2,
                                "out": f"for_each 超上限: {len(lines)} 行 > 200,已拒绝", "dir": str(root)})
                prev_rc = 2
                if not step.get("optional"): break
                continue
            rcs, outs, raws = [], [], []  # raws: 无前缀原始输出(收割/哈希入队用;outs 的 [行] 前缀会让 ^ 锚定正则失配)
            for line in lines:
                ivals = {**values, fe["param"]: shlex.quote(line)}
                cmd = PLACEHOLDER.sub(lambda m: ivals.get(m.group(1), ""), step["cmd"])
                cmd, miss = _hydrate_creds(cmd, sdir)
                if miss:
                    rcs.append(2); outs.append(f"凭据不存在: {miss}")
                    break
                ck = f"chain:{cid}:{step['checkpoint']}:{line}" if step.get("checkpoint") else None
                if ck and _state(sdir, "tried", "check", ck)[0] == 0:
                    rcs.append(0); outs.append(f"[{line}] (checkpoint 已完成,跳过)")
                    continue
                try:
                    r = subprocess.run(["bash", "-c", wrap_proxy(cmd, use_proxy, step.get("sudo"))],
                                       capture_output=True, text=True,
                                       input=(sudo_pass + "\n") if step.get("sudo") and sudo_pass else "",
                                       timeout=_timeout(step.get("timeout", 300)), cwd=root,
                                       env={**os.environ, **({"PROJ_DIR": str(proj)} if proj else {})})
                    rcs.append(r.returncode)
                    raw = (r.stdout + ("\n[stderr]\n" + r.stderr if r.stderr else "")).strip()
                    raws.append(raw)
                    outs.append(f"[{line}] " + raw)
                    if ck: _state(sdir, "tried", "mark", ck, r.returncode)
                except subprocess.TimeoutExpired:
                    rcs.append(-1); outs.append(f"[{line}] 超时")
                    if ck: _state(sdir, "tried", "mark", ck, -1)
            rc = 0 if rcs and all(x == 0 for x in rcs) else next((x for x in rcs if x != 0), 0)  # 全 0 才算成
            out = "\n".join(outs)[-8000:]
            slog.write_text(out, encoding="utf-8")
            if rc == 0 and proj:
                raw_all = "\n".join(raws)
                newq = queue_hashes(proj, RE_TGS_HASH.findall(raw_all))
                if newq:
                    out += f"\n[+] {len(newq)} 条哈希入破解队列 hashqueue.txt"
                stid = step.get("harvest", step.get("name", ""))  # 收割归属:step.harvest 指定,否则按步骤名
                h = harvest({"id": stid}, raw_all, proj, root.name)
                if h: out += "\n" + h
                _auto_findings(proj, stid, out, params, f"{root.name}/step{i}", h)
                proj_note(proj, f"✅ 链·{step['name']} for_each {len(rcs)} 行全部成功")
            results.append({"step": step["name"], "rc": rc, "out": out,
                            "iterations": len(rcs), "rcs": rcs, "dir": str(root)})
            prev_rc = rc
            if rc != 0 and not step.get("optional"): break
            continue
        cmd = PLACEHOLDER.sub(lambda m: values.get(m.group(1), ""), step["cmd"])
        cmd, miss = _hydrate_creds(cmd, sdir)
        if miss:  # 凭据水合失败:该步立即失败
            results.append({"step": step["name"], "rc": 2, "out": f"凭据不存在: {miss}", "dir": str(root)})
            prev_rc = 2
            if not step.get("optional"): break
            continue
        full = wrap_proxy(cmd, use_proxy, step.get("sudo"))
        ck_key = f"chain:{cid}:{step['checkpoint']}" if step.get("checkpoint") else None
        if ck_key and _state(sdir, "tried", "check", ck_key)[0] == 0:
            results.append({"step": step["name"], "name": step["checkpoint"], "skipped": 1,
                            "rc": 0, "out": "(checkpoint 已完成,跳过)", "dir": str(root)})
            continue
        try:
            r = subprocess.run(["bash", "-c", full], capture_output=True, text=True,
                               input=(sudo_pass + "\n") if step.get("sudo") and sudo_pass else "",
                               timeout=_timeout(step.get("timeout", 300)), cwd=root,
                               env={**os.environ, **({"PROJ_DIR": str(proj)} if proj else {})})
            raw_full = r.stdout + ("\n[stderr]\n" + r.stderr if r.stderr else "")
            out = raw_full[-8000:]   # 展示截断;收割/入队用 raw_full(哈希行可能在前段被截掉)
            slog.write_text(raw_full, encoding="utf-8")
            ok = r.returncode == 0
            if ck_key: _state(sdir, "tried", "mark", ck_key, r.returncode)
            if ok: _cred_use(sdir, chain.get("params", []), params)
            if ok and proj:
                newq = queue_hashes(proj, RE_TGS_HASH.findall(raw_full))
                if newq:
                    out += f"\n[+] {len(newq)} 条哈希入破解队列 hashqueue.txt"
                stid = step.get("harvest", step.get("name", ""))  # 收割归属:step.harvest 指定,否则按步骤名
                h = harvest({"id": stid}, raw_full, proj, root.name)
                if h: out += "\n" + h
                _auto_findings(proj, stid, out, params, f"{root.name}/step{i}", h)
                proj_note(proj, f"{'✅' if ok else '⚠️'} 链·{step['name']} rc={r.returncode}")
            results.append({"step": step["name"], "rc": r.returncode, "out": out, "dir": str(root)})
            prev_rc = r.returncode
            if r.returncode != 0 and not step.get("optional"):
                break
        except subprocess.TimeoutExpired as te:
            partial = ((te.stdout or "") + (te.stderr or ""))[-4000:] if isinstance(te.stdout or te.stderr, str) else ""
            results.append({"step": step["name"], "rc": -1, "out": "超时\n" + partial, "dir": str(root)})
            prev_rc = -1
            if ck_key: _state(sdir, "tried", "mark", ck_key, -1)
            if not step.get("optional"): break
    return {"chain": chain["name"], "dir": str(root), "steps": results, "generated": generated}

def build_cmd(tid, params):
    t = TOOLS[tid]
    values, missing = build_values(t.get("params", []), params)
    if missing: raise ValueError("缺少必填参数: " + ", ".join(missing))
    return PLACEHOLDER.sub(lambda m: values.get(m.group(1), ""), t["cmd"])
def wrap_proxy(cmd, use_proxy, sudo):
    inner = ("proxychains4 -q " + cmd) if use_proxy else cmd
    return ("sudo -S -p '' " + inner) if sudo else inner

def bh_auto_upload(rundir):
    cfgp = BH_JSON
    if not cfgp.exists(): return "(BH 自动上传:未配置 redops/bh.json,请手动导入)"
    try:
        import urllib.request
        cfg = json.loads(cfgp.read_text())
        zips = sorted(Path(rundir).glob("*bloodhound*.zip"), key=lambda p: p.stat().st_mtime)
        if not zips: return "(BH 自动上传:未找到采集 zip)"
        data = json.dumps({"login_method": "secret", "username": cfg["user"], "secret": cfg["pass"]}).encode()
        req = urllib.request.Request(cfg["url"].rstrip("/") + "/api/v2/login", data=data,
                                     headers={"Content-Type": "application/json"}, method="POST")
        token = json.loads(urllib.request.urlopen(req, timeout=15).read())["data"]["session_token"]
        z = zips[-1]
        # BH CE v2 文件摄取三步: start 拿任务 id → 传原始字节 → end 触发入库
        auth = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        req = urllib.request.Request(cfg["url"].rstrip("/") + "/api/v2/file-upload/start",
                                     data=b"{}", headers=auth, method="POST")
        job = json.loads(urllib.request.urlopen(req, timeout=15).read())
        fid = job["data"]["id"]
        req = urllib.request.Request(f"{cfg['url'].rstrip('/')}/api/v2/file-upload/{fid}",
                                     data=z.read_bytes(), method="POST",
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/zip"})
        urllib.request.urlopen(req, timeout=120).read()
        req = urllib.request.Request(f"{cfg['url'].rstrip('/')}/api/v2/file-upload/{fid}/end",
                                     data=b"{}", headers=auth, method="POST")
        urllib.request.urlopen(req, timeout=60).read()
        return f"(BH 自动上传成功: {z.name})"
    except Exception as e:
        return f"(BH 自动上传失败: {type(e).__name__}: {e} — 先 ~/tools/bin/console.sh up 起依赖,或手动导入 zip)"

def _auto_findings(proj, tid, out, params, evidence, h=""):
    """成功运行(rc==0)的战果自动登记,全程 fail-safe:
    输出含 (Pwn3d!) 且有目标味参数值 → host owned + 高 finding;
    secretsdump/dcsync 系收割到 ≥1 条新凭据(harvest 摘要含 🔑)→ 高 finding(不带主机)。"""
    if not proj:
        return
    try:
        if "(Pwn3d!)" in (out or ""):
            ip = next((str(v).strip() for k, v in (params or {}).items()
                       if str(k).lower() in TARGET_KEYS and str(v).strip()), "")
            if ip:
                _state(proj, "host", "owned", ip)
                _state(proj, "finding", "add", "主机拿下(本地管理员)", "高", evidence, ip)
        if tid in ("secretsdump", "dcsync", "adfs-dcsync") and "🔑 收割" in (h or ""):
            _state(proj, "finding", "add", f"凭据收割: {tid}", "高", evidence)
        if tid == "certipy-find":
            escs, ca = parse_certipy(out)
            for e in escs:
                _state(proj, "finding", "add", f"ADCS {e} 可利用模板", "高", evidence)
            if ca:
                proj_note(proj, f"ADCS CA 名称: {ca}")
        if tid == "bh-diff":
            m = RE_BH_HVALUE.search(out or "")
            if m and int(m.group(1)) > 0:
                _state(proj, "finding", "add", f"BloodHound 环境变化: {m.group(1)} 条高价值", "中", evidence)
        if tid == "persist-audit":
            p = parse_persist(out or "")
            if p:
                if p["shadow"] > 0:
                    _state(proj, "finding", "add", f"检测到影子凭据残留 {p['shadow']} 条", "中", evidence)
                if p["unconstrained"] > 0:
                    _state(proj, "finding", "add", f"存在非约束委派主机 {p['unconstrained']} 台", "中", evidence)
    except Exception:
        pass

def _auto_crack_sync(proj, log):
    """hashcat-queue 后台跑完(rc=0)→ 自动 crack-sync 回收 potfile 入台账;全程 fail-safe,失败只在日志留痕"""
    try:
        r = subprocess.run(["crack-sync.sh"], capture_output=True, text=True, timeout=60)  # PATH 解析(~/tools/bin 已前置);项目经 active.json 自解析
        summ = next((l.split(":", 1)[1].strip() for l in r.stdout.splitlines()
                     if l.strip().startswith("汇总:")), f"rc={r.returncode}")
        msg = f"[+] 自动 crack-sync: {summ}"
        with open(log, "a", encoding="utf-8") as f:
            f.write("\n" + msg + "\n")
        proj_note(proj, msg)
    except Exception as e:
        try:
            with open(log, "a", encoding="utf-8") as f:
                f.write(f"\n[!] 自动 crack-sync 未执行: {type(e).__name__}: {e}\n")
        except OSError:
            pass

def run(cmd, t, sudo_pass="", use_proxy=False, params=None):
    ts = time.strftime("%H%M%S")
    proj = proj_dir(); sdir = _state_dir(proj)
    cmd, miss = _hydrate_creds(cmd, sdir)
    if miss:  # 凭据水合失败:不执行,直接报错(不入史)
        return {"bg": 0, "rc": 2, "out": f"凭据不存在: {miss}", "cmd": "", "dir": "", "tried_before": None}
    if t.get("sudo") and not sudo_pass:  # sudo 工具缺密码:直接给新手可读错误,不放行到 sudo 报错
        return {"bg": 0, "rc": 2, "out": "该工具需要 root 权限 → 执行台勾选 sudo 并填密码", "cmd": "", "dir": "", "tried_before": None}
    runs_root = (proj / "loot" / "runs") if proj else RUNS
    rundir = _mk_rundir(runs_root, f"{t['id']}-{ts}")
    full = wrap_proxy(cmd, use_proxy, t.get("sudo"))
    log = rundir / "out.log"
    entry = {"ts": time.strftime("%m-%d %H:%M:%S"), "id": t["id"], "name": t["name"],
             "cmd": full, "params": dict(params or {}),  # 历史原文存储(用户要求不脱敏)
             "proj": proj.name if proj else ""}
    env_extra = {"PROJ_DIR": str(proj)} if proj else {}
    def note(line):
        if proj: proj_note(proj, line)
    if t.get("bg"):
        pass_stdin = bool(t.get("sudo") and sudo_pass)  # sudo 密码走 stdin 管道,不进 argv/进程列表
        with open(log, "w") as f:
            env = {**os.environ, "PYTHONUNBUFFERED": "1", **env_extra}
            # stdin 恒为 PIPE 且 waiter 前不关闭:DEVNULL/EOF 会让交互式长任务(ntlmrelayx)读到底直接自杀
            # stdbuf 包 bash 本体(而非把 stdbuf 拼进命令串):VAR= 赋值开头的命令不会再被当成可执行名
            proc = subprocess.Popen(["stdbuf", "-oL", "-eL", "bash", "-c", full], stdout=f, stderr=subprocess.STDOUT,
                                    stdin=subprocess.PIPE, start_new_session=True, cwd=rundir, env=env)
        if pass_stdin:
            try: proc.stdin.write((sudo_pass + "\n").encode()); proc.stdin.flush()
            except (BrokenPipeError, OSError): pass
        (rundir / "pid").write_text(str(proc.pid))
        entry.update(bg=1); hist(entry, runs_root)
        def _waiter():  # 守护线程等后台进程退出:写 rc 文件 + 追加 done 史条 + 收割日志(responder NetNTLMv2 等)
            rc = proc.wait()
            try: proc.stdin.close()  # 进程已退,补关管道
            except (BrokenPipeError, OSError): pass
            try: (rundir / "rc").write_text(str(rc))
            except OSError: return
            hist({**entry, "ts": time.strftime("%m-%d %H:%M:%S"), "rc": rc, "done": 1}, runs_root)
            if proj:
                o = log.read_text(errors="ignore")
                h = harvest(t, o, proj, rundir.name)
                if rc == 0: _auto_findings(proj, t["id"], o, params, rundir.name, h)
                if rc == 0 and t["id"] == "netcheck": _set_timeout_mult(o)  # 后台形态同样生效
                note(f"{'✅' if rc == 0 else '⚠️'} 后台结束 **{t['name']}** rc={rc} → `{rundir.name}/`" + h)
                if rc == 0 and t["id"] == "hashcat-queue": _auto_crack_sync(proj, log)  # 破解队列跑完 → 自动回台账闭环
        Thread(target=_waiter, daemon=True).start()  # daemon:服务退出不被等待线程拖住
        note(f"🟡 后台启动 **{t['name']}** pid={proc.pid} → `{rundir.name}/`")
        return {"bg": 1, "log": str(log), "cmd": full, "dir": str(rundir), "pid": proc.pid}

    tkey = f"tool:{t['id']}:{hashlib.sha1(full.encode()).hexdigest()[:10]}"  # tried 咨询:同工具同命令不重试提醒
    tried_before = _tried_ts(sdir, tkey) if _state(sdir, "tried", "check", tkey)[0] == 0 else None

    try:
        r = subprocess.run(["bash", "-c", full], capture_output=True, text=True,
                           input=(sudo_pass + "\n") if t.get("sudo") and sudo_pass else "",
                           timeout=_timeout(t.get("timeout", 120)), cwd=rundir, env={**os.environ, **env_extra})
        raw_full = r.stdout + ("\n[stderr]\n" + r.stderr if r.stderr else "")
        out = raw_full[-20000:]  # 展示截断;收割用 raw_full(防大输出截掉凭据/哈希行)
        if r.returncode == 0 and t["id"] == "bh-collect":
            out += "\n" + bh_auto_upload(rundir)
        out += fail_hints(out)
        log.write_text(out, encoding="utf-8")
        entry.update(bg=0, rc=r.returncode); hist(entry, runs_root)
        summary = next((l.strip() for l in out.splitlines() if l.strip() and not l.startswith("[")), "")[:80]
        h = harvest(t, raw_full, proj, rundir.name) if r.returncode == 0 else ""
        if r.returncode == 0:
            if t["id"] == "netcheck": _set_timeout_mult(out)  # 实测网络倍数 → 后续全部工具/链步骤超时
            _auto_findings(proj, t["id"], out, params, rundir.name, h)
            _state(sdir, "tried", "mark", tkey, 0)
            _cred_use(sdir, t.get("params", []), params)
            if t["id"] in VERIFY_TIDS and "[+]" in out:  # nxc-verify 命中 → valid_for 记录目标
                _state(sdir, "cred", "verify",
                       str((params or {}).get("user", "")).strip(), str((params or {}).get("target", "")).strip())
        return {"bg": 0, "rc": r.returncode, "out": out, "cmd": full, "dir": str(rundir), "tried_before": tried_before}
    except subprocess.TimeoutExpired:
        entry.update(bg=0, rc=-1); hist(entry, runs_root)
        note(f"⏱ **{t['name']}** 超时强杀 → `{rundir.name}/`")
        return {"bg": 0, "rc": -1, "out": f"[超时 {_timeout(t.get('timeout',120))}s 强杀]", "cmd": full, "dir": str(rundir), "tried_before": tried_before}
