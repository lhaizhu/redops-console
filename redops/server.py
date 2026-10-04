"""server.py — HTTP 层:Handler 类(全部 /api/* 路由 + token 认证 + 静态白名单)
  GET  /              静态(redops/web 目录,仅 index.html)
  GET  /api/tools     工具注册表(启动时校验二进制,缺失标 warn)
  GET  /api/history   最近 60 条执行历史(原文)
  GET  /api/log?p=    长任务日志尾部(限 runs 目录)
  POST /api/run       {id, params, sudo_pass, proxy} → 执行;proxy=1 套 proxychains4
安全:仅注册表内命令可执行;参数 shlex.quote;超时强杀;目录穿越防护;/api/* 需 X-RedOps-Token 头"""
import hmac, json, os, re, signal, tempfile, time
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from . import config
from .config import CFG, CFG_DEFAULTS, BH_JSON, cfg_save
from .paths import RUNS, WEB, PROJECTS, ACTIVE
from .project import (proj_dir, proj_create, proj_add_domain, proj_note,
                      _state, hist_entries, run_roots, _atomic_write_text)
from . import engine
from .engine import (TARGET_KEYS, run, run_chain, build_cmd,
                     _scope_gate, _scope_validate)  # REG/TOOLS/CHAINS 走 engine.* 动态取(支持热加载)
from .intel import board_data, brief_data
from .ai import call_llm, advise_prompt

TOKEN = ""  # __main__ 启动时经 set_token 注入(每次启动随机);/api/* 需带 X-RedOps-Token 头

def set_token(tok):
    global TOKEN
    TOKEN = tok

_INDEX = {"key": None, "body": b"", "lm": ""}  # index.html 字节缓存,按 (mtime,size) 失效

MAX_BODY = 1 << 20  # POST 请求体上限 1MB
class BodyTooLarge(Exception): pass

class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        b = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def _read_json(self):
        n = int(self.headers.get("Content-Length", 0))
        if n > MAX_BODY:  # 请求体上限 1MB,超限拒收(防内存撑爆)
            raise BodyTooLarge(f"请求体过大: {n} > 1MB")
        return json.loads(self.rfile.read(n))

    def _auth(self):
        """校验 /api/* 请求的 X-RedOps-Token 头(常量时间比较);失败回 401"""
        tok = self.headers.get("X-RedOps-Token", "").encode("utf-8", "ignore")  # 先编码:非 ASCII 头值不致 compare_digest TypeError
        if hmac.compare_digest(tok, TOKEN.encode("utf-8")):
            return True
        self._send(401, '{"error":"unauthorized"}')
        return False

    def _serve_index(self):
        # 威胁模型:仅绑 127.0.0.1;GET / 不设鉴权且把 token 注入页面 —— token 防的是
        # CSRF/误暴露,不是本机其他用户(同机任意进程都能 GET / 取 token 获得完整 API/命令执行)。
        # 信任边界 = 本机用户;切勿把端口转发/反代到非回环地址。
        try: st = (WEB / "index.html").stat()
        except OSError: return self._send(404, "not found", "text/plain")
        key = (st.st_mtime, st.st_size)
        if _INDEX["key"] != key:
            _INDEX.update(key=key,
                          body=(WEB / "index.html").read_bytes().replace(b"__TOKEN__", TOKEN.encode()),
                          lm=formatdate(st.st_mtime, usegmt=True))
        if self.headers.get("If-Modified-Since") == _INDEX["lm"]:
            self.send_response(304); self.send_header("Last-Modified", _INDEX["lm"])
            self.send_header("Content-Length", "0"); self.end_headers(); return
        b = _INDEX["body"]
        self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b))); self.send_header("Last-Modified", _INDEX["lm"])
        self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path.startswith("/api/") and not self._auth(): return
        if u.path == "/api/chains":
            engine.maybe_reload()
            return self._send(200, json.dumps({"chains": engine.CHAINS}, ensure_ascii=False))
        if u.path == "/api/tools":
            engine.maybe_reload()
            return self._send(200, json.dumps({**engine.REG, "net_timeout_mult": config.TIMEOUT_MULT}, ensure_ascii=False))
        if u.path == "/api/project":
            p = proj_dir()
            proj = None
            if p: proj = json.loads((p / "project.json").read_text(encoding="utf-8"))
            return self._send(200, json.dumps({"project": proj, "projects": sorted(d.name for d in PROJECTS.iterdir() if d.is_dir())}, ensure_ascii=False))
        if u.path == "/api/project/state":
            p = proj_dir()
            if not p: return self._send(404, json.dumps({"error": "无激活项目"}, ensure_ascii=False))
            def _sj(*a):  # state.py 子命令 → JSON;故障 fail-safe 回空
                rc, s = _state(p, *a)
                if rc != 0: return None
                try: return json.loads(s)
                except ValueError: return None
            return self._send(200, json.dumps({"summary": _sj("summary") or {},
                                               "findings": _sj("finding", "list") or [],
                                               "hosts": _sj("host", "list") or {}}, ensure_ascii=False))
        if u.path == "/api/project/board":
            p = proj_dir()
            if not p: return self._send(200, json.dumps({"error": "无激活项目(顶部下拉选择)"}, ensure_ascii=False))
            return self._send(200, json.dumps(board_data(p), ensure_ascii=False))
        if u.path == "/api/config":
            # 配置读取:bh pass 脱敏;scope 为激活项目 scope.txt 原文
            bh = {}
            try: bh = json.loads(BH_JSON.read_text(encoding="utf-8"))
            except Exception: pass
            p = proj_dir()
            scope = None
            if p:
                try:
                    sp = p / "scope.txt"
                    if sp.exists(): scope = sp.read_text(encoding="utf-8", errors="ignore")
                except OSError: pass
            ai = dict(CFG.get("ai") or CFG_DEFAULTS["ai"])
            ai["api_key"] = "***" if ai.get("api_key") else ""  # key 永不明文外发
            return self._send(200, json.dumps({
                "ai_enabled": bool(CFG.get("ai_enabled")), "proxy": CFG.get("proxy", ""),
                "wordlist": CFG.get("wordlist", ""), "ai": ai,
                "bh": {"url": bh.get("url", ""), "user": bh.get("user", ""),
                       "pass": "***" if bh.get("pass") else ""},
                "scope": scope, "project": p.name if p else None}, ensure_ascii=False))
        if u.path == "/api/agent/brief":
            # LLM 操作员速览:项目+状态+战果+最近失败,全 fail-safe;凭据只出元信息,值/vhash 绝不外发
            if not CFG.get("ai_enabled"):
                return self._send(403, json.dumps({"error": "AI 接入已禁用(配置页开启后可用)"}, ensure_ascii=False))
            p = proj_dir()
            if not p: return self._send(404, json.dumps({"error": "无激活项目"}, ensure_ascii=False))
            return self._send(200, json.dumps(brief_data(p, engine.REG["tools"], config.TIMEOUT_MULT), ensure_ascii=False))
        if u.path == "/api/history":
            root = (proj_dir() / "loot" / "runs") if proj_dir() else RUNS
            h = hist_entries(root / "history.jsonl", 60)
            return self._send(200, json.dumps({"hist": h[::-1]}, ensure_ascii=False))
        if u.path == "/api/log":
            p = parse_qs(u.query).get("p", [""])[0]
            f = (RUNS / p).resolve()  # p 为绝对路径时 RUNS / p == p;根白名单是唯一防线
            if not any(f.is_relative_to(r) for r in run_roots()) or not f.is_file():
                return self._send(404, '{"error":"log not found"}')
            with open(f, "rb") as fh:  # seek 读尾:后台日志可长到数 GB,绝不整文件入内存
                fh.seek(0, 2); size = fh.tell()
                fh.seek(max(0, size - 20000))
                tail = fh.read().decode("utf-8", "ignore")
            return self._send(200, json.dumps({"out": tail}, ensure_ascii=False))

        # 静态资源白名单:仅 index.html(bh.json/tools.json/*.py 一律 404)
        if u.path in ("/", "/index.html"):
            return self._serve_index()
        return self._send(404, "not found", "text/plain")


    def do_POST(self):
        path = urlparse(self.path).path
        if path.startswith("/api/") and not self._auth(): return
        _cl = self.headers.get("Content-Length", "")
        if _cl.isdigit() and int(_cl) > MAX_BODY:  # 超限早拒,不进分支(_read_json 兜底同样拒)
            return self._send(413, json.dumps({"error": "请求体过大(>1MB),已拒绝"}, ensure_ascii=False))
        if path == "/api/project/domain":
            try:
                body = self._read_json()
                pname = body.get("proj") or (json.loads(ACTIVE.read_text()).get("name") if ACTIVE.exists() else "")
                dom = str(body.get("domain") or "").strip()
                if not dom:
                    return self._send(400, json.dumps({"error": "domain 不能为空"}, ensure_ascii=False))
                proj = proj_add_domain(pname, dom, body.get("dcip", ""), body.get("dcfqdn", ""))
                return self._send(200, json.dumps({"ok": 1, "domains": proj["domains"]}, ensure_ascii=False))
            except ValueError as e:
                return self._send(400, json.dumps({"error": str(e)}, ensure_ascii=False))
            except Exception as e:
                return self._send(500, json.dumps({"error": str(e)}, ensure_ascii=False))
        if path in ("/api/project/create", "/api/project/select"):
            try:
                body = self._read_json()
                if path.endswith("create"):
                    proj = proj_create(body["name"], **{k: body.get(k, "") for k in ("domain", "dcip", "dcfqdn", "me")})
                    return self._send(200, json.dumps({"ok": 1, "project": proj}, ensure_ascii=False))
                name = body.get("name", "")
                d = PROJECTS / name
                if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", name) or not d.is_dir():
                    return self._send(404, '{"error":"项目不存在"}')
                _atomic_write_text(ACTIVE, json.dumps({"name": name}))
                return self._send(200, json.dumps({"ok": 1, "name": name}, ensure_ascii=False))
            except ValueError as e:
                return self._send(400, json.dumps({"error": str(e)}, ensure_ascii=False))
            except Exception as e:
                return self._send(500, json.dumps({"error": str(e)}, ensure_ascii=False))
        if path == "/api/chain":
            engine.maybe_reload()
            try:
                body = self._read_json()
                chain = next((c for c in engine.CHAINS if c["id"] == body.get("id")), None)
                if not chain:
                    return self._send(400, json.dumps({"error": f"链不存在: {body.get('id')}"}, ensure_ascii=False))
                danger = [s.get("name", f"step{i}") for i, s in enumerate(chain.get("steps", []), 1)
                          if s.get("danger") or s.get("confirm")]
                if danger and body.get("confirm") is not True:  # confirm 闸门:危险步需显式确认
                    return self._send(409, json.dumps({"error": "危险操作需确认", "need_confirm": True,
                                                       "steps": danger}, ensure_ascii=False))
                # scope 闸门:链步骤是内联 cmd(无 tool id),无法判定 readonly → 一律要求 scope
                gate = _scope_gate(proj_dir(), body.get("params", {}), readonly=False)
                if gate:
                    return self._send(403, json.dumps(gate, ensure_ascii=False))
                res = run_chain(body["id"], body.get("params", {}), body.get("sudo_pass", ""), bool(body.get("proxy")))
                return self._send(200, json.dumps(res, ensure_ascii=False))
            except ValueError as e:
                return self._send(400, json.dumps({"error": str(e)}, ensure_ascii=False))
            except Exception as e:
                return self._send(500, json.dumps({"error": f"{type(e).__name__}: {e}"}, ensure_ascii=False))
        if path == "/api/stop":
            try:
                body = self._read_json()
                name = Path(body.get("dir", "")).name
                d = next((c for r in run_roots()
                          if (c := (r / name).resolve()).is_relative_to(r) and (c / "pid").exists()), None)
                if not d:
                    return self._send(404, '{"error":"run not found"}')
                pid = int((d / "pid").read_text().strip())
                if pid <= 1:
                    return self._send(400, '{"error":"bad pid"}')
                try: cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
                except OSError: cmdline = b""
                if not cmdline:  # 进程已不在,防止 PID 复用误杀别的进程组
                    return self._send(200, json.dumps({"stopped": "already"}, ensure_ascii=False))
                # PID 复用防护:bg 启动时 cwd=rundir(engine.run);cwd 对不上即无关进程,拒杀
                try: cwd = os.readlink(f"/proc/{pid}/cwd")
                except OSError: cwd = ""
                if cwd != str(d):
                    return self._send(409, json.dumps({"error": "pid 已被无关进程复用(cwd 不匹配),拒绝 killpg;请手工处置"}, ensure_ascii=False))
                os.killpg(pid, signal.SIGTERM); time.sleep(0.5)
                try: os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError: pass
                return self._send(200, json.dumps({"stopped": pid}, ensure_ascii=False))
            except ProcessLookupError:
                return self._send(200, json.dumps({"stopped": "already"}, ensure_ascii=False))
            except Exception as e:
                return self._send(500, json.dumps({"error": str(e)}, ensure_ascii=False))
        if path == "/api/run_multi":
            engine.maybe_reload()
            try:
                body = self._read_json()
                t = engine.TOOLS.get(body.get("id", ""))
                if not t:
                    return self._send(400, json.dumps({"error": f"工具不存在: {body.get('id')}"}, ensure_ascii=False))
                # 主目标参数:工具参数中名字 ∈ TARGET_KEYS 的那个(取第一个;没有则不支持批量)
                tkey = next((p["k"] for p in t.get("params", []) if str(p.get("k", "")).lower() in TARGET_KEYS), "")
                if not tkey:
                    return self._send(400, json.dumps({"error": f"工具 {t['id']} 无目标参数,不支持批量"}, ensure_ascii=False))
                targets = body.get("targets")
                if not isinstance(targets, list) or not targets or not all(isinstance(x, str) and x.strip() for x in targets):
                    return self._send(400, json.dumps({"error": "targets 须为非空字符串数组"}, ensure_ascii=False))
                if len(targets) > 32:
                    return self._send(400, json.dumps({"error": f"targets 超上限: {len(targets)} > 32,已拒绝"}, ensure_ascii=False))
                if (t.get("danger") or t.get("confirm")) and body.get("confirm") is not True:  # confirm 闸门:整单确认一次
                    return self._send(409, json.dumps({"error": "危险操作需确认", "need_confirm": True,
                                                       "id": t["id"], "name": t["name"]}, ensure_ascii=False))
                proj = proj_dir()
                base_params = dict(body.get("params") or {})
                try:  # 预校验全部目标的 build_cmd:任一失败 400,一个都不启动(防部分下发+报错)
                    cmds = [(tgt.strip(), build_cmd(t["id"], {**base_params, tkey: tgt.strip()}))
                            for tgt in targets]
                except ValueError as e:
                    return self._send(400, json.dumps({"error": str(e)}, ensure_ascii=False))
                runs = []
                for tgt, cmd in cmds:
                    p2 = {**base_params, tkey: tgt}
                    gate = _scope_gate(proj, p2, readonly=bool(t.get("readonly")))  # scope 闸门逐目标判定
                    if gate:
                        runs.append({"target": tgt, "skipped": gate["error"]})
                        continue
                    res = run(cmd, {**t, "bg": True},
                              body.get("sudo_pass", ""), bool(body.get("proxy")), p2)
                    runs.append({"target": tgt, "dir": res.get("dir", "")})
                return self._send(200, json.dumps({"runs": runs}, ensure_ascii=False))
            except Exception as e:
                return self._send(500, json.dumps({"error": f"{type(e).__name__}: {e}"}, ensure_ascii=False))
        if path == "/api/config":
            # 配置保存:子集合并;scope 先校验(无效整体不落盘);bh pass '***'/空 = 保留旧值
            try:
                body = self._read_json()
            except BodyTooLarge as e:
                return self._send(413, json.dumps({"error": str(e)}, ensure_ascii=False))
            except Exception as e:
                return self._send(400, json.dumps({"error": str(e)}, ensure_ascii=False))
            scope_text = None
            if "scope" in body:
                p = proj_dir()
                if not p: return self._send(404, json.dumps({"error": "无激活项目,无法保存 scope"}, ensure_ascii=False))
                scope_text = str(body.get("scope") or "")
                err = _scope_validate(scope_text)
                if err: return self._send(400, json.dumps({"error": err}, ensure_ascii=False))
            if any(k in body for k in CFG_DEFAULTS):
                for k in CFG_DEFAULTS:
                    if k not in body: continue
                    if k == "ai_enabled": CFG[k] = bool(body[k])
                    elif k == "ai":  # 子集合并;api_key '***'/空 = 保留旧值
                        a = body.get("ai") or {}
                        cur = dict(CFG.get("ai") or CFG_DEFAULTS["ai"])
                        for ak in ("format", "base_url", "model"):
                            if ak in a: cur[ak] = str(a[ak])
                        key = str(a.get("api_key") or "")
                        if key and key != "***": cur["api_key"] = key
                        CFG[k] = cur
                    else: CFG[k] = str(body[k])
                cfg_save(CFG)
            if "bh" in body:
                b = body.get("bh") or {}
                old = {}
                try: old = json.loads(BH_JSON.read_text(encoding="utf-8"))
                except Exception: pass
                for k in ("url", "user"):
                    if k in b: old[k] = str(b[k])
                pw = str(b.get("pass") or "")
                if pw and pw != "***": old["pass"] = pw
                else: old.setdefault("pass", "")
                fd, tmp = tempfile.mkstemp(dir=BH_JSON.parent, prefix=".bh-")  # mkstemp:并发保存不抢固定 tmp 名
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(json.dumps(old, ensure_ascii=False, indent=2))
                os.replace(tmp, BH_JSON)
            if scope_text is not None:
                (proj_dir() / "scope.txt").write_text(scope_text, encoding="utf-8")
            return self._send(200, '{"ok":1}')
        if path == "/api/agent/note":
            # LLM 操作员手记:带 🤖[类别] 前缀进项目 notes.md;text 截 500 字
            if not CFG.get("ai_enabled"):
                return self._send(403, json.dumps({"error": "AI 接入已禁用(配置页开启后可用)"}, ensure_ascii=False))
            p = proj_dir()
            if not p: return self._send(404, json.dumps({"error": "无激活项目"}, ensure_ascii=False))
            try:
                body = self._read_json()
                text = str(body.get("text", "")).strip()[:500]
                if not text:
                    return self._send(400, json.dumps({"error": "text 不能为空"}, ensure_ascii=False))
                kind = {"decision": "决策", "hypothesis": "假设", "observation": "观察"}.get(body.get("kind"), "决策")
                proj_note(p, f"🤖[{kind}] {text}")
                return self._send(200, '{"ok":1}')
            except Exception as e:
                return self._send(400, json.dumps({"error": str(e)}, ensure_ascii=False))
        if path in ("/api/agent/ping", "/api/agent/advise"):
            # AI 连通性测试 / 下一步建议:与 brief/note 同闸门(ai_enabled);LLM 错误一律干净 JSON,不炸 handler
            if not CFG.get("ai_enabled"):
                return self._send(403, json.dumps({"error": "AI 接入已禁用(配置页开启后可用)"}, ensure_ascii=False))
            ai_cfg = CFG.get("ai") or {}
            if not str(ai_cfg.get("base_url") or "").strip() or not str(ai_cfg.get("model") or "").strip():
                return self._send(400, json.dumps({"error": "AI 未配置完整"}, ensure_ascii=False))
            model = str(ai_cfg.get("model") or "")
            if path == "/api/agent/ping":
                try:
                    t0 = time.time()
                    reply = call_llm(ai_cfg, "你是连通性测试助手,只做简短应答。", "回复: pong")
                    return self._send(200, json.dumps({"ok": 1, "model": model,
                        "latency_ms": int((time.time() - t0) * 1000), "reply": reply[:80]}, ensure_ascii=False))
                except Exception as e:
                    return self._send(502, json.dumps({"error": str(e)}, ensure_ascii=False))
            p = proj_dir()
            if not p: return self._send(404, json.dumps({"error": "无激活项目"}, ensure_ascii=False))
            try:
                system, user = advise_prompt(brief_data(p, engine.REG["tools"], config.TIMEOUT_MULT))
                t0 = time.time()
                advice = call_llm(ai_cfg, system, user)
                ms = int((time.time() - t0) * 1000)
            except Exception as e:
                return self._send(502, json.dumps({"error": str(e)}, ensure_ascii=False))
            try: proj_note(p, f"🤖[AI建议] {advice[:200]}")
            except Exception: pass
            return self._send(200, json.dumps({"advice": advice, "model": model, "latency_ms": ms}, ensure_ascii=False))
        if path != "/api/run":
            return self._send(404, '{"error":"nf"}')
        engine.maybe_reload()
        try:
            body = self._read_json()
            t = engine.TOOLS.get(body.get("id", ""))
            if not t:
                return self._send(400, json.dumps({"error": f"工具不存在: {body.get('id')}"}, ensure_ascii=False))
            if (t.get("danger") or t.get("confirm")) and body.get("confirm") is not True:  # confirm 闸门
                return self._send(409, json.dumps({"error": "危险操作需确认", "need_confirm": True,
                                                   "id": t["id"], "name": t["name"]}, ensure_ascii=False))
            gate = _scope_gate(proj_dir(), body.get("params", {}), readonly=bool(t.get("readonly")))
            if gate:
                return self._send(403, json.dumps(gate, ensure_ascii=False))
            cmd = build_cmd(body["id"], body.get("params", {}))
            res = run(cmd, t, body.get("sudo_pass", ""),
                      bool(body.get("proxy")), body.get("params", {}))
            self._send(200, json.dumps(res, ensure_ascii=False))
        except ValueError as e:
            self._send(400, json.dumps({"error": str(e)}, ensure_ascii=False))
        except Exception as e:
            self._send(500, json.dumps({"error": f"{type(e).__name__}: {e}"}, ensure_ascii=False))

    def log_message(self, *a): pass
