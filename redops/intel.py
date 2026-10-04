"""intel.py — 纯数据函数:fail_hints(24 签名错误码建议)/ board_data(项目看板 v2)/ brief_data(LLM 操作员速览)
不触碰 HTTP;ai_enabled 闸门留在 server 层"""
import csv, json, re
from .project import _state, hist_entries
from .harvest import RE_TGS_HASH, RE_NETNTLMV2, RE_CRED_LINE

RE_NT_HEX = re.compile(r"[0-9a-fA-F]{32}")  # 裸 NT 哈希(32 位十六进制)

def _mask_secrets(text):
    """外发前脱敏:工具输出尾部可能带 NT/NetNTLMv2/TGS 哈希或明文行 → 一律打码。
    红线:凭据值绝不离开本机(brief 会发给用户自定义的第三方 LLM 端点)"""
    if not text: return text
    for rx in (RE_TGS_HASH, RE_NETNTLMV2, RE_CRED_LINE, RE_NT_HEX):
        text = rx.sub("***", text)
    return text

def fail_hints(out):
    """按输出错误码给下一步建议(接 10 号回退树)"""
    hints = []
    if "STATUS_LOGON_FAILURE" in out: hints.append("密码/哈希不匹配 → 空会话 --rid-brute 枚举真实用户名再试;或全网段 --local-auth 喷该哈希找母机(工具:工作组哈希碰撞)")
    if "STATUS_ACCOUNT_LOCKED_OUT" in out: hints.append("已锁定 → 换账号;--pass-pol 看锁定时长后再战")
    if "STATUS_PASSWORD_EXPIRED" in out: hints.append("密码过期 → impacket-changepasswd 改密后重来")
    if "STATUS_ACCOUNT_DISABLED" in out: hints.append("账户禁用 → rid-brute 找替身账户")
    if "CLOCK_SKEW" in out or "clock skew" in out.lower(): hints.append("时间偏移 → domain-setup 对时(chronyd)")
    if "SMB session error" in out and "NT_STATUS_CONNECTION_REFUSED" in out: hints.append("端口不通 → nmap 复核 445/5985")
    if "STATUS_ACCESS_DENIED" in out: hints.append("权限拒绝 → 账户对/权限不够:换高权账户或走 BH 查该账户的边")
    if "STATUS_LOGON_TYPE_NOT_GRANTED" in out: hints.append("登录类型被拒(如本地账户禁网络登录)→ 换 SMB 之外的通道(WinRM/RDP)或域账户")
    if "KDC_ERR" in out: hints.append("Kerberos 错误 → 核对 KDC_ERR_PREAUTH(密码错)/S_PRINCIPAL_UNKNOWN(SPN 拼写)/时钟偏移(对时)")
    if "timeout" in out.lower() and "connect" in out.lower(): hints.append("连接超时 → 可达性复核;深层网段记得勾 proxychains4 或先铺 ligolo")
    if "STATUS_NO_LOGON_SERVERS" in out or "STATUS_IO_TIMEOUT" in out: hints.append("找不到登录服务器/IO 超时 → DC 不可达或 DNS 错:核对 -dc-ip 与 /etc/hosts,domain-setup 重做")
    if "KDC_ERR_ETYPE_NOTSUPP" in out or "aes256" in out.lower() and "etype" in out.lower(): hints.append("加密类型不支持 → 加 -aesKey 或强制 RC4(--no-pass 场景换 NT 哈希)")
    if "STATUS_NOT_SUPPORTED" in out: hints.append("SMB1 拒绝/协议不支持 → 目标是 SMB2/3 only;换 nxc 默认方言,别用老 smbclient -L")
    if "CERTSRV_E_TEMPLATE_DENIED" in out or "ERR_BAD_TEMPLATE" in out: hints.append("模板被拒 → 模板名拼写/权限:certipy find -vulnerable 复核命中模板与注册权限")
    if "CA_NOT_FOUND" in out or ("certipy" in out.lower() and "not found" in out.lower()): hints.append("CA 找不到 → CA 名用 find 输出的准确全名(含主机前缀),-dc-ip 指向 CA 所在林")
    if "No hashes loaded" in out or "Token length exception" in out: hints.append("hashcat 没吃到哈希 → 队列空或格式错:crack-sync 前先看 hashqueue.txt 是否有料;NetNTLM 用 -m 5600")
    if "clGetDeviceIDs" in out or "nvrtc" in out.lower(): hints.append("hashcat GPU 初始化失败 → 加 --force 走 CPU 或换 -O 精简内核;VM 内属正常")
    if "Address already in use" in out: hints.append("端口被占 → 旧 responder/服务没死:console.sh stop 或 pkill -f 对应进程")
    if "Proxy request failed" in out or "proxychains" in out.lower() and "timeout" in out.lower(): hints.append("代理链路断 → 查 ligolo/chisel 隧道存活;proxychains4 -q 重试前先 netcheck")
    if "WinRMAuthorizationError" in out: hints.append("WinRM 认证失败 → 密码错或账户禁 WinRM;换 SMB 验证(nxc-verify)排除密码问题")
    if "Failed to resolve" in out: hints.append("DNS 解析失败 → /etc/hosts 补域控记录,或全用 IP + -dc-ip 显式指定")
    if "STATUS_PIPE_BROKEN" in out or "NT_STATUS_PIPE_BROKEN" in out: hints.append("管道断 → 目标服务重启中或 EDR 断连;隔几分钟重试,反复断=被盯上了,降速")
    if "NoneType' object has no attribute 'extend'" in out: hints.append("BloodHound DNS 崩溃 → 域名/DC 主机名未解析:先跑「接入链 onboard」(domain-setup 配 /etc/hosts+krb5.conf)")
    if "No entries found" in out: hints.append("该域没有可烤账户 → 多域环境换子域/林内其他域各跑一遍(trust-map 看拓扑);或确认查询账户有该域读取权")
    if "STATUS_OBJECT_NAME_NOT_FOUND" in out and "atexec" in out.lower(): hints.append("atexec 在高延迟链路 Run 后立刻 Delete 任务,任务没起跑就被删(非读回竞态) → 用「Win Agent 执行 win-run」(任务保活+文件回读)")
    if "Matching credential not found" in out: hints.append("evil-winrm 票不对 SPN → WinRM 要 http/<主机> 的票(cifs 票不行),S4U 重取 spn=http/...")
    if "rpc_s_access_denied" in out.lower() or "ERROR_DS_DRA_ACCESS_DENIED" in out: hints.append("DRSUAPI/RPC 权限拒绝 → 对子域用父域 EA(林根内置 administrator 默认 EA)跨域 DCSync:dcsync-all 填凭据所属域=父域、dc=子域控")
    return "\n[建议] " + "\n[建议] ".join(hints) if hints else ""

def board_data(p):
    """项目看板 v2:notes/creds/runs + state.json 驱动的下一步建议引擎。p 为激活项目目录(存在性由调用方保证)"""
    notes = p.joinpath("notes.md"); creds = p.joinpath("creds.csv"); runs = p.joinpath("loot", "runs")
    board = {"name": p.name,
             "notes": notes.read_text(errors="ignore").splitlines()[-80:] if notes.exists() else [],
             "creds": list(csv.reader(creds.read_text(errors="ignore").splitlines()))[1:] if creds.exists() else [],
             "runs": sorted((d.name for d in runs.iterdir() if d.is_dir()), reverse=True)[:40] if runs.exists() else []}
    # —— 下一步建议引擎 v2:state.json 驱动(phases/tried/creds 计数 + hashqueue 残留)——
    qf = p / "hashqueue.txt"; queue_n = len([l for l in qf.read_text().splitlines() if l.strip()]) if qf.exists() else 0
    creds_txt = creds.read_text(errors="ignore") if creds.exists() else ""
    _rc, _s = _state(p, "summary")
    try: summ = json.loads(_s) if _rc == 0 else {}
    except ValueError: summ = {}
    try: st = json.loads((p / "state.json").read_text(encoding="utf-8"))
    except Exception: st = {}
    phases = set(summ.get("phases") or st.get("phases", {}).keys())
    creds_n = summ.get("creds", len(st.get("creds", [])))
    tried_ok = [k for k, v in st.get("tried", {}).items() if v.get("rc") == 0]
    krbtgt = "krbtgt" in (" ".join(c.get("subject", "") for c in st.get("creds", [])) + creds_txt).lower()
    nexts = []
    if "P1" not in phases:
        nexts.append("P1 侦察未完成 → 跑侦察(autopwn / 执行台「sweep 一把梭」)")
    elif creds_n == 0:
        nexts.append("侦察完成但仍无凭据 → 密码喷洒(spray)/ AS-REP 爆破(asreproast)")
    if creds_n > 0 and queue_n:
        nexts.append(f"破解队列残留 {queue_n} 条 → 跑 crack-sync(hashcat-queue)收割明文")
    if creds_n > 0 and not any("bh-collect" in k for k in tried_ok):
        nexts.append("有凭据但未采集 → BloodHound 采集(bh-collect)看攻击路径")
    if krbtgt:
        nexts.append("krbtgt 已到手 → 域控后动作:金票(golden)/ dcsync 全域导出")
    # —— 手册 §四 决策表的确定性部分 ——
    used_n = summ.get("creds_used", 0)
    if creds_n > 0 and used_n < creds_n:
        nexts.append(f"{creds_n - used_n} 条凭据未验证/未用 → nxc-verify 验证有效面,别急着打新洞")
    owned = [ip for ip, h in st.get("hosts", {}).items() if h.get("owned")]
    covered = {h for c in st.get("creds", []) for h in c.get("valid_for", [])}
    lat = [h for h in covered if h not in owned]
    if lat:
        nexts.append(f"凭据覆盖但未拿下的主机 {len(lat)} 台({', '.join(sorted(lat)[:3])}) → 横向:evilwinrm/psexec")
    hi = [f for f in st.get("findings", []) if f.get("severity") == "高"]
    if hi:
        nexts.append(f"高危发现 {len(hi)} 条待跟进 → 最新: {hi[-1].get('title', '')}({hi[-1].get('host') or '全域'})")
    if not nexts: nexts.append("按 Runbook 推进;结项跑 report.sh")
    board["next"] = nexts[:5]; board["queue"] = queue_n
    return board

def brief_data(p, tools, timeout_mult):
    """LLM 操作员速览:项目+状态+战果+最近失败,全 fail-safe;凭据只出元信息,值/vhash 绝不外发。
    p 为激活项目目录(存在性由调用方保证);tools 为 REG["tools"];timeout_mult 为当前网络超时倍数"""
    def _sj(*a):  # state.py 子命令 → JSON;故障回空
        rc, s = _state(p, *a)
        if rc != 0: return None
        try: return json.loads(s)
        except ValueError: return None
    try: pj = json.loads((p / "project.json").read_text(encoding="utf-8"))
    except Exception: pj = {}
    try: st = json.loads((p / "state.json").read_text(encoding="utf-8"))
    except Exception: st = {}
    creds = [{k: c.get(k) for k in ("subject", "type", "domain", "used", "valid_for", "last_verified")}
             for c in st.get("creds", [])]
    scope = None
    try:
        sp = p / "scope.txt"
        if sp.exists(): scope = sp.read_text(errors="ignore").splitlines()
    except OSError: pass
    runs = p / "loot" / "runs"
    hent = hist_entries(runs / "history.jsonl", 10)
    recent = [{k: e.get(k) for k in ("id", "name", "rc", "ts", "proj")} for e in hent]  # cmd/params 不进速览
    last_failure = None
    for e in reversed(hent):  # hent 尾部最新;rc!=0 即失败(含超时 -1)
        if e.get("rc") in (None, 0): continue
        tail = None
        try:  # rundir 不入史,best-effort 按 <id>-* 目录最新 mtime 定位 out.log
            cands = [d for d in runs.glob(f"{e.get('id', '')}-*") if d.is_dir()]
            for d in sorted(cands, key=lambda d: d.stat().st_mtime, reverse=True):
                lg = d / "out.log"
                if lg.is_file():
                    tail = _mask_secrets(lg.read_text(errors="ignore")[-1500:]); break
        except Exception: pass
        last_failure = {"id": e.get("id"), "ts": e.get("ts"), "rc": e.get("rc"), "out_tail": tail}
        break
    qf = p / "hashqueue.txt"
    try: queue = len([l for l in qf.read_text().splitlines() if l.strip()]) if qf.exists() else 0
    except OSError: queue = 0
    stages = {}
    for t in tools:
        stages.setdefault(t.get("stage", ""), []).append(t["id"])
    return {"project": {"name": p.name, "domain": pj.get("domain", ""), "dcip": pj.get("dcip", ""),
                        "domains": pj.get("domains", [])},
            "summary": _sj("summary") or {},
            "findings": _sj("finding", "list") or [],
            "hosts": _sj("host", "list") or {},
            "creds": creds, "scope": scope, "recent": recent, "last_failure": last_failure,
            "queue": queue, "timeout_mult": timeout_mult, "tools_available": stages}
