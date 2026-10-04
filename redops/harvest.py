"""harvest.py — 工具输出自动收割:凭据 → creds.csv(去重);可爆哈希(TGS/ASREP/NetNTLMv2)→ hashqueue.txt;fscan 端口 → state hosts;certipy ESC/CA、BH 差异计数、persist-audit 汇总行解析"""
import csv, fcntl, re, time
from contextlib import contextmanager
from .project import _state

@contextmanager
def proj_lock(proj):
    """creds.csv/hashqueue.txt 写者与 state.py 共用同一把 <proj>/.state.lock(全写者单锁约定;
    bash 侧用 flock 命令锁同一文件)。注意:锁内绝不调 _state(子进程会抢同一把锁 → 死锁)"""
    f = open(proj / ".state.lock", "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(f, fcntl.LOCK_UN)
        f.close()

def queue_hashes(proj, hashes):
    """哈希行按行去重追加 hashqueue.txt(.state.lock 内读+写,与 crack-sync 重写互斥);返回新增行"""
    with proj_lock(proj):
        qf = proj / "hashqueue.txt"
        exist = qf.read_text(errors="ignore") if qf.exists() else ""
        fresh = [h for h in hashes if h not in exist]
        if fresh:
            with open(qf, "a") as f: f.write("\n".join(fresh) + "\n")
    return fresh

RE_TGS_HASH = re.compile(r"^\$krb5(?:asrep|tgs)\$\d+\$\S+", re.M)
RE_NETNTLMV2 = re.compile(r"([\w.$\\-]+::[^\s:]+:[0-9a-fA-F]{16}:[0-9a-fA-F]{32,}:[0-9a-fA-F]{20,})")
RE_CRED_LINE = re.compile(r"^([\w.$\\-]+:\d+:[a-f0-9]{32}:[a-f0-9]{32}:::)", re.M)
RE_FSCAN_PORT = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})(?!\d)")  # fscan 行式:'1.2.3.4:445 open' / '[+] 1.2.3.4:445'
RE_ESC = re.compile(r"^\s+ESC(\d{1,2})\s+:\s*\S", re.M)     # certipy 漏洞段行;'ESCn Target Template' 说明行不匹配
RE_CA_NAME = re.compile(r"^\s+CA Name\s+:\s*(\S+)\s*$", re.M)
RE_BH_HVALUE = re.compile(r"\*\*高价值变化 (\d+) 条\*\*")      # bin/bh-diff.py 汇总行
RE_PERSIST_SUM = re.compile(r"^PERSIST-AUDIT: sdholder=(\d+) shadow=(\d+) unconstrained=(\d+) krbtgt_pwdlastset=(\S+)", re.M)  # bin/persist-audit.sh 汇总行
RE_TGS_USER = re.compile(r"^\$krb5tgs\$\d+\$\*([^$]+)\$")    # $krb5tgs$23$*USER$DOMAIN$...
RE_ASREP_USER = re.compile(r"^\$krb5asrep\$\d+\$([^@$]+)@")  # $krb5asrep$23$USER@DOMAIN$...

def parse_certipy(out):
    """certipy find -vulnerable 文本输出 → (可利用 ESCn 列表, CA 名);
    仅当输出含漏洞段标记(Vulnerab/[!])时提取,避免 ESCn 出现在非漏洞上下文的误报"""
    if not out or ("Vulnerab" not in out and "[!]" not in out):
        return [], ""
    escs = sorted({"ESC" + n for n in RE_ESC.findall(out)}, key=lambda s: int(s[3:]))
    m = RE_CA_NAME.search(out)
    return escs, (m.group(1) if m else "")

def parse_persist(out):
    """persist-audit.sh 汇总行 → {'sdholder','shadow','unconstrained':int,'krbtgt_pwdlastset':str};无该行返回 None"""
    m = RE_PERSIST_SUM.search(out or "")
    if not m: return None
    return {"sdholder": int(m.group(1)), "shadow": int(m.group(2)),
            "unconstrained": int(m.group(3)), "krbtgt_pwdlastset": m.group(4)}

def _hash_subject(h):
    """TGS/ASREP 哈希 → 用户名(登记待爆破主体用);取不出返回 ''"""
    m = RE_TGS_USER.match(h) or RE_ASREP_USER.match(h)
    return m.group(1) if m else ""

def harvest(t, out, proj, rundir_name):
    """从工具输出自动收割凭据 → creds.csv(去重)+ 可爆哈希入 hashqueue.txt(TGS/ASREP/NetNTLMv2);返回摘要"""
    if not proj: return ""
    tid = t["id"] if isinstance(t, dict) else str(t)
    rows = []
    if tid in ("secretsdump", "dcsync", "dcsync-all", "adfs-dcsync", "nxc-sam", "sam"):
        for m in RE_CRED_LINE.finditer(out):
            parts = m.group(1).split(":")
            rows.append(("NT哈希", parts[0], m.group(1)))
    if tid in ("certipy-auth",):
        m = re.search(r"Got hash:\s*([a-f0-9]{32}:[a-f0-9]{32})", out)
        if m: rows.append(("NT哈希", "certipy-auth 产出", m.group(1)))
    queued = 0
    tq = RE_TGS_HASH.findall(out)
    if tid == "responder" or tid.startswith("relay-"):
        tq += RE_NETNTLMV2.findall(out)  # NetNTLMv2 → hashqueue(hashcat 5600),与 TGS 同按行去重
    if tq:
        fresh = queue_hashes(proj, tq)
        if fresh:
            queued = len(fresh)
            for s in sorted({u for u in map(_hash_subject, fresh) if u}):
                _state(proj, "cred", "add", "待爆破哈希", s, "", rundir_name)  # 主体骨架入 state(无值);subject+type 去重
    fscan_hosts = {}
    if tid == "fscan":  # fscan 存活端口 → state hosts(按 IP 聚合;合并/去重由 state.py host add)
        for m in RE_FSCAN_PORT.finditer(out):
            port = int(m.group(2))
            if port <= 65535:
                fscan_hosts.setdefault(m.group(1), set()).add(port)
    if not rows and not queued and not fscan_hosts: return ""
    new = []
    if rows:
        csvf = proj / "creds.csv"
        with proj_lock(proj):  # 读+追加整体入锁:与 csv_mark_used 的原子重写互斥,不丢行
            existing = set()   # 按解析列(主体,值)去重,不用原始子串(防哈希互为子串误去重)
            if csvf.exists():
                with open(csvf, encoding="utf-8", errors="ignore") as f:
                    for r in csv.reader(f):
                        if len(r) >= 5: existing.add((r[2], r[4]))
            new = [r for r in rows if (r[1], r[2]) not in existing]
            if new:
                with open(csvf, "a", encoding="utf-8", newline="") as f:
                    w = csv.writer(f)  # csv 引号:值含逗号/引号不冲垮台账列
                    for typ, who, val in new:
                        w.writerow([time.strftime('%Y-%m-%d %H:%M'), typ, who, "", val,
                                    rundir_name, "自动收割", "未用", ""])
        for typ, who, val in new:
            _state(proj, "cred", "add", typ, who, "", rundir_name, val)  # state.json 登记(值只存 sha256 vhash),自动去重
    parts = []
    if new: parts.append(f"🔑 收割 {len(new)} 条凭据→creds.csv")
    if queued: parts.append(f"⏳ {queued} 条哈希入破解队列 hashqueue.txt")
    if fscan_hosts:
        n = 0
        for ip, ps in sorted(fscan_hosts.items()):
            if _state(proj, "host", "add", ip, "services=" + ",".join(map(str, sorted(ps))))[0] == 0:
                n += 1
        if n: parts.append(f"🖥 登记 {n} 台主机端口→state")
    return (" " + " · ".join(parts)) if parts else ""
