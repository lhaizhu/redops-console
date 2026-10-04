#!/usr/bin/env python3
# state.py — 项目交战状态机唯一读写器(projects/<name>/state.json)
# serve.py 与 bin/lib/state.sh 都通过本 CLI 操作,避免双写漂移。
# 用法: state.py <projdir> <cmd> [args]
#   tried check <key>              tried[key].rc==0 → exit 0,否则 1
#   tried mark <key> <rc>          记录 {ts, rc}
#   phase check <name>             phases[name].done 存在 → exit 0,否则 1
#   phase mark <name> [artifact]   记录完成时间+产物路径
#   phase artifact <name>          打印产物路径(无则空行)
#   cred add <类型> <主体> <域> <来源>   去重登记(不存值,值在 creds.csv)
#   cred use <needle>              needle==值 或 ∈主体 的凭据标记已用:
#                                  state.creds[].used=true 且 creds.csv 用过没列→已用;打印命中数
#   cred verify <主体> <host>      valid_for += host, last_verified=now
#   summary                        打印 JSON 计数(供看板)
# 并发:fcntl 锁 + os.replace 原子写。任何命令失败都不该搞挂调用方(调用方自行 || true)。
import copy
import csv
import fcntl
import json
import os
import sys
import tempfile
import hashlib
from datetime import datetime

def now() -> str:
    return datetime.now().strftime("%m-%d %H:%M:%S")

EMPTY = {"version": 1, "hosts": {}, "creds": [], "tried": {}, "phases": {}, "findings": []}

class State:
    """带锁读-改-写 state.json。with State(projdir) as s: ... s.save()"""

    def __init__(self, projdir: str):
        self.dir = projdir
        self.path = os.path.join(projdir, "state.json")
        self.lock_path = os.path.join(projdir, ".state.lock")
        self.data = None
        self._lock = None

    def __enter__(self) -> "State":
        os.makedirs(self.dir, exist_ok=True)
        self._lock = open(self.lock_path, "w")
        fcntl.flock(self._lock, fcntl.LOCK_EX)
        if os.path.exists(self.path):
            try:
                self.data = json.loads(open(self.path, encoding="utf-8").read())
            except (ValueError, OSError):
                # 状态腐败不丢原文件:备份(时间戳名,不覆盖上一份备份)后重置
                os.replace(self.path, self.path + "." + datetime.now().strftime("%Y%m%d%H%M%S") + ".bak")
                self.data = json.loads(json.dumps(EMPTY))
        else:
            self.data = json.loads(json.dumps(EMPTY))
        for k, v in EMPTY.items():
            self.data.setdefault(k, copy.deepcopy(v))  # 深拷贝默认值:绝不把 EMPTY 的共享可变对象插进 data
        return self

    def save(self) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".state-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)

    def __exit__(self, *exc) -> None:
        fcntl.flock(self._lock, fcntl.LOCK_UN)
        self._lock.close()

def cred_match(c: dict, needle: str) -> bool:
    # needle 命中:值原文(遗留)、主体包含、或值的 sha256(值不落盘,只存指纹)
    return bool(needle) and (needle == c.get("value") or needle in c.get("subject", "")
                             or hashlib.sha256(needle.encode()).hexdigest() == c.get("vhash"))

def csv_mark_used(projdir: str, needle: str) -> int:
    """creds.csv 用过没列(第 8 列,idx 7)→已用;命中数返回。原子重写。"""
    path = os.path.join(projdir, "creds.csv")
    if not os.path.exists(path):
        return 0
    rows = list(csv.reader(open(path, encoding="utf-8")))
    if not rows:
        return 0
    n = 0
    for r in rows[1:]:
        if len(r) >= 8 and r[7].strip() != "已用" and (needle == r[4] or needle in r[2]):
            r[7] = "已用"
            n += 1
    if n:
        fd, tmp = tempfile.mkstemp(dir=projdir, prefix=".creds-")
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            csv.writer(f).writerows(rows)
        os.replace(tmp, path)
    return n

USAGE = "用法: state.py <projdir> <tried|phase|cred|summary> [args](见文件头注释)"

def main() -> int:
    if len(sys.argv) < 3:
        print(USAGE)
        return 1
    projdir, cmd, args = sys.argv[1], sys.argv[2], sys.argv[3:]
    with State(projdir) as s:
        d = s.data
        if not args and cmd != "summary":
            print(USAGE)
            return 1
        if cmd == "tried" and args[0] == "check" and len(args) == 2:
            e = d["tried"].get(args[1])
            return 0 if e and e.get("rc") == 0 else 1
        if cmd == "tried" and args[0] == "mark" and len(args) == 3:
            d["tried"][args[1]] = {"ts": now(), "rc": int(args[2])}
            s.save()
            return 0
        if cmd == "phase" and args[0] == "check" and len(args) == 2:
            return 0 if d["phases"].get(args[1], {}).get("done") else 1
        if cmd == "phase" and args[0] == "mark" and len(args) >= 2:
            d["phases"][args[1]] = {"done": now(), "artifact": args[2] if len(args) > 2 else ""}
            s.save()
            return 0
        if cmd == "phase" and args[0] == "artifact" and len(args) == 2:
            print(d["phases"].get(args[1], {}).get("artifact", ""))
            return 0
        if cmd == "cred" and args[0] == "add" and len(args) in (5, 6):
            typ, subj, dom, src = args[1], args[2], args[3], args[4]
            vhash = hashlib.sha256(args[5].encode()).hexdigest() if len(args) == 6 else None
            for c in d["creds"]:
                if c["subject"].lower() == subj.lower() and c["type"] == typ:  # 域\用户大小写不敏感(north\X 与 NORTH\X 同一凭据)
                    if vhash and not c.get("vhash"):
                        c["vhash"] = vhash
                        s.save()
                    return 0  # 去重(补指纹)
            d["creds"].append({"type": typ, "subject": subj, "domain": dom, "source": src,
                               "vhash": vhash,
                               "used": False, "used_ts": None, "valid_for": [], "last_verified": None})
            s.save()
            return 0
        if cmd == "cred" and args[0] == "use" and len(args) == 2:
            needle = args[1]
            n = 0
            for c in d["creds"]:
                if cred_match(c, needle) and not c["used"]:
                    c["used"] = True
                    c["used_ts"] = now()
                    n += 1
            n += csv_mark_used(projdir, needle)
            if n:
                s.save()
            print(n)
            return 0
        if cmd == "cred" and args[0] == "get" and len(args) == 2:
            # {{cred:主体}} 水合:state 找最新有效条目,creds.csv 取值原文
            subj = args[1]
            best = None
            for c in d["creds"]:
                if subj in c["subject"]:
                    if best is None or (c["valid_for"] and not best["valid_for"]):
                        best = c
            if best is None:
                return 1
            path = os.path.join(projdir, "creds.csv")
            if os.path.exists(path):
                rows = [r for r in list(csv.reader(open(path, encoding="utf-8")))[1:] if len(r) >= 5]
                # 主体精确相等优先于子串包含(防账户名互相包含误配);creds.csv 追加式,尾部最新
                cands = [r for r in rows if r[2] == best["subject"]] or \
                        [r for r in rows if best["subject"] in r[2]]
                pick = None
                vh = best.get("vhash") or ""
                if vh:  # best 带指纹:优先值 sha256 与 vhash 匹配的行(密码轮换后仍取到对应值)
                    pick = next((r for r in reversed(cands)
                                 if hashlib.sha256(r[4].encode()).hexdigest() == vh), None)
                if pick is None and cands:
                    pick = cands[-1]  # 无指纹可核对:取最新一条,不取最旧
                if pick is not None:
                    print(f"{pick[1]}\t{pick[4]}")  # 类型<TAB>值
                    return 0
            return 1
        if cmd == "cred" and args[0] == "verify" and len(args) == 3:
            subj, host = args[1], args[2]
            for c in d["creds"]:
                if subj in c["subject"]:
                    if host not in c["valid_for"]:
                        c["valid_for"].append(host)
                    c["last_verified"] = now()
            s.save()
            return 0
        if cmd == "finding" and args[0] == "add" and len(args) >= 4:
            # finding add <标题> <严重度> <证据> [主机] — 按 标题+主机 去重
            title, sev, ev = args[1], args[2], args[3]
            host = args[4] if len(args) > 4 else ""
            for f in d["findings"]:
                if f["title"] == title and f.get("host", "") == host:
                    return 0
            d["findings"].append({"ts": now(), "title": title, "severity": sev,
                                  "evidence": ev, "host": host})
            s.save()
            return 0
        if cmd == "finding" and args[0] == "list":
            print(json.dumps(d["findings"], ensure_ascii=False, indent=1))
            return 0
        if cmd == "host" and args[0] == "add" and len(args) >= 2:
            # host add <ip> [k=v ...] — 合并写入 hosts 清单
            h = d["hosts"].setdefault(args[1], {"owned": False, "services": [], "first_seen": now()})
            for kv in args[2:]:
                k, _, v = kv.partition("=")
                if k == "services":
                    h["services"] = sorted({int(x) for x in v.split(",") if x.isdigit()} | set(h.get("services", [])))
                elif k:
                    h[k] = v
            s.save()
            return 0
        if cmd == "host" and args[0] == "owned" and len(args) == 2:
            h = d["hosts"].setdefault(args[1], {"owned": False, "services": [], "first_seen": now()})
            h["owned"] = True
            h["owned_ts"] = now()
            s.save()
            return 0
        if cmd == "host" and args[0] == "list":
            print(json.dumps(d["hosts"], ensure_ascii=False, indent=1))
            return 0
        if cmd == "summary":
            print(json.dumps({
                "creds": len(d["creds"]),
                "creds_used": sum(1 for c in d["creds"] if c["used"]),
                "tried": len(d["tried"]),
                "tried_ok": sum(1 for t in d["tried"].values() if t.get("rc") == 0),
                "phases": sorted(d["phases"]),
                "hosts": len(d["hosts"]),
                "hosts_owned": sum(1 for h in d["hosts"].values() if h.get("owned")),
                "findings": len(d["findings"]),
            }, ensure_ascii=False))
            return 0
    print(USAGE)
    return 1

if __name__ == "__main__":
    sys.exit(main())
