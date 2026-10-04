#!/usr/bin/env python3
"""bh-diff.py — BloodHound 两次采集差异对比(阶段推进证据)
用法: bh-diff.py <旧采集目录或zip> <新采集目录或zip>
输出: 新增/变化 实体与高价值信号(新用户/新机器/新信任/adminCount 新增/SPN 新增/委托新增)
支持 bloodhound-python 产物(*_users.json/_computers.json/_groups.json;信任取自 *_domains.json 的 Trusts 字段,zip 成员内存读取不解压)
"""
import json, sys, zipfile
from pathlib import Path, PurePosixPath


def load_docs(src, kind):
    """返回指定 kind 的 BH 文档列表(目录或 zip);zip 成员仅按文件名过滤后内存读取,不解压落盘"""
    src = Path(src)
    docs = []
    if src.suffix == ".zip":
        with zipfile.ZipFile(src) as zf:
            for n in zf.namelist():
                base = PurePosixPath(n).name
                if base.endswith(".json") and kind in base:
                    try: docs.append(json.loads(zf.read(n).decode("utf-8", "ignore")))
                    except Exception: pass
        return docs
    for f in sorted(src.glob(f"*{kind}*.json")):
        try: docs.append(json.loads(f.read_text(errors="ignore")))
        except Exception: pass
    return docs

def load_set(src, kind):
    """返回 {名字: 标志集合}"""
    out = {}
    for d in load_docs(src, kind):
        for e in d.get("data", []):
            p = e.get("Properties", {})
            name = (p.get("name") or e.get("ObjectProperties", {}).get("name") or "").lower()
            if not name: continue
            flags = set()
            if p.get("admincount"): flags.add("adminCount")
            if p.get("hasspn", False): flags.add("SPN")
            if p.get("unconstraineddelegation", False): flags.add("无约束委托")
            if p.get("dontreqpreauth", False): flags.add("AS-REP可烤")
            if p.get("enabled", True) is False: flags.add("禁用")
            if e.get("AllowedToDelegate", []) or p.get("allowedtodelegate"): flags.add("约束委托")
            out[name] = flags
    return out

DIR_CN = {1: "入向", 2: "出向", 3: "双向"}
TYPE_CN = {0: "ParentChild", 1: "CrossLink", 2: "Forest", 3: "External", 4: "Unknown"}

def load_trusts(src):
    """返回 {源域→目标域: 标志集合}
    bloodhound-python 不产出独立 *_trusts.json:信任内嵌于 *_domains.json 每个域的 Trusts 字段
    (TargetDomainName/TargetDomainSid/IsTransitive/TrustDirection/TrustType/SidFilteringEnabled);
    同时兼容少数产出独立 trusts 文件的采集分支"""
    entries = []   # (源域名小写, trust dict)
    docs = load_docs(src, "trusts")
    if docs:
        for d in docs:
            for t in d.get("data", []):
                entries.append(((t.get("SourceDomainName") or t.get("sourcedomainname") or "").lower(), t))
    else:
        for d in load_docs(src, "domains"):
            for dom in d.get("data", []):
                src_name = (dom.get("Properties", {}).get("name") or "").lower()
                for t in dom.get("Trusts", []):
                    entries.append((src_name, t))
    out = {}
    for src_name, t in entries:
        tgt = (t.get("TargetDomainName") or t.get("targetdomainname") or "").lower()
        if not tgt: continue
        flags = set()
        if t.get("TrustDirection") in DIR_CN: flags.add(DIR_CN[t["TrustDirection"]])
        if t.get("TrustType") in TYPE_CN: flags.add(TYPE_CN[t["TrustType"]])
        if t.get("IsTransitive"): flags.add("可传递")
        if t.get("SidFilteringEnabled"): flags.add("SID过滤")
        out[f"{src_name}→{tgt}" if src_name else tgt] = flags
    return out


def diff_set(old, new, label):
    lines = []
    added = set(new) - set(old)
    removed = set(old) - set(new)
    for n in sorted(added):
        fl = ", ".join(sorted(new[n])) or "普通"
        lines.append(f"| + {label} | {n} | {fl} |")
    for n in sorted(removed):
        lines.append(f"| - {label} | {n} | 已消失 |")
    for n in sorted(set(old) & set(new)):
        gained = new[n] - old[n]
        if gained:
            lines.append(f"| Δ {label} | {n} | 新增标记: {', '.join(sorted(gained))} |")
    return lines

def main():
    if len(sys.argv) != 3:
        print(__doc__); return 1
    old, new = sys.argv[1], sys.argv[2]
    rows = []
    for kind, label in [("users", "用户"), ("computers", "机器"), ("groups", "组")]:
        rows += diff_set(load_set(old, kind), load_set(new, kind), label)
    rows += diff_set(load_trusts(old), load_trusts(new), "信任")
    print("# BH 采集差异(旧 → 新)\n")
    if not rows:
        print("无显著差异(实体集合与高价值标记一致)\n"); return 0
    print("| 变化 | 类型 | 实体 | 信号 |")
    print("|---|---|---|---|")
    print("\n".join(rows))
    hi = [r for r in rows if any(k in r for k in ("adminCount", "无约束", "SPN", "AS-REP", "信任"))]
    print(f"\n**高价值变化 {len(hi)} 条**" + ("(优先跟进)" if hi else ""))
    return 0

if __name__ == "__main__":
    sys.exit(main())
