#!/usr/bin/env python3
"""bh-queries.py — 将 ~/tools/redops/bh_queries.json 固化进 BloodHound CE(Saved Queries)
用法: bh-queries.py [--url http://127.0.0.1:8080] [--user admin] [--pass admin] [--list] [--rm 前缀]
流程: 登录(/api/v2/login, login_method=secret) → 按 name 去重 → 逐条 POST /api/v2/saved-queries/import
--rm 前缀: 删除名称以该前缀开头的已存查询(DELETE /api/v2/saved-queries/{id}),逐条打印确认
"""
import argparse, json, sys, urllib.request, urllib.error
from pathlib import Path

CFG_DIR = Path(__file__).resolve().parent.parent / "redops"
QSET = CFG_DIR / "bh_queries.json"

def load_cfg():
    cfg = {"url": "http://127.0.0.1:8080", "user": "admin", "pass": "admin"}
    p = CFG_DIR / "bh.json"
    if p.exists():
        cfg.update(json.loads(p.read_text()))
    return cfg

def parse_args():
    ap = argparse.ArgumentParser(description="将 bh_queries.json 固化进 BloodHound CE Saved Queries")
    ap.add_argument("--url", help="BH CE 地址(覆盖 redops/bh.json)")
    ap.add_argument("--user", help="登录用户名")
    ap.add_argument("--pass", dest="passwd", help="登录密码(secret)")
    ap.add_argument("--list", action="store_true", help="只列出当前已存查询")
    ap.add_argument("--rm", metavar="前缀", help="删除名称以该前缀开头的已存查询")
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

def main():
    args = parse_args()
    cfg = load_cfg()
    if args.url: cfg["url"] = args.url
    if args.user: cfg["user"] = args.user
    if args.passwd: cfg["pass"] = args.passwd
    tok = login(cfg)
    if not tok: return 1
    st, cur = api(cfg, "/api/v2/saved-queries", token=tok)
    saved = (cur.get("data") or []) if st == 200 else []
    if args.list:
        for q in saved:
            print(f"  {q['name']}")
        return 0
    if args.rm is not None:
        hits = [q for q in saved if q["name"].startswith(args.rm)]
        if not hits:
            print(f"无名称以「{args.rm}」开头的已存查询"); return 0
        fail = 0
        for q in hits:
            st, res = api(cfg, f"/api/v2/saved-queries/{q['id']}", token=tok, method="DELETE")
            if 200 <= st < 300: print(f"[-] 已删除: {q['name']}")
            else: fail += 1; print(f"[!] 删除失败 {q['name']}: HTTP {st} {json.dumps(res, ensure_ascii=False)[:120]}")
        print(f"完成: 删除 {len(hits) - fail} / 失败 {fail}")
        return 0 if fail == 0 else 1
    existing = {q["name"] for q in saved}
    queries = json.loads(QSET.read_text())["queries"]
    ok = skip = fail = 0
    for q in queries:
        if q["name"] in existing:
            skip += 1; continue
        st, res = api(cfg, "/api/v2/saved-queries/import",
                      {"name": q["name"], "query": q["query"], "description": q["description"]}, tok)
        if st in (200, 201): ok += 1; print(f"[+] {q['name']}")
        else: fail += 1; print(f"[-] {q['name']}: HTTP {st} {json.dumps(res)[:120]}")
    print(f"完成: 新增 {ok} / 已存在跳过 {skip} / 失败 {fail}")
    print("BloodHound 界面 → Analysis → Saved Queries 查看(刷新页面)")
    return 0 if fail == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
