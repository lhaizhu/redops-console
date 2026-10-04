#!/usr/bin/env python3
"""build.py — 从 ~/tools/docs/*.md 提取结构化数据,注入模板生成自包含 index.html
用法: python3 build.py [docs_dir] [template] [output]
"""
import json, re, sys, pathlib

DOCS = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path.home() / "tools/docs")
TEMPLATE = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else pathlib.Path(__file__).parent / "template.html")
OUTPUT = pathlib.Path(sys.argv[3] if len(sys.argv) > 3 else pathlib.Path(__file__).parent / "index.html")

ORDER = ["01-信息收集", "02-Web渗透", "03-漏洞利用与C2", "04-密码攻击", "05-内网横向与AD",
         "06-隧道与代理", "07-权限提升", "08-无线与近源", "09-逆向与利用开发",
         "10-域渗透一条龙", "11-ADCS证书攻击", "12-Kerberos深度利用", "13-Windows落地工具箱",
         "14-MSSQL与域", "15-Exchange与ADFS", "16-域新打法", "17-Windows持久化", "18-钓鱼初始入口", "19-SCCM与MECM", "20-免杀与EDR对抗", "21-数据渗出与OPSEC", "22-域信任与跨林攻击", "23-vCenter与Veeam", "24-云身份与防护绕过", "25-多域作战流程", "26-凭据收割全家桶", "27-域内Linux与补充面", "28-自动化编排规划", "29-AI操作手册", "TRICKS", "CHEATSHEET-域渗透", "99-环境与代理配置"]

def split_note(s: str):
    """拆分命令与行内注释:仅当 # 在行首或前置空白、且不在单/双引号内时视为注释"""
    q = None
    for i, ch in enumerate(s):
        if q:
            if ch == q: q = None
        elif ch in ("'", '"'):
            q = ch
        elif ch == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i].rstrip(), s[i + 1:].strip()
    return s, ""

def parse_doc(path: pathlib.Path, text: str = None):
    text = path.read_text(encoding="utf-8") if text is None else text
    doc = {"file": path.name, "title": path.stem, "sections": []}
    # 顶层 # 标题后的一行说明
    m = re.search(r"^# (.+)$", text, re.M)
    if m: doc["title"] = m.group(1).strip()
    # 按 ## 切节
    parts = re.split(r"^## ", text, flags=re.M)
    for part in parts[1:]:
        lines = part.splitlines()
        head = lines[0].strip()
        body = lines[1:]
        src = next((l.replace("来源:", "").strip() for l in body[:3] if l.startswith("来源")), "")
        blocks = []          # (lang, [lines])
        cur = None
        for l in body:
            if l.startswith("```"):
                if cur is None: cur = [l[3:].strip() or "bash", []]
                else: blocks.append(cur); cur = None
            elif cur is not None: cur[1].append(l)
        if cur: blocks.append(cur)
        cmds = []
        for lang, blines in blocks:
            pending_note = ""
            for l in blines:
                s = l.strip()
                if not s:
                    pending_note = ""   # 空行隔断:注释不跨越空行附着到远处的命令
                    continue
                if s.startswith("#"):
                    pending_note = s.lstrip("# ").strip(); continue   # 连续注释块:后者覆盖前者
                cmd_part, inline = split_note(s)
                note = inline or pending_note; pending_note = ""
                if cmd_part: cmds.append({"c": cmd_part, "n": note, "lang": lang or "bash"})
        doc["sections"].append({"h": head, "src": src, "cmds": cmds})
    return doc

def parse_matrix(text: str):
    idx = text.find("场景适配矩阵")
    if idx < 0: return []
    rows = []
    for line in text[idx:].splitlines():
        if not line.startswith("|"): continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if set("".join(cells)) <= set("-|: "): continue      # 分隔行
        if len(cells) >= 5: rows.append(cells[:5])
    return rows[1:]                                           # 去表头

def main():
    docs, matrix, stages = [], [], []
    for name in ORDER:
        p = DOCS / f"{name}.md"
        if not p.exists():
            print(f"[!] ORDER 中的文档不存在,已跳过: {p}", file=sys.stderr)
            continue
        text = p.read_text(encoding="utf-8")
        docs.append(parse_doc(p, text))
        if name == "10-域渗透一条龙":
            matrix = parse_matrix(text)
            for part in re.split(r"^## ", text, flags=re.M)[1:]:
                h = part.splitlines()[0].strip()
                if h.startswith(("阶段", "失败回退", "凭据台账", "手工 → C2")):
                    stages.append(h)
    data = {"docs": docs, "matrix": matrix, "stages": stages, "built": __import__("time").strftime("%Y-%m-%d %H:%M")}
    tpl = TEMPLATE.read_text(encoding="utf-8")
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    OUTPUT.write_text(tpl.replace("__DATA__", payload), encoding="utf-8")
    total = sum(len(s["cmds"]) for d in docs for s in d["sections"])
    print(f"[+] {OUTPUT}  文档 {len(docs)} 个 / 小节 {sum(len(d['sections']) for d in docs)} / 命令 {total} 条 / 矩阵 {len(matrix)} 行")

if __name__ == "__main__":
    main()
