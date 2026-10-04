#!/usr/bin/env python3
"""check-refs.py — 引用一致性审计:
1) tools.json/chains.json 的 doc 字段("16 §1"/"10 §1.5")→ 检查文档存在且小节匹配
2) cmd 首词二进制存在性(等价 redops 启动 warn,供提交前手跑)
用法: python3 check-refs.py   退出码 0=全绿
"""
import json, re, shutil, sys, os
from pathlib import Path
os.environ["PATH"] = os.path.expanduser("~/tools/bin") + ":" + os.path.expanduser("~/.local/bin") + ":" + os.environ.get("PATH", "")

BASE = Path(__file__).resolve().parent.parent / "redops" / "web"
DOCS = BASE.parent.parent / "docs"
issues = []

def load(p): return json.loads((BASE / p).read_text(encoding="utf-8"))

def doc_sections(stem):
    """返回按序的 ## 顶级小节标题;含 ### N.M 子节编号"""
    secs = []
    for m in re.finditer(r"^(##|###) +(.+)$", (DOCS / (stem + ".md")).read_text(errors="ignore"), re.M):
        if m.group(1) == "##": secs.append(m.group(2).strip())
        elif re.match(r"^\d", m.group(2)): secs.append(m.group(2).strip())   # "1.5 密码喷洒"
    return secs
# ① doc 引用 → 文档小节
heads = {}   # docname → set(section keywords)
for f in DOCS.glob("*.md"):
    hs = set()
    for m in re.finditer(r"^#{2,3} +(.+)$", f.read_text(errors="ignore"), re.M):
        hs.add(m.group(1).strip())
    heads[f.stem] = hs

def check_doc(ref, src):
    if not ref: return
    m = re.match(r"^(\d+[^ ]*|TRICKS|CHEATSHEET[^ ]*|99)[^§]*(?:§\s*([0-9.]+))?", ref)
    if not m: return
    num = m.group(1).rstrip(".")
    doc = next((k for k in heads if re.match(r"^" + re.escape(num) + r"\b", k)), None)
    if not doc:
        issues.append(f"[缺文档] {src}: {ref}"); return
    if m.group(2):
        want = m.group(2).rstrip(".")
        secs = doc_sections(doc)
        ok = any(s.startswith(want + " ") or s.startswith(want + "、") or s.startswith(want + "(") or s == want
                 or re.match(r"^" + re.escape(want) + r"[ .、(]", s) for s in secs)
        # §N 也接受第 N 个 ## 节
        try:
            ok = ok or (1 <= int(float(want)) <= len(secs))
        except Exception:
            pass
        if not ok:
            issues.append(f"[节漂移] {src}: {ref} → {doc} 无该小节")

for t in load("tools.json")["tools"]:
    check_doc(t.get("doc", ""), f"tool:{t['id']}")
# (chains.json 步骤无 doc 引用,无需遍历)

# ② 二进制存在
SHELL_KW = {"for","if","while","echo","export","cd","sudo","bash","python3","[","xargs"}
for t in load("tools.json")["tools"]:
    cmd = t["cmd"].replace("~", str(Path.home()))
    cmd = cmd.replace("PROJ_DIR=${PROJ_DIR:-} ", "").replace("PROJ_DIR=${PROJ_DIR:-$HOME/tools/projects/default} ", "")
    # 跳过行首 VAR=val 赋值前缀(与引擎 warn-check 同约定;VAR=$(...) 含空格时整段到分号为止)
    rest = cmd.strip()
    while re.match(r"^[A-Za-z_]\w*=", rest):
        if re.match(r"^[A-Za-z_]\w*=\$\(", rest):
            _, _, rest = rest.partition(";")   # VAR=$(...) ; 整段跳过
        else:
            rest = rest.split(None, 1)[1] if " " in rest else ""
        rest = rest.strip()
    first = rest.split(None, 1)[0] if rest else ""
    if "/" in first or shutil.which(first) or first in SHELL_KW:
        continue
    issues.append(f"[缺二进制] tool:{t['id']}: {first}")

print(f"审计完成: {len(issues)} 个问题" if issues else "审计完成: 全绿 ✓")
for i in issues: print(" ", i)
sys.exit(1 if issues else 0)
