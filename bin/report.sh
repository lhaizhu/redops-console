#!/usr/bin/env bash
# report.sh — 从项目目录一键生成交付报告(Markdown + 自包含 HTML)
# 用法: ~/tools/bin/report.sh [项目名](缺省取活跃项目)
set -euo pipefail
source "$(dirname "$(readlink -f "$0")")/lib/project.sh"
P="${1:+$HOME/tools/projects/$1}"
[ -z "$P" ] && P=$(resolve_project || true)
[ -z "$P" ] && { echo "用法: $0 [项目名]  (缺省:projects/active.json 活跃项目)"; exit 1; }
[ -d "$P" ] || { echo "项目不存在: $P"; exit 1; }

# state.py 绝对路径必须在 cd 之前解析:相对路径调用(report.sh GOAD)时 cd 后 $0 解析失效
STATE="$(dirname "$(readlink -f "$0")")/state.py"
export STATE
cd "$P"

RUNS=$(ls -1 loot/runs 2>/dev/null | grep -vc '^history' || true)
CREDS=$( [ -f creds.csv ] && tail -n +2 creds.csv | grep -c . || echo 0 )
DOMAIN=$(python3 -c "import json;print(json.load(open('project.json')).get('domain',''))" 2>/dev/null || echo "")
TS=$(date '+%Y-%m-%d %H:%M')


FINDINGS_MD=$(python3 - 2>/dev/null <<'PYF' || echo '- 暂无 findings'
import json, os, subprocess
sev_rank = {"高": 0, "中": 1, "低": 2}
fs = []
if os.path.exists("state.json"):
    try:
        r = subprocess.run(["python3", os.environ["STATE"], ".", "finding", "list"],
                           capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            fs = json.loads(r.stdout)
    except Exception:
        fs = []
if not fs:
    print("- 暂无 findings")
else:
    fs.sort(key=lambda f: (sev_rank.get(f.get("severity", ""), 9), f.get("ts", "")))
    for f in fs:
        host = f.get("host") or "-"
        print(f"- [{f.get('severity', '?')}] {f.get('title', '')} — {host} `{f.get('evidence', '')}` ({f.get('ts', '')})")
PYF
)

HOSTS_MD=$(python3 - 2>/dev/null <<'PYH' || echo '- 暂无主机信息'
import json, os, subprocess
hs = {}
if os.path.exists("state.json"):
    try:
        r = subprocess.run(["python3", os.environ["STATE"], ".", "host", "list"],
                           capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            hs = json.loads(r.stdout)
    except Exception:
        hs = {}
if not hs:
    print("- 暂无主机信息")
else:
    def ipkey(ip):
        return tuple((0, int(p)) if p.isdigit() else (1, p) for p in str(ip).split("."))
    for ip in sorted(hs, key=ipkey):
        h = hs[ip] or {}
        sv = h.get("services") or []
        print(f"### {ip}")
        print(f"- 角色:{h.get('role') or '-'}")
        print(f"- 系统:{h.get('os') or '-'}")
        print(f"- 服务:{','.join(str(x) for x in sv) if sv else '-'}")
        print(f"- 状态:{'👑 已拿下' if h.get('owned') else '未拿下'}")
        print(f"- 首次发现:{h.get('first_seen') or '-'}")
        if h.get("owned_ts"):
            print(f"- 拿下时间:{h['owned_ts']}")
        print()
PYH
)

cat > report.md <<EOF
# 渗透测试报告 — $(basename "$P")

- 生成时间:$TS
- 目标域:$DOMAIN
- 执行次数:$RUNS · 收割凭据:$CREDS 条

## 一、项目档案
\`\`\`json
$(cat project.json 2>/dev/null || echo '{}')
\`\`\`

## 二、攻击时间线(notes.md 全量)

$(cat notes.md 2>/dev/null || echo '(无)')

## 三、Findings 发现(按严重度排序,证据链见 state.json)

$FINDINGS_MD

## 四、凭据台账(${CREDS} 条,值已截断)
\`\`\`
$( [ -s creds.csv ] && python3 -c "
import csv
for r in list(csv.reader(open('creds.csv')))[1:]:
    r += [''] * (9 - len(r))
    print(' | '.join([r[0], r[1], r[2], r[4][:16] + '…', r[6]]))" || echo '(空)')
\`\`\`

## 五、主机清单

$HOSTS_MD

## 六、攻击覆盖矩阵(按执行历史推断)

$(python3 - <<'PYC'
import json, pathlib
hj = pathlib.Path("loot/runs/history.jsonl")
used = set()
if hj.exists():
    for l in hj.read_text(errors="ignore").splitlines():
        try: used.add(json.loads(l).get("id",""))
        except Exception: pass
tj = pathlib.Path.home()/ "tools/redops/web/tools.json"
stages = {}
if tj.exists():
    for t in json.loads(tj.read_text())["tools"]:
        stages.setdefault(t["stage"], []).append(t["id"])
for st, ids in stages.items():
    u = sum(1 for i in ids if i in used)
    bar = "█" * int(u * 10 / max(1,len(ids))) + "░" * (10 - int(u * 10 / max(1,len(ids))))
    print(f"- {st}:已用 {u}/{len(ids)} {bar} {u*100//max(1,len(ids))}%")
PYC
)

## 七、执行产物索引
\`\`\`
$(ls -1 loot/runs 2>/dev/null | grep -v '^history' || echo '(空)')
\`\`\`
EOF

# HTML 版(转义 + 内联样式,可直接发客户)
python3 - <<'PYEOF'
import html, pathlib
md = pathlib.Path("report.md").read_text(encoding="utf-8")
# (标题/列表由下方循环渲染)
lines = md.splitlines(); out = []
for l in lines:
    e = html.escape(l)
    if l.startswith("# "): out.append(f"<h2 style='font-family:sans-serif'>{e[2:]}</h2>")
    elif l.startswith("## "): out.append(f"<h3 style='font-family:sans-serif;color:#445'>{e[3:]}</h3>")
    elif l.startswith("### "): out.append(f"<h4 style='font-family:sans-serif;color:#668'>{e[4:]}</h4>")
    elif l.startswith("- "): out.append(f"<li>{e[2:]}</li>")
    else: out.append(f"<p style='margin:6px 0;font-family:sans-serif'>{e}</p>")
doc = f"""<!DOCTYPE html><html lang=zh><meta charset=utf-8><title>渗透测试报告</title>
<body style='background:#f6f7f9;margin:0;padding:32px'><div style='max-width:860px;margin:auto;background:#fff;border-radius:12px;padding:36px;box-shadow:0 2px 10px #0002'>
{''.join(out)}</div></body></html>"""
pathlib.Path("report.html").write_text(doc, encoding="utf-8")
print("report.html OK")
PYEOF

echo "生成完成: $P/report.md / report.html"
