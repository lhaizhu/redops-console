#!/usr/bin/env bash
# trust-map.sh — 多域信任拓扑一键测绘:遍历项目全部域,枚举信任,产出拓扑图(文本+mermaid)入项目
# 用法: PROJ_DIR=~/tools/projects/<名> trust-map.sh <用户> <密码>   (用户/密码为任一域有效凭据)
set -uo pipefail
source "$(dirname "$(readlink -f "$0")")/lib/project.sh"
PROJ=$(resolve_project)
[ -z "$PROJ" ] && { echo "需项目上下文:PROJ_DIR=... $0 <用户> <密码>"; exit 1; }
U="${1:-}"; P="${2:-}"; [ -z "$U" ] && { echo "用法: $0 <用户> <密码>"; exit 1; }

DOMAINS=$(python3 - "$PROJ" <<'PY' 2>/dev/null
import json, sys
d = json.load(open(sys.argv[1] + '/project.json'))
print('\n'.join(f"{x['name']}|{x.get('dcip','')}" for x in d.get('domains', []) if x.get('name')))
PY
)
[ -z "$DOMAINS" ] && { echo "项目无域档案(看板「＋ 添加域」)"; exit 1; }

OUT="$PROJ/trust-map.txt"; MMD="$PROJ/trust-map.mmd"; > "$OUT"; echo "graph LR" > "$MMD"
echo "== 信任拓扑测绘 $(date '+%H:%M') ==" | tee -a "$OUT"

while IFS='|' read -r DOM DCIP; do
    [ -z "$DOM" ] && continue
    echo "--- 域: $DOM (DC: ${DCIP:-?}) ---" | tee -a "$OUT"
    # -y 从文件读密码(进程替换),避免出现在 ps 的 argv 里;-o ldif-wrap=no 防长行折行破坏 awk 记录解析
    RES=$(ldapsearch -o nettimeout=8 -o ldif-wrap=no -LLL -x -H "ldap://${DCIP:-$DOM}" -D "$U@$DOM" -y <(printf '%s' "$P") \
        -b "CN=System,$(echo $DOM | awk -F. '{dn="";for(i=1;i<=NF;i++)dn=dn",DC="$i;print substr(dn,2)}')" \
        '(objectClass=trustedDomain)' cn trustDirection trustType trustAttributes 2>/dev/null | grep -E '^(dn|cn|trustDirection|trustAttributes):|^$' )
    if [ -z "$RES" ]; then echo "  (不可达或无信任/匿名拒绝)" | tee -a "$OUT"; continue; fi
    # mermaid 边(方向:1=入 2=出 3=双向)
    echo "$RES" | awk -v src="$DOM" '
        /^cn:/ { dst=$2 }
        /^trustDirection:/ { dir=$2 }
        /^$/ { if(dst!=""){ d=""; if(dir=="2")d="-->"; else if(dir=="1")d="<--"; else d="<-->";
               printf "  %s[\"%s\"] %s %s[\"%s\"]\n", src, src, d, dst, dst; dst=""; } }
        END { if(dst!=""){ d=""; if(dir=="2")d="-->"; else if(dir=="1")d="<--"; else d="<-->";
              printf "  %s[\"%s\"] %s %s[\"%s\"]\n", src, src, d, dst, dst; } }' >> "$MMD"
    echo >> "$MMD"
done <<< "$DOMAINS"

echo | tee -a "$OUT"
echo "== 拓扑图(mermaid,渲染:console 8080 或 mermaid.live)==" | tee -a "$OUT"
cat "$MMD" | tee -a "$OUT"
echo "产出: $OUT / $MMD"
echo "决策提示:双向/出站信任=可从该域打对端;TGT(信任账户)用于 22 号跨域伪造。"
