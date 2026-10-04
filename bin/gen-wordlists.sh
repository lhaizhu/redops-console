#!/usr/bin/env bash
# gen-wordlists.sh — 从项目档案生成喷洒字典(users.txt + 公司变体密码本)
# 用法: PROJ_DIR=~/tools/projects/<名> gen-wordlists.sh   (或全局模式给域名)
set -euo pipefail
source "$(dirname "$(readlink -f "$0")")/lib/project.sh"
source "$(dirname "$(readlink -f "$0")")/lib/recon.sh"
PROJ=$(resolve_project || true)
if [ -n "$PROJ" ] && [ -f "$PROJ/project.json" ]; then
    DOMAIN=$(python3 -c "import json;print(json.load(open('$PROJ/project.json')).get('domain',''))")
    OUT="$PROJ"
else
    DOMAIN="${1:-}"; [ -z "$DOMAIN" ] && { echo "用法: PROJ_DIR=项目目录 $0  或  $0 <域名>"; exit 1; }
    OUT="."; mkdir -p "$OUT"
fi
COMPANY=$(company_root "$DOMAIN")   # test.local → Test
echo "[*] 项目域: $DOMAIN → 公司词根: $COMPANY"

# ① 密码变体:公司词根 × 年季 × 常见后缀
seasonal_passwords "$COMPANY" "$OUT"

# ② users.txt:汇聚项目内散落的用户名(nxc --users / ad-sweep 产物)
if [ -d "$OUT/loot" ]; then
    find "$OUT/loot" -name 'users*.txt' -o -name '*_users.txt' 2>/dev/null | while read -r f; do
        grep -oE '^[a-zA-Z0-9._-]{3,32}$' "$f" 2>/dev/null
    done | sort -u > "$OUT/users.txt"
else
    : > "$OUT/users.txt"   # 新项目尚无 loot,建空表
fi
echo "  users.txt: $(wc -l < "$OUT/users.txt") 个用户名(来源:loot 内 users*.txt)"
echo "[*] 喷洒:~/tools/bin/spray-safe.sh <DC> $OUT/users.txt [验证用户] [密码] 或执行台「OWA 喷洒/spray-safe」"
