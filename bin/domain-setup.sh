#!/usr/bin/env bash
# domain-setup.sh — 域渗透接入准备一条命令:对时 + DNS + krb5.conf + 可选 kinit
# 用法: sudo domain-setup.sh <域名> <域控IP> [域控FQDN] [用户] [密码]
# 示例: sudo domain-setup.sh test.local 10.10.10.10 dc01.test.local jsmith 'Passw0rd!'
set -euo pipefail

usage() { echo "用法: sudo $0 <域名> <域控IP> [域控FQDN] [用户] [密码]"; exit 1; }
[ $# -lt 2 ] && usage
DOMAIN="$1"; DCIP="$2"; DCFQDN="${3:-}"; USER="${4:-}"; PASS="${5:-}"
REALM=$(echo "$DOMAIN" | tr 'a-z' 'A-Z')
[ -z "$DCFQDN" ] && DCFQDN="$DCIP"
[ "$(id -u)" -ne 0 ] && exec sudo -- "$0" "$@"

echo "[1/4] 时间同步到 $DCIP ..."
timeout 15 chronyd -q "server $DCIP iburst" >/dev/null 2>&1 || echo "  [!] chronyd 同步失败/超时(15s),检查 DC 是否放行 NTP(UDP 123)"; timedatectl | grep -E 'Local time|synchronized' || true

echo "[2/4] DNS 指向 $DCIP ..."
if command -v resolvectl >/dev/null 2>&1 && resolvectl status >/dev/null 2>&1; then
    IFACE=$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')
    resolvectl dns "${IFACE:-eth0}" "$DCIP" && echo "  resolvectl 已设置(接口 ${IFACE:-eth0})"
else
    sed -i "1i nameserver $DCIP" /etc/resolv.conf && echo "  /etc/resolv.conf 已置顶 nameserver $DCIP"
fi

# /etc/hosts 兜底(DNS 经 VPN 时 resolvectl 未必生效;BH/krb5 全靠 FQDN 可解)
grep -qF "$DCFQDN" /etc/hosts 2>/dev/null || { echo "$DCIP $DCFQDN $DOMAIN" >> /etc/hosts; echo "  /etc/hosts 已加 $DCFQDN"; }

echo "[3/4] /etc/krb5.conf 写入 realm $REALM ..."
if grep -qF "$REALM = {" /etc/krb5.conf 2>/dev/null; then
    echo "  已存在,跳过"
elif grep -q '^\[realms\]' /etc/krb5.conf 2>/dev/null; then
    # 已有 [realms] 段:插入段内而不是追加重复段头(krb5 不合并同名段)
    T=$(mktemp)
    awk -v realm="$REALM" -v dom="$DOMAIN" -v kdc="$DCFQDN" '
        /^\[realms\]/ && !r { print; print realm " = {\n    kdc = " kdc "\n    admin_server = " kdc "\n}"; r=1; next }
        /^\[domain_realm\]/ && !d { print; print "." dom " = " realm "\n" dom " = " realm; d=1; next }
        { print }
        END { if(!d) print "\n[domain_realm]\n." dom " = " realm "\n" dom " = " realm }
    ' /etc/krb5.conf > "$T" && cat "$T" > /etc/krb5.conf && rm -f "$T"
    echo "  已插入现有 [realms] 段(kdc = $DCFQDN)"
else
    cat >> /etc/krb5.conf <<EOF

# --- added by domain-setup.sh ---
[realms]
$REALM = {
    kdc = $DCFQDN
    admin_server = $DCFQDN
}
[domain_realm]
.$DOMAIN = $REALM
$DOMAIN = $REALM
EOF
    echo "  已写入(kdc = $DCFQDN)"
fi

echo "[4/4] 验证 ..."
if [ -n "$USER" ] && [ -n "$PASS" ]; then
    echo "$PASS" | timeout 20 kinit "$USER@$REALM" >/dev/null 2>&1 && echo "  kinit OK" || echo "  [!] kinit 失败/超时(检查时间偏移/密码/UPN 后缀)"
    klist 2>/dev/null | head -5 || true
else
    getent hosts "$DCFQDN" >/dev/null 2>&1 && echo "  DNS 解析 $DCFQDN OK" || echo "  [!] $DCFQDN 解析失败"
fi
echo "完成。下一步:~/tools/bin/ad-sweep.sh 或直接看 ~/tools/docs/10-域渗透一条龙.md"
