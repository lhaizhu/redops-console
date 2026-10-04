#!/usr/bin/env bash
# persist-audit.sh — 持久化检测面只读审计(四条 nxc ldap --query 自定义查询,无任何写):
#   ① (adminCount=1)                    → AdminSDHolder 保护对象(孤儿账户=经典后门)
#   ② (msDS-KeyCredentialLink=*)        → 影子凭据残留
#   ③ UAC:1.2.840.113556.1.4.803:=524288 → 非约束委派(TRUSTED_FOR_DELEGATION)
#   ④ krbtgt 的 pwdLastSet              → 金票检测面(久远未重置=历史金票仍有效)
# 用法: PROJ_DIR=~/tools/projects/<名> persist-audit.sh <DC IP> <域名> <用户> <密码> [--proxy]
# 输出: 逐节计数+主体明细;尾部 PERSIST-AUDIT: 汇总行供 redops 收割;结果落 <项目>/loot/persist-audit-<时间戳>.txt
set -uo pipefail
source "$(dirname "$(readlink -f "$0")")/lib/state.sh"   # 自带 project.sh:resolve_project / state_*

[ $# -ge 4 ] || { echo "用法: $0 <DC IP> <域名> <用户> <密码> [--proxy]"; exit 1; }
DCIP="$1"; DOM="$2"; U="$3"; PW="$4"
P=""; [ "${5:-}" = "--proxy" ] && P="proxychains4 -q"
command -v nxc >/dev/null || { echo "nxc 未安装(netexec)"; exit 1; }

PROJ=$(resolve_project)
TS=$(date '+%Y%m%d-%H%M%S')
if [ -n "$PROJ" ]; then OUT="$PROJ/loot/persist-audit-$TS.txt"; else OUT="$(mktmpdir persist-audit)/persist-audit-$TS.txt"; fi

# q <filter> <属性列表> — 一条只读 LDAP 自定义查询;不可达/拒登回空串(fail-safe,计数落 0)
q() { $P nxc ldap "$DCIP" -u "$U" -p "$PW" -d "$DOM" --query "$1" "$2" 2>/dev/null; }

> "$OUT"
echo "== 持久化检测面审计 $DOM @ $DCIP $(date '+%F %T') ==" | tee -a "$OUT"

# sec <编号标题> <filter> <attrs> — 打印计数+原始应答+主体行,全局变量 SEC_N 回传计数
sec() {
    local title="$1" filt="$2" attrs="$3" res
    res=$(q "$filt" "$attrs")
    SEC_N=$(printf '%s\n' "$res" | grep -c 'Response for object:' || true)
    echo "--- $title: $SEC_N 条 ---" | tee -a "$OUT"
    if [ "$SEC_N" -gt 0 ]; then
        printf '%s\n' "$res" | grep -E 'Response for object:|sAMAccountName|dNSHostName|KeyCredentialLink|pwdLastSet' | sed 's/^/  /' | tee -a "$OUT"
    else
        echo "  (无命中或查询失败)" | tee -a "$OUT"
    fi
}

sec "① AdminSDHolder 保护对象 (adminCount=1)" '(adminCount=1)' 'sAMAccountName';            N1=$SEC_N
sec "② 影子凭据残留 (msDS-KeyCredentialLink=*)" '(msDS-KeyCredentialLink=*)' 'sAMAccountName msDS-KeyCredentialLink'; N2=$SEC_N
sec "③ 非约束委派 (UAC 524288)" '(userAccountControl:1.2.840.113556.1.4.803:=524288)' 'sAMAccountName dNSHostName'; N3=$SEC_N

R4=$(q '(sAMAccountName=krbtgt)' 'sAMAccountName pwdLastSet')
PLS=$(printf '%s\n' "$R4" | awk '/pwdLastSet/{print $NF; exit}')
KR="unknown"
if [[ "${PLS:-}" =~ ^[0-9]+$ ]] && [ "$PLS" != "0" ]; then
    KR=$(date -d "@$(( PLS / 10000000 - 11644473600 ))" '+%F_%T' 2>/dev/null || echo "unknown")
fi
echo "--- ④ krbtgt pwdLastSet: $KR (原始值 ${PLS:-无};久远未动=历史金票仍有效,作废需 24h 内重置两次) ---" | tee -a "$OUT"

echo | tee -a "$OUT"
echo "PERSIST-AUDIT: sdholder=$N1 shadow=$N2 unconstrained=$N3 krbtgt_pwdlastset=$KR" | tee -a "$OUT"
echo "产出: $OUT"
state_phase_mark persist-audit "$OUT"
echo "解读:① 不在特权组却 adminCount=1 的孤儿账户是后门(12号⑪节);② >0 自动登记中危 finding;③ 非约束委派主机可截高权 TGT;④ 金票检测面见 17 号§9。"
