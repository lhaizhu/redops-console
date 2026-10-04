#!/usr/bin/env bash
# crack-sync.sh — hashcat 破解结果回台账:遍历 hashqueue.txt,逐条 hashcat --show 查 potfile,
#   命中 → cred_log + state_cred_add 登记并从队列移除;全程 state 调用 fail-safe。
# 用法: crack-sync.sh(队列: <项目>/hashqueue.txt,无项目回落 ~/tools/loot/hashqueue.txt)
# 哈希类型识别: $krb5asrep$* → 18200 / $krb5tgs$* → 13100 / 含 '::' (NetNTLMv2) → 5600
set -uo pipefail
source "$(dirname "$(readlink -f "$0")")/lib/project.sh"
source "$(dirname "$(readlink -f "$0")")/lib/state.sh"

command -v hashcat >/dev/null 2>&1 || { no "未找到 hashcat,无法查询破解结果"; exit 1; }

PROJ=$(resolve_project || echo "$HOME/tools/loot")
HQ="$PROJ/hashqueue.txt"
LOCK="$PROJ/.state.lock"   # 与 state.py/redops harvest 同一把锁
if [ ! -s "$HQ" ]; then
    ok "队列为空: $HQ"
    echo "汇总: 0 队列 / 0 已破 / 0 新增凭据"
    exit 0
fi

# 快照队列(锁内只读,立即放锁):后续 hashcat --show / cred_log 不持锁(cred_log 自取同一把锁,持锁调用会死锁)
exec 9>"$LOCK"
flock -x 9
mapfile -t HQLINES < "$HQ"
flock -u 9

# crack_parse <哈希行> — 回显「mode<TAB>主体<TAB>域」(识别不出 → 返回 1)
crack_parse() {
    local h="$1" rest user dom
    case "$h" in
        '$krb5asrep$'*)
            rest="${h#\$krb5asrep\$23\$}"          # USER@DOMAIN:checksum(无 @ 时域留空)
            user="${rest%%@*}"
            if [ "$user" != "$rest" ]; then dom="${rest#*@}"; dom="${dom%%:*}"; else dom=""; fi
            [ -n "$user" ] || return 1
            printf '18200\t%s\t%s\n' "$user" "$dom" ;;
        '$krb5tgs$'*)
            rest="${h#\$krb5tgs\$23\$\*}"          # USER$DOMAIN$REALM/SPN$checksum
            user="${rest%%\$*}"; rest="${rest#*\$}"; dom="${rest%%\$*}"
            [ -n "$user" ] && [ -n "$dom" ] || return 1
            printf '13100\t%s\t%s\n' "$user" "$dom" ;;
        *::*)
            user="${h%%::*}"; rest="${h#*::}"; dom="${rest%%:*}"   # USER::DOMAIN:...
            [ -n "$user" ] || return 1
            printf '5600\t%s\t%s\n' "$user" "$dom" ;;
        *) return 1 ;;
    esac
}

TOTAL=0; CRACKED=0; ADDED=0; SKIP=0
CRACKED_LINES=()
for h in "${HQLINES[@]}"; do
    h="${h%$'\r'}"; [ -z "$h" ] && continue
    TOTAL=$((TOTAL+1))
    if ! info=$(crack_parse "$h"); then
        go "类型未识别,保留队列: ${h:0:40}…"; SKIP=$((SKIP+1)); continue
    fi
    mode="${info%%	*}"; info="${info#*	}"
    user="${info%%	*}"; dom="${info#*	}"
    out=$(hashcat --show -m "$mode" -- "$h" 2>/dev/null || true)
    # john 兜底:无 GPU/OpenCL 的 VM 里 hashcat 起不来(--show 只读 potfile 仍可用,先试它)
    if [ -z "$out" ] && command -v john >/dev/null 2>&1; then
        JF=""; case "$mode" in 18200) JF=krb5asrep;; 13100) JF=krb5tgs;; 5600) JF=netntlmv2;; esac
        if [ -n "$JF" ]; then
            JTMP=$(mktemp); printf '%s\n' "$h" > "$JTMP"
            jline=$(john --show --format="$JF" "$JTMP" 2>/dev/null | grep ':' | head -1); rm -f "$JTMP"
            [ -n "$jline" ] && out="$h:${jline#*:}"
        fi
    fi
    case "$out" in
        "$h:"?*) ;;
        *) continue ;;   # 未破出,保留队列
    esac
    plain="${out#"$h:"}"
    CRACKED=$((CRACKED+1))
    CRACKED_LINES+=("$h")
    if [ -n "$dom" ]; then subj="$dom\\$user"; else subj="$user"; fi
    cred_log 密码 "$subj" "$dom" "$plain" "hashcat 爆破" && ADDED=$((ADDED+1))
    state_cred_add 密码 "$subj" "$dom" "hashcat" "$plain"
    ok "已破: ${subj//\\/\\\\} → 台账+state 登记,移出队列"
done

# 有破解成果才重写队列(锁内仅从当前文件剔除已破行:处理期间并发追加的新行原样保留,不丢哈希)
if [ "$CRACKED" -gt 0 ]; then
    TMP=$(mktemp)
    flock -x 9
    printf '%s\n' "${CRACKED_LINES[@]}" | grep -vxF -f - "$HQ" > "$TMP" || true
    mv "$TMP" "$HQ"
    flock -u 9
fi
exec 9>&-
echo "汇总: $TOTAL 队列 / $CRACKED 已破 / $ADDED 新增凭据"
