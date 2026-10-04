#!/usr/bin/env bash
# netcheck.sh v2 — 网络质量检测(容错版)
set -uo pipefail
TARGET="${1:?用法: $0 <目标IP> [端口]}"
PORT="${2:-445}"

# 延迟测量(容错:丢包时回退 TCP);取 rtt min/avg/max/mdev 摘要中的 avg(第 2 段)
PING_OUT=$(ping -c 3 -W 3 "$TARGET" 2>&1 | tail -1)
RTT=$(echo "$PING_OUT" | awk -F'= ' '{print $2}' | awk -F'/' '{print $2}')
[ -z "$RTT" ] && RTT=999

# TCP 探测(容错;TARGET/PORT 走位置参数防注入,PORT 必须纯数字)
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "端口非法: $PORT"; exit 1; }
TCP="FAIL"
timeout 5 bash -c 'exec 3<>/dev/tcp/$1/$2' _ "$TARGET" "$PORT" 2>/dev/null && TCP="OK"

# 分类
if (( $(echo "$RTT < 5" | bc -l 2>/dev/null || echo 0) )); then
    Q="excellent"; L="直连(<5ms)"; M=1
elif (( $(echo "$RTT < 30" | bc -l 2>/dev/null || echo 0) )); then
    Q="good"; L="局域网(<30ms)"; M=2
elif (( $(echo "$RTT < 80" | bc -l 2>/dev/null || echo 0) )); then
    Q="fair"; L="VPN/远程(<80ms)"; M=3
else
    Q="poor"; L="高延迟(>80ms)⚠️"; M=5
fi

echo "延迟: ${RTT}ms | 质量: $Q ($L) | TCP/$PORT: $TCP | 超时倍数: ${M}x"

case "$Q" in
    excellent|good)
        echo "建议: 全部工具可用,标准超时" ;;
    fair)
        echo "建议: 读操作正常;写操作(LDAP/DCE RPC)加超时 30s+"; ;;
    poor)
        echo "⚠️ 高延迟环境:"
        echo "  ✅ 可用: nxc 指纹/认证、impacket 基础、hashcat"
        echo "  ⚠️ 慢: bloodhound-python、certipy find"
        echo "  ❌ 不可用: LDAP 写(RBCD)、DCE RPC(certipy req)、交互式 MSSQL"
        echo "  解法: ①直连 ②proxychains ③超时 x${M}" ;;
esac

echo "export NET_QUALITY=$Q NET_RTT=$RTT NET_TIMEOUT_MULT=$M"
