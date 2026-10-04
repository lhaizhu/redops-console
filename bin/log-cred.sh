#!/usr/bin/env bash
# log-cred.sh — 凭据台账一键登记(append 到 ~/tools/loot/creds.csv,无则建表头)
# 用法: log-cred.sh <类型:密码/NT哈希/票据> <主体> <域> <值> <来源> [已知权限]
# 示例: log-cred.sh NT哈希 'TEST\svc_sql' TEST.LOCAL 'aad3...:31d6...' '10.10.10.20 secretsdump' 'MSSQL服务账户'
set -euo pipefail
[ $# -lt 5 ] && { echo "用法: $0 <类型> <主体> <域> <值> <来源> [已知权限]"; exit 1; }
source "$(dirname "$(readlink -f "$0")")/lib/project.sh"
CSV="$(resolve_project || echo "$HOME/tools/loot")/creds.csv"
mkdir -p "$(dirname "$CSV")"
# 与 state.py/redops harvest 同一把 .state.lock:append 与 csv_mark_used 原子重写互斥,不丢行
LOCK="$(dirname "$CSV")/.state.lock"
(
    flock -x 9
    [ -f "$CSV" ] || echo "时间,类型,主体,域,值(密码/NT哈希/票据路径),来源,已知权限,用过没,备注" > "$CSV"
    # 用 python csv 模块正确加引号:字段含逗号/换行不再冲垮台账(report.sh 也按 csv 解析)
    python3 -c 'import csv,sys; csv.writer(sys.stdout).writerow(sys.argv[1:])' \
        "$(date '+%Y-%m-%d %H:%M')" "$1" "$2" "$3" "$4" "$5" "${6:-未知}" "未用" "" >> "$CSV"
) 9>"$LOCK"
echo "已登记($CSV 最后 1 行):"; tail -1 "$CSV"
