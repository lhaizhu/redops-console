# state.sh — bin/state.py 的薄封装:交战状态机(tried/phase/cred)
# 用法: source .../lib/state.sh(自动带上 project.sh)
# 项目不可解析(PROJ_DIR/active.json 都没有)时所有 helper 静默 no-op:
#   check → 返回 1(视为未完成,照常执行);mark/写 → 返回 0(假装成功);artifact → 空行
# 这样全局(无项目)模式行为完全不变,state 问题永不搞挂交战流程。
source "$(dirname "${BASH_SOURCE[0]}")/project.sh"

STATE_PY="$(dirname "${BASH_SOURCE[0]}")/../state.py"

# _state_proj — 回显项目目录;不可解析或 state.py 缺失 → 返回 1(调用方决定 no-op 语义)
_state_proj() {
    local proj
    proj=$(resolve_project) || return 1
    [ -n "$proj" ] && [ -f "$STATE_PY" ] && echo "$proj"
}

# state_tried_check <key> — 该 key 已记录 rc==0 → 返回 0
state_tried_check() {
    local p; p=$(_state_proj) || return 1
    python3 "$STATE_PY" "$p" tried check "$1" 2>/dev/null
}
# state_tried_mark <key> <rc> — 记录尝试结果(失败也返回 0)
state_tried_mark() {
    local p; p=$(_state_proj) || return 0
    python3 "$STATE_PY" "$p" tried mark "$1" "$2" >/dev/null 2>&1 || true
}
# state_phase_check <name> — 相位已完成 → 返回 0
state_phase_check() {
    local p; p=$(_state_proj) || return 1
    python3 "$STATE_PY" "$p" phase check "$1" 2>/dev/null
}
# state_phase_mark <name> [artifact] — 标记相位完成+产物路径(失败也返回 0)
state_phase_mark() {
    local p; p=$(_state_proj) || return 0
    python3 "$STATE_PY" "$p" phase mark "$@" >/dev/null 2>&1 || true
}
# state_phase_artifact <name> — 打印产物路径(无则空行)
state_phase_artifact() {
    local p; p=$(_state_proj) || { echo; return 0; }
    python3 "$STATE_PY" "$p" phase artifact "$1" 2>/dev/null || true
}
# state_cred_use <needle> — 凭据标记已用(state.json used=true + creds.csv 用过没→已用)
state_cred_use() {
    local p; p=$(_state_proj) || return 0
    python3 "$STATE_PY" "$p" cred use "$1" 2>/dev/null || true
}
# state_cred_verify <主体> <host> — valid_for += host
state_cred_verify() {
    local p; p=$(_state_proj) || return 0
    python3 "$STATE_PY" "$p" cred verify "$1" "$2" >/dev/null 2>&1 || true
}
# state_cred_add <类型> <主体> <域> <来源> [值原文] — 去重登记(值不落盘,state 只存 sha256 指纹)
state_cred_add() {
    local p; p=$(_state_proj) || return 0
    python3 "$STATE_PY" "$p" cred add "$@" >/dev/null 2>&1 || true
}
# state_host_add <ip> [k=v ...] — 主机清单登记(role/os;services 逗号分隔合并去重)
state_host_add() {
    local p; p=$(_state_proj) || return 0
    python3 "$STATE_PY" "$p" host add "$@" >/dev/null 2>&1 || true
}
# state_host_owned <ip> — 标记主机已拿下
state_host_owned() {
    local p; p=$(_state_proj) || return 0
    python3 "$STATE_PY" "$p" host owned "$1" >/dev/null 2>&1 || true
}
# state_finding_add <标题> <严重度> <证据> [主机] — 发现登记(按 标题+主机 去重)
state_finding_add() {
    local p; p=$(_state_proj) || return 0
    python3 "$STATE_PY" "$p" finding add "$@" >/dev/null 2>&1 || true
}
