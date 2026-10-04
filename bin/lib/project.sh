# project.sh — 项目上下文解析(PROJ_DIR 约定:projects/<名>,活跃项目见 projects/active.json)
# 用法: source .../lib/project.sh 后  PROJ_DIR=$(resolve_project)
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# resolve_project — 回显项目目录:PROJ_DIR 优先,其次 active.json 的活跃项目;无法解析时静默返回 1
resolve_project() {
    local proj="${PROJ_DIR:-}"
    [ -z "$proj" ] && [ -f "$HOME/tools/projects/active.json" ] && \
        proj="$HOME/tools/projects/$(python3 -c "import json;print(json.load(open('$HOME/tools/projects/active.json'))['name'])" 2>/dev/null)"
    [ -n "$proj" ] && echo "$proj"
}

# ─── 项目持久化助手(autopwn 等编排脚本用;无项目时静默跳过) ───

# cred_log <类型> <主体> <域> <值> <来源> [已知权限] — 凭据台账登记(log-cred.sh 包装)
# 无活跃项目时 log-cred.sh 自带 ~/tools/loot 兜底;脚本缺失仅告警一次,不中断主流程
CRED_LOG_WARNED=""
cred_log() {
    local lc="$(dirname "${BASH_SOURCE[0]}")/../log-cred.sh"
    if [ ! -x "$lc" ]; then
        [ -z "$CRED_LOG_WARNED" ] && { no "log-cred.sh 缺失,凭据仅留在临时目录"; CRED_LOG_WARNED=1; }
        return 0
    fi
    "$lc" "$@" || true
}

# hashqueue_add — 从 stdin 读哈希行,grep -qF 去重后追加到 <项目>/hashqueue.txt;无项目静默跳过
# 全程 flock <项目>/.state.lock(与 state.py/harvest/crack-sync 同一把锁):读-去重-追加与队列重写互斥
hashqueue_add() {
    local proj hq h
    proj=$(resolve_project) || return 0
    [ -n "$proj" ] || return 0
    hq="$proj/hashqueue.txt"
    (
        flock -x 9
        while IFS= read -r h; do
            [ -z "$h" ] && continue
            { [ -f "$hq" ] && grep -qF "$h" "$hq"; } || echo "$h" >> "$hq"
        done
    ) 9>"$proj/.state.lock"
    return 0
}

# proj_note <文本> — 追加一行到 <项目>/notes.md(格式同 redops proj_note);无项目静默跳过
proj_note() {
    local proj
    proj=$(resolve_project) || return 0
    [ -n "$proj" ] || return 0
    echo "- $(date '+%m-%d %H:%M') $1" >> "$proj/notes.md"
}
