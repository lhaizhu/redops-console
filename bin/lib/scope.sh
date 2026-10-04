# scope.sh — 交战范围护栏 CLI 封装(唯一实现是 bin/scope.py,console API 侧强制 403)
# 用法: source .../lib/scope.sh 后  scope_check <目标: IP/CIDR/主机名/域名>
# 语义(CLI 是人在跑,仅「范围外」硬拦):
#   无项目(全局临时模式)      → 放行,返回 0
#   项目内 + scope.txt 命中    → 放行,返回 0
#   项目内 + 无 scope.txt/为空 → 黄色警告后放行,返回 0(建议建立范围文件)
#   项目内 + 范围外            → 红色报错,返回 1(调用方应中止)
#   scope.py 异常(非 0/1/2)  → 红色报错,返回 1(fail-safe:放行决策从严)
source "$(dirname "${BASH_SOURCE[0]}")/project.sh"

SCOPE_PY="$(dirname "${BASH_SOURCE[0]}")/../scope.py"

# scope_check <目标> — 见头注释;范围内/可放行返回 0,范围外或异常返回 1
scope_check() {
    local target="$1" proj rc
    proj=$(resolve_project) || return 0
    [ -n "$proj" ] || return 0
    [ -f "$SCOPE_PY" ] && python3 "$SCOPE_PY" "$proj" "$target" >/dev/null 2>&1
    rc=$?
    case $rc in
        0) return 0 ;;
        2) echo -e "  ${Y}[!]${N} 无 scope.txt,建议建立范围文件: $proj/scope.txt" >&2; return 0 ;;
        1) echo -e "  ${R}[✗]${N} 目标 $target 在交战范围外,已中止(范围: $proj/scope.txt)" >&2; return 1 ;;
        *) echo -e "  ${R}[✗]${N} scope 检查异常(exit $rc),按范围外处理" >&2; return 1 ;;
    esac
}
