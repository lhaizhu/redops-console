# common.sh — 共享基础库:PATH / 颜色 / 日志助手 / 临时目录
# 用法: source "$(dirname "$(readlink -f "$0")")/lib/common.sh"
# 幂等:重复 source 不会重复 prepend PATH
[ -n "${TOOLS_LIB_COMMON:-}" ] && return 0
TOOLS_LIB_COMMON=1

export PATH="$HOME/.local/bin:$HOME/tools/bin:$PATH"

G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; N='\033[0m'
ok(){ echo -e "  ${G}[✓]${N} $1"; }; no(){ echo -e "  ${R}[✗]${N} $1"; }; go(){ echo -e "  ${Y}[▶]${N} $1"; }

# mktmpdir <前缀> — 建临时目录并回显路径(默认前缀 tmp)
mktmpdir(){ mktemp -d "/tmp/${1:-tmp}-XXXXXX"; }
