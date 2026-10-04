#!/usr/bin/env bash
# console.sh — 启动 RedOps Console(静态页 + 执行台后端,默认 8765,仅 127.0.0.1)
# 用法: console.sh [端口]        停止: console.sh stop [端口]
set -euo pipefail
PORT="${1:-8765}"
DIR="$HOME/tools"
WEB="$DIR/redops/web"

case "${1:-}" in
  # pgrep/pkill -f 用 ERE:锚定端口边界,避免 stop 876 误杀 8765
  stop) P="${2:-8765}"
        pkill -f "redops $P([[:space:]]|$)" 2>/dev/null && echo "已停止" || echo "未在运行"; exit 0 ;;
  up)   echo "[*] 拉起依赖服务…"
        sudo systemctl start postgresql neo4j bloodhound || echo "[!] sudo 启动失败(可配 sudoers NOPASSWD 免密)"
        systemctl --no-pager --plain is-active postgresql neo4j bloodhound 2>/dev/null
        exit 0 ;;
esac

# 文档有更新则重新构建(命令库数据注入 index.html)
python3 "$WEB/build.py" "$DIR/docs" "$WEB/template.html" "$WEB/index.html" >/dev/null

for s in bloodhound neo4j beef-xss gophish; do
    systemctl is-active --quiet "$s" 2>/dev/null && echo "  ● $s 活跃" || true
done

if pgrep -f "redops $PORT([[:space:]]|$)" >/dev/null 2>&1; then
    echo "已在运行: http://127.0.0.1:$PORT"
else
    # setsid 脱离调用方进程组:即使从超时会话的 shell 启动,服务也不被连带杀掉
    (cd "$DIR" && setsid nohup python3 -m redops "$PORT" >/dev/null 2>&1 < /dev/null &)
    sleep 1
    echo "控制台+执行台: http://127.0.0.1:$PORT  (停止: $0 stop)"
fi
curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT" || true
# headless(无 DISPLAY/WAYLAND)下 xdg-open 会挂住;后台+超时,且仅在有显示时调用
if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && command -v xdg-open >/dev/null; then
    timeout 5 xdg-open "http://127.0.0.1:$PORT" >/dev/null 2>&1 &
fi
