#!/usr/bin/env bash
# tools-update.sh — 一键更新全部攻击资源(git 仓库/exploitdb/nuclei 模板/fscan 版本检查)
# 用法: ~/tools/bin/tools-update.sh   (走代理: PROXY=http://host:port ~/tools/bin/tools-update.sh)
set -uo pipefail
# 代理改为环境变量显式开启;不设则直连
[ -n "${PROXY:-}" ] && export http_proxy="$PROXY" https_proxy="$PROXY"
export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"

echo "== [1/4] git 仓库更新(~/tools/src) =="
for d in ~/tools/src/*/; do
    name=$(basename "$d")
    [ -d "$d/.git" ] || continue
    if git -C "$d" pull -q --ff-only 2>/dev/null; then
        echo "  ✓ $name"
    else
        echo "  ✗ $name(有本地改动或冲突,跳过)"
    fi
done

echo "== [2/4] ExploitDB 漏洞库 =="
sudo -n searchsploit --update 2>/dev/null || searchsploit --update 2>&1 | tail -1

echo "== [3/4] nuclei 模板 =="
nuclei -update-templates 2>&1 | tail -1

echo "== [4/4] PEASS 重建 linpeas(可选,耗时) =="
# 需要时取消注释:
# cd ~/tools/src/PEASS-ng/linPEAS && python3 -m builder.linpeas_builder --all-no-fat --output linpeas.sh

echo "完成。别忘了:~/tools/bin/console.sh 会自动把文档改动重建进控制台。"
