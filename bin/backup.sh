#!/usr/bin/env bash
# backup.sh — ~/tools 轻量备份:git 快照 + 打包 docs/bin/redops 到 ~/backups(保留最近 5 份)
# 用法: ~/tools/bin/backup.sh        (建议 crontab: 0 3 * * * ~/tools/bin/backup.sh)
set -euo pipefail
DEST="$HOME/backups"; mkdir -p "$DEST"
TS=$(date +%Y%m%d-%H%M)

# 1) git 快照(未提交改动先落一笔,防止丢失)
cd "$HOME/tools"
if ! git diff --quiet HEAD 2>/dev/null || [ -n "$(git ls-files --others --exclude-standard)" ]; then
    git add -A && git -c user.name=kali -c user.email=kali@local commit -qm "backup.sh 自动快照 $TS" || true
fi

# 2) 打包核心资产(文档/脚本/控制台;不含 loot/二进制/仓库)
# 旧路径 tools/console 已迁至 tools/redops;直接打包三个目录
tar czf "$DEST/tools-$TS.tar.gz" -C "$HOME" tools/docs tools/bin tools/redops

# 3) git bundle(完整历史,可克隆恢复)
git bundle create "$DEST/tools-$TS.bundle" --all 2>/dev/null || true

# 4) 轮转:只留最近 5 份
ls -1t "$DEST"/tools-*.tar.gz 2>/dev/null | tail -n +6 | xargs -r rm -f || true
ls -1t "$DEST"/tools-*.bundle 2>/dev/null | tail -n +6 | xargs -r rm -f || true

echo "备份完成: $DEST/tools-$TS.tar.gz (+.bundle)"
# 异地建议:scp $DEST/tools-*$TS* user@远端:/backup/ 或 rclone 到对象存储
