#!/usr/bin/env bash
# install.sh — RedOps Console 一键安装(Kali / Debian 系)
# 用法: bash install.sh [--with-binaries] [--skip-deps]
#   --with-binaries  额外下载第三方大二进制(fscan/rclone/ligolo/easytier,GitHub 官方 release)
#   --skip-deps      跳过 apt/pip 依赖安装(仅配置+自检;CI/已装环境用)
# 幂等:可重复执行;已装的跳过,已存在的配置不覆盖。
set -uo pipefail
RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; NC=$'\033[0m'
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WITH_BIN=0; SKIP_DEPS=0
for a in "$@"; do case "$a" in
  --with-binaries) WITH_BIN=1;;
  --skip-deps) SKIP_DEPS=1;;
  *) echo "未知参数: $a"; exit 2;; esac; done

say()  { echo "${GRN}[+]${NC} $*"; }
warn() { echo "${YLW}[!]${NC} $*"; }
die()  { echo "${RED}[x]${NC} $*"; exit 1; }

SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
command -v python3 >/dev/null || die "需要 python3(≥3.11)"
PYV=$(python3 -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")')
python3 -c 'import sys;sys.exit(0 if sys.version_info>=(3,11) else 1)' || die "python $PYV 过旧,需 ≥3.11"

# ── 1. 系统依赖(apt) ─────────────────────────────
APT_PKGS=(impacket-scripts netexec certipy-ad hashcat john bloodhound-ce-python
          ldap-utils krb5-user sshpass genisoimage curl git python3-pip)
if [ "$SKIP_DEPS" -eq 0 ]; then
  say "安装系统依赖(${#APT_PKGS[@]} 个,已装自动跳过) ..."
  $SUDO apt-get update -qq || warn "apt update 失败(继续,可能已装)"
  $SUDO apt-get install -y -qq "${APT_PKGS[@]}" || warn "部分 apt 包安装失败(见上;非 Kali 源可能缺 netexec/certipy-ad → 用 pip 补)"
  # pip 兜底:apt 没有的 python 工具
  python3 -c "import impacket" 2>/dev/null || pip3 install --user impacket || warn "impacket pip 安装失败"
  command -v netexec >/dev/null || command -v nxc >/dev/null || pip3 install --user netexec || warn "netexec 未装上"
  command -v certipy-ad >/dev/null || pip3 install --user certipy-ad || true
  python3 -c "import pylnk3" 2>/dev/null || pip3 install --user pylnk3 || warn "pylnk3 未装(make-lure 退回手工 LNK 构造,仍可用)"
else
  say "跳过依赖安装(--skip-deps)"
fi

# ── 2. 可选:第三方大二进制 ───────────────────────
dl() { # dl <url> <目标文件> [解压inner路径]
  local url="$1" dst="$2" inner="${3:-}"
  [ -x "$dst" ] && { say "$(basename "$dst") 已存在,跳过"; return 0; }
  say "下载 $(basename "$dst") ..."
  local tmp; tmp=$(mktemp -d)
  if curl -fSL --connect-timeout 15 -o "$tmp/pkg" "$url"; then
    case "$url" in
      *.tar.gz|*.tgz) tar xzf "$tmp/pkg" -C "$tmp" 2>/dev/null;;
      *.zip) (cd "$tmp" && python3 -c "import zipfile;zipfile.ZipFile('pkg').extractall()");;
    esac
    local f; f=$(find "$tmp" -type f -name "${inner:-$(basename "$dst")}" | head -1)
    [ -n "$f" ] && { cp "$f" "$dst"; chmod +x "$dst"; say "✓ $(basename "$dst")"; } || warn "解压后未找到 $(basename "$dst"),手动装"
  else
    warn "下载失败($url),跳过——该工具对应功能不可用,不影响核心"
  fi
  rm -rf "$tmp"
}
if [ "$WITH_BIN" -eq 1 ]; then
  say "下载第三方二进制(GitHub 官方 release,失败不致命) ..."
  dl "https://github.com/shadow1ng/fscan/releases/latest/download/fscan_linux_amd64" "$ROOT/bin/fscan"
  dl "https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz" "$ROOT/bin/ligolo_proxy" "proxy"
  dl "https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz" "$ROOT/bin/ligolo_agent" "agent"
  dl "https://downloads.rclone.org/rclone-current-linux-amd64.zip" "$ROOT/bin/rclone" "rclone"
  dl "https://github.com/BasicSwap/easytier/releases/latest/download/easytier-linux-x86_64.zip" "$ROOT/bin/easytier-core" "easytier-core" || true
fi

# ── 3. 配置初始化(不覆盖已有) ────────────────────
[ -f "$ROOT/redops/bh.json" ] || { cp "$ROOT/redops/bh.json.example" "$ROOT/redops/bh.json" 2>/dev/null && say "bh.json 已由 example 生成(默认 admin/admin,用 BloodHound CE 时改)"; }
mkdir -p "$ROOT/projects" "$ROOT/loot"
chmod +x "$ROOT"/bin/*.sh "$ROOT"/bin/*.py 2>/dev/null || true

# ── 4. 自检 ─────────────────────────────────────
say "运行回归自检(全隔离,~10s) ..."
if PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$ROOT" python3 -m redops.tests.regress 2>&1 | tail -3; then
  say "自检通过"
else
  die "自检未过——看上面失败项,或提 issue"
fi

echo
echo "${GRN}════════════════ 安装完成 ════════════════${NC}"
echo "启动:   cd $ROOT && python3 -m redops 18911"
echo "        (或 bash bin/console.sh up)"
echo "打开:   http://127.0.0.1:18911  输入启动时打印的 Token"
echo "剧本:   docs/10-域渗透一条龙.md 开头「🚀 新手剧本」"
[ "$WITH_BIN" -eq 0 ] && echo "提示:   bash install.sh --with-binaries 可补 fscan/ligolo/rclone 等大二进制"
