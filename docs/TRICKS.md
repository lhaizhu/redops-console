# 域渗透奇技索引(TRICKS)

> 按实战场景组织,全部来自本项目已验证文档(括号内为来源号)。`grep -n '关键词' ~/tools/docs/TRICKS.md` 直查。

## 卡住了 → 解法速查

| 场景 | 奇技 | 来源 |
|---|---|---|
| Kerberos 全部失败/时间对不上 | **时钟漂移是第一嫌疑人**:DC 与本机差 >5min 必败;`sudo chronyd -q 'server <DC> iburst'` 后再战 | 12 |
| 账号锁死不敢动 | `--pass-pol` 先看锁定阈值/观察窗;`nxc --no-bruteforce` 只按字典逐对;spray-safe.sh 自动节流 | 04/10 |
| 喷洒全失败 | 试**首字母大写+年份后缀**变体(`Company@2024`/`Spring2024!`);用户名本身当密码(未改初始密码) | 10 |
| 破解太慢 | **优先 RC4 行**(`$krb5...$23$` 前缀,-m 13100/18200 比 AES 快几个量级);hashcat -O 优化内核 | 12 |
| gMSA 拿到哈希 | **直接传递,别爆破**(120+ 位随机);impacket 系全支持 `-hashes` | 10/12 |
| 用户密码改了权限还在 | 你有 NT 哈希就够——**PTH 不需要密码**;改成啥无所谓,除非二次哈希轮换 | 10 |
| 机器账户比用户账户稳 | 密码 30 天自动轮换的是机器账户,**你建的 EVIL$ 不轮换**;Certifried 也吃机器户 | 16 |
| ESC 编号 JSON 里找不到 | certipy find 的 **ESC14 只在 text 输出**,`-text` 别用 `-json` 找它 | 16 |
| ADCS find 报一堆 ESC | 优先级:**ESC1(自填SAN)>ESC8(中继)>ESC4(改模板)>其他**;ESC9/ESC10/ESC12 不自动检测需手核 | 11/16 |
| NTLM 中继全被拦(签名/EPA) | 换 **Kerberos 中继**(krbrelayx + CVE-2022-33679,RC4 降级)——签名管不到它 | 16/10§1.5 |
| responder 起了没流量 | ①配 **ADIDNS 通配符**(dnstool `*.domain`→本机),解析不到的全回你 ②responder.conf 关 SMB/HTTP 再配中继防互抢 | 10§1.5/05 |
| 中继挂上了不知道谁会来 | **coercer scan 先探测**目标支持哪些强制方法,再精确 coerce;别全方法乱打 | 11 |
| LSASS 读不了(RunAsPPL) | `rundll32 comsvcs.dll MiniDump <pid> dump.bin full` 走系统签名组件;pypykatz 离线解 | 13 |
| 只有"读"权限不知道能干啥 | BH 查询集里 **DCSync 候选/GPO 控制边/LAPS 可读** 三条先跑——读权限也能变 DA | 12 附录/bh-queries |
| 工作组单哈希不知道打谁 | **--local-auth 全网段喷**:本地管理员密码复用是工作组命门;命中→--sam 拉全量→新哈希再喷(雪球);空密码哈希 31d6… 直接跳过 | 05/TRICKS |
| 不知道管理员从哪台连过来 | **溯源两问**:nxc --sessions/--loggedon-users 看实时来源;历史看 4624(LogonType 3/10 取 IpAddress)+RDP 注册表 Servers 键(连过谁);Linux 一把 last -a/known_hosts(26 §8,执行台双溯源工具) | 26 §8 |
| 域内 Linux 机器不知道怎么下口 | keytab 三连(klist -kt 看→拖回→kinit -kt 换票据)→GSSAPI 免密 SSH 直达其它域机器(27 §1) | 27 §1 |
| 内网共享太多找不到密码文件 | spider_plus 递归+下载小文件(无 PATTERN,下载后本地关键词:密码/pass/vpn/拓扑/cred/backup)(27 §4,执行台 file-hunt) | 27 §4 |
| 拿了 DA 但随时会被踢 | 先干三件事:**DCSync krbtgt(金票原料)→影子凭据(pywhisker)→ACL-dcsync 后门**;金票要打时现生成,别囤 ccache | 10 §5 |
| ZeroLogon 打完域控失联 | 没恢复机器账户哈希——**导出 .history 再 setpassword**,否则 NETLOGON 禁用=域控断网 | 10 §4.4 |
| Exchange 443 暴露 | 2021-2023 的 Proxy 系全家桶:ProxyLogon/ProxyShell/ProxyNotShell msf 一键(模块名带 _rce);OWA 爆破 msf owa_login | 15 |
| 有 SCCM(客户端有 CCMExec) | **SCCM 管理员≈域管**:sccmhunter find→NAA 雪球→http 注册滥用 | 19 |
| 文件传不过去(出网全断) | SMB 共享 + `net use` 映射(内网直连);再断就 base64 echo 写文件 | 13 |
| 命令能跑但工具落地就报毒 | LOLBins 先行(rundll32/certutil);要 exe 就 **Shhhloader 直接系统调用+unhook** | 20 |
| 怕蜜罐/被反制 | 拿到 shell 先看 `Get-Service | where Status -eq Running` 有没有 canary 类进程;BH 图上"太容易的 DA 路径"多想一步 | 21/经验 |

## 操作方式层(本控制台特性)

- **链**:RBCD/Kerberoast/ADCS/接入 四条链自动接续上步产物(执行台 🔗 组)
- **自动收割**:secretsdump/nxc/certipy 输出→creds.csv;asrep/tgs 哈希→hashqueue.txt;看板"下一步建议"按产物自动推阶段
- **项目隔离**:A/B 项目切换即全部上下文切换,Ⓟ 自动预填域/DC 参数
- **proxychains 开关**:打深层网段时勾上,一条命令走隧道
