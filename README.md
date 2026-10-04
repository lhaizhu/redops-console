# RedOps Console — 域渗透编排控制台

本地 Web 控制台 + 编排引擎:把 **88 个工具 / 10 条攻击链**封装成新手也能走完的域渗透流水线。
在 GOAD 实验室(Game of Active Directory)经两轮全链实战验证:从零信息到**全林制霸**(父域+子域金票、44 条凭据自动入账)。

> ⚠️ **仅用于授权环境**(实验室 / 已签授权的渗透测试)。内置 scope 硬护栏不是装饰品——先声明范围再开打。

---

## 核心特性

| 能力 | 说明 |
|---|---|
| **执行台** | 88 工具参数化执行,危险操作 confirm 闸门,sudo 密码走 stdin 不进进程列表 |
| **攻击链** | 10 条链(onboard / kerb / rbcd / esc1 / shadow / esc8 / mssql-links / cross-domain / wg-reap …),支持断点续跑(checkpoint)、条件步(when)、逐行展开(for_each) |
| **scope 硬护栏** | `projects/<名>/scope.txt` 声明 CIDR/IP/域后缀;超范围目标一律 403,fail-closed |
| **凭据流水线** | 输出自动收割 → `creds.csv` 台账(去重) + `state.json`(值只存 sha256);模板 `{{cred:主体}}` 水合自动代填;可爆哈希自动入队 → crack-sync(hashcat→john 兜底)破解回灌 |
| **findings 自动发现** | Pwn3d / ESC4 / 凭据收割等 26 类签名 → 攻击面看板(board)指路下一步 |
| **fail_hints** | 26+ 错误签名静态对策(Kerberos 错误码 / atexec 竞态 / EA 跨域 …),新手照着走 |
| **Windows agent 原语** | `bin/win-exec.py`:任务计划保活触发 + SMB 结果文件回读——根治高延迟链路 atexec Run/Delete 竞态与 psexec 管道挂起;SYSTEM 权限;密码/NT哈希/KRB5票三认证 |
| **Defender 规避正解** | 不碰 LSASS:EA 跨域 DRSUAPI(dcsync-all)零落地拉全域哈希,杀软无感 |
| **报告交付** | `bin/report.sh <项目>` 聚合台账/findings/时间线 → 交付报告 |
| **注册表热加载** | tools.json/chains.json 按 mtime 自动重载,改坏保旧表 |
| **回归包** | `python3 -m redops.tests.regress` 9 组用例(隔离 /tmp,不碰真实数据) |
| **AI 兜底(默认关)** | 配置页开启后可问「下一步建议」;OpenAI/Claude/自定义网关三格式;外发前哈希打码 |

## 架构

```
浏览器 ──► redops.server(ThreadingHTTPServer, token 认证, 127.0.0.1)
             ├─ redops.engine   工具/链执行 · scope 闸门 · 历史 · checkpoint
             ├─ redops.harvest  输出收割 → 台账/哈希队列
             ├─ redops.intel    fail_hints · board · findings
             ├─ redops.state    状态机(tried/phase/cred/summary)
             ├─ redops.project  多项目工作区(projects/<名>/{scope.txt,loot,notes.md})
             └─ redops.web      tools.json(88 工具) · chains.json(10 链) · 文档站(build.py 生成)
bin/*.sh|py   25 个编排脚本(autopwn / spray-safe / win-exec / report …)
docs/         33 篇中文知识库(域渗透一条龙 / ADCS / 跨林 / 凭据收割 …)
```

## 快速开始(一键)

**环境**:Kali Linux(或 Debian 系),Python ≥ 3.11,仅标准库 + impacket。

```bash
git clone <repo> ~/tools && cd ~/tools
bash install.sh                    # 依赖+配置+自检一条龙;加 --with-binaries 连大二进制一起装
python3 -m redops 18911            # 启动;打印 Token
# 浏览器打开 http://127.0.0.1:18911,填入 Token
```

`install.sh` 幂等可重复跑:`--skip-deps` 只配置+自检;`--with-binaries` 从 GitHub 官方 release 拉
fscan / ligolo-proxy / ligolo-agent / rclone / easytier(单一下载失败不致命,只影响对应功能)。

**可选服务**:BloodHound CE——install 已生成 `redops/bh.json`(默认 admin/admin),改成你的实例凭据即可。

## 新手剧本(GOAD 实战验证路径)

```bash
# 0. 建项目+声明范围(硬护栏,先做!)
python3 -m redops.project 新建 GOAD && echo '192.168.56.0/24' > projects/GOAD/scope.txt

# 1. 从零打点:    bin/autopwn.sh <域控IP>
# 2. 有凭据后:    bin/autopwn-continue.sh <域控IP>   # 权限验证/SAM/LSA/MSSQL
# 3. 配环境:      控制台跑 onboard 链(/etc/hosts+krb5.conf+对时)
# 4. 读路径:      bh-collect → bh-path(攻击路径解读)
# 5. 烤制破解:    kerb 链 → hashcat-queue → crack-sync 自动回灌台账
# 6. 制霸:        dcsync-all(EA 可跨域)→ golden 金票
# 7. 交付:        bin/report.sh GOAD
```

详细手册:`docs/10-域渗透一条龙.md` 开头「🚀 新手剧本」、`docs/29-AI操作手册.md`。

## 项目结构

```
redops/            # 引擎包(~4k 行,stdlib+impacket)
  engine.py        #   执行/链/scope 闸门/历史/checkpoint
  server.py        #   HTTP API(20 端点,token 常量时间比较)
  harvest.py       #   凭据收割/哈希入队
  intel.py         #   fail_hints/board/findings
  state.py scope.py project.py config.py ai.py paths.py
  web/tools.json   #   88 工具注册表(参数化模板)
  web/chains.json  #   10 攻击链
  web/build.py     #   docs/*.md → 单文件文档站 index.html
  tests/regress.py #   永久回归包(9 组用例)
bin/               # 25 编排脚本 + lib 公共库
docs/              # 33 篇中文知识库
install.sh         # 一键安装(依赖/二进制/配置/自检)
bin/check-refs.py  # 文档↔工具↔链引用一致性审计(全绿为准)
```

## 安全设计要点

- **scope 硬护栏**:每个目标参数过 scope.py,超范围 403;校验器崩溃/超时一律拒绝(fail-closed)
- **危险闸门**:`danger:true` 工具必须 `confirm:true` 才执行(喷洒/金票/DCSync/远程执行)
- **喷洒保护**:spray-safe 强制锁定阈值解析+限速,唯一喷洒入口
- **token 认证**:`X-RedOps-Token` 常量时间比较;仅监听 127.0.0.1
- **sudo 密码**:stdin 管道传递,不出现在 argv/进程列表/历史
- **对外脱敏**:配置端点(BH/api_key)与 AI brief 外发一律打码(执行历史按用户选择原文存储)
- **状态值最小化**:state.json 只存凭据 sha256 指纹,明文落 creds.csv(本地文件,别提交)

## 不入库的东西(本仓库已排除)

- `projects/ loot/ runs/`——交战数据(凭据台账、票据 ccache、输出日志)
- 大型第三方二进制(fscan/rclone/ligolo 等,上文有清单)
- `redops/bh.json`(BloodHound 实例凭据,用 bh.json.example)

## 实战验证记录(GOAD,2026-09)

两轮全链实测:侦察→凭据→BH 路径→9 链→爆破回灌→父域金票→**EA 跨域 DRSUAPI 北域全域**→北域金票验证。
期间修复 18+ 个实战暴露的摩擦点并全部固化进回归包。受限项(环境性,非工具):essos 跨林缺凭据、
GOAD Defender 拦 mimikatz/comsvcs(正解=换 DRSUAPI 协议,已内置 dcsync-all)。

## 免责声明

本项目仅面向**授权**安全测试与学习(如 GOAD/HTB/自建实验林)。使用者须确保对目标拥有书面授权;
作者不对任何未授权使用负责。内置 scope 护栏是辅助手段,不构成授权证明。
