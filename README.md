# RedOps Console

域渗透工具编排平台:本地 Web 控制台 + 执行引擎,将 88 个参数化工具与 10 条攻击链组织为可复现的操作流水线。
面向授权渗透测试与 AD 实验环境(如 GOAD)。全部操作强制经过 scope 校验。

## 功能

- **执行台**:工具参数化调用;危险操作需显式 confirm;sudo 密码经 stdin 传递,不进 argv 与进程列表
- **攻击链**:多步编排,支持断点续跑(checkpoint)、条件步骤(when)、按行展开(for_each)、步骤间 cwd 产物交接
- **scope 校验**:按项目声明 CIDR/IP/域名后缀;范围外目标拒绝执行;校验失败一律拒绝(fail-closed)
- **凭据管理**:工具输出自动解析入台账(creds.csv,去重);模板支持 `{{cred:主体}}` 引用台账凭据;可爆哈希(TGS/ASREP/NetNTLMv2)自动入队,crack-sync 走 hashcat、失败回退 john,破解结果自动回灌台账
- **结果分析**:26 类签名识别(Pwn3d/ADCS 模板/凭据收割等)生成 findings;错误输出匹配静态处置建议(fail_hints)
- **远程执行原语**(bin/win-exec.py):任务计划触发 + SMB 文件回读,规避高延迟链路下 atexec 的任务删除竞态与 psexec 管道挂起;支持密码 / NT 哈希 / KRB5CCNAME 票据三种认证,SYSTEM 权限
- **DCSync**:DRSUAPI 远程复制,支持哈希认证与 Enterprise Admins 跨域(父域凭据拉子域),不产生目标机落地文件
- **报告**:bin/report.sh 聚合台账、findings、执行时间线输出交付文档
- **注册表热加载**:tools.json / chains.json 修改后自动重载;解析失败保留旧表
- **回归测试**:`python3 -m redops.tests.regress`,9 组用例,全程 /tmp 隔离
- **AI 辅助(默认关闭)**:配置后支持下一步建议;兼容 OpenAI / Claude / 自定义网关;外发内容经哈希打码

## 组成

```
redops/            引擎(Python 标准库 + impacket)
  engine.py        工具/链执行、scope 校验、历史、checkpoint
  server.py        HTTP API,token 认证,监听 127.0.0.1
  harvest.py       输出解析、台账写入、哈希入队
  intel.py         fail_hints、findings、攻击面看板数据
  state.py         状态机(已试标记/阶段/凭据/摘要)
  scope.py         范围校验(CIDR/IP/域名后缀/排除规则)
  web/tools.json   工具注册表(88)
  web/chains.json  攻击链(10)
  web/build.py     docs/*.md → 单文件文档站
  tests/regress.py 回归用例
bin/               编排脚本 25 个(autopwn、spray-safe、win-exec、report 等)及公共库
docs/              中文参考文档 33 篇
install.sh         安装脚本
```

## 安装

要求:Kali Linux 或 Debian 系,Python ≥ 3.11。

```bash
git clone <repo> ~/tools && cd ~/tools
bash install.sh
```

install.sh 完成:apt 依赖(impacket-scripts、netexec、certipy-ad、hashcat、john、bloodhound-ce-python 等)、
pip 兜底、bh.json 初始化、回归自检。参数:

- `--with-binaries`:附加下载 fscan / ligolo / rclone / easytier(GitHub 官方 release,单项失败不影响其余)
- `--skip-deps`:跳过依赖安装,仅配置与自检

脚本幂等,可重复执行;已有配置不覆盖。

## 使用

```bash
python3 -m redops 18911        # 启动,输出访问 token
# 浏览器访问 http://127.0.0.1:18911
```

典型流程:

```bash
# 建立项目并声明范围(必选,未声明范围仅允许只读工具)
echo '10.10.10.0/24' > projects/<项目名>/scope.txt

# 信息收集与打点
bin/autopwn.sh <域控IP>
bin/autopwn-continue.sh <域控IP>

# 控制台执行:onboard 链(名称解析/krb5/对时)→ bh-collect → bh-path
# 凭据攻击:kerb 链 → crack-sync 自动破解回灌
# 域控复制:dcsync-all(支持 EA 跨域)→ golden 票据

# 输出报告
bin/report.sh <项目名>
```

详见 docs/10-域渗透一条龙.md、docs/29-AI操作手册.md。

## 安全模型

- 所有目标参数经 scope 校验,范围外拒绝;校验器异常按拒绝处理
- danger 标记的工具/链要求 confirm 显式确认
- 密码喷洒统一走 spray-safe,强制解析目标锁定策略并限速
- API 使用 X-RedOps-Token 常量时间比较,仅监听 127.0.0.1
- 配置接口(BloodHound 凭据、AI api_key)不回显明文
- state.json 仅保存凭据的 sha256 指纹;明文仅存在于本地 creds.csv

## 仓库不含以下内容

- projects/、loot/、runs/:运行期数据(台账、票据、日志)
- bin/ 下第三方二进制(fscan、rclone、ligolo 等,install.sh --with-binaries 获取)
- redops/bh.json(由 bh.json.example 生成)

## 测试记录

在 GOAD v3 实验林完成两轮全流程验证:信息收集 → 凭据获取 → BloodHound 路径分析 →
委派/ADCS/票据链 → 父域 DCSync → Enterprise Admins 跨域复制子域全域 → 子域金票验证。
过程中发现并修复的问题已固化进回归用例。

已知环境限制:跨林(essos)需目标林凭据;目标机启用 Defender 时 mimikatz/comsvcs 类
内存读取会被拦截,应改用 DRSUAPI 复制(已内置)。

## License

MIT。仅限授权环境使用,使用者须确保对目标持有书面授权。
