"""__main__.py — 入口: python3 -m redops [port](默认 8765,仅 127.0.0.1)
特性:每次运行独立 rundir(~/tools/loot/runs/<id>-<ts>/);bh-collect 成功后若配置
     redops/bh.json({url,user,pass})自动登录 BloodHound CE 上传采集 zip。"""
import secrets, sys, webbrowser
from http.server import ThreadingHTTPServer
from . import engine, project, server


def main():
    engine.startup_checks()  # 注册命令首词二进制自检 → warn(前端黄条)
    engine.adopt_orphan_runs()  # 收养孤儿后台任务:活进程标注/死进程补 rc=-2(fail-safe)
    project.prune_all_runs()  # runs 轮转:超 300 的旧目录打包 archive/ 后删除(fail-safe)
    server.set_token(secrets.token_urlsafe(24))  # 每次启动随机生成;/api/* 需带 X-RedOps-Token 头
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    print(f"[*] RedOps Console: http://127.0.0.1:{port}  (Ctrl+C 停止)")
    print(f"[*] Token: {server.TOKEN}")
    try: webbrowser.open(f"http://127.0.0.1:{port}")
    except Exception: pass
    ThreadingHTTPServer(("127.0.0.1", port), server.H).serve_forever()


if __name__ == "__main__":
    main()
