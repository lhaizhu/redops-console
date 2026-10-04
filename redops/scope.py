#!/usr/bin/env python3
# scope.py — 交战范围护栏唯一实现(projects/<name>/scope.txt)
# serve.py 与 bin/lib/scope.sh 共用,避免双写漂移。
# 用法: scope.py <projdir> <target>
#   target 可为: IP / CIDR / 主机名 / 域名
# 退出码: 0=范围内  1=范围外  2=无 scope 文件或文件为空(调用方决定策略)
# scope.txt 格式: 一行一个 CIDR(10.0.0.0/24) / 单 IP / 域名后缀(corp.local 或 .corp.local)
#   `!` 前缀 = 排除(优先于允许); # 注释; 空行忽略
import ipaddress
import os
import sys

def load_scope(projdir: str):
    path = os.path.join(projdir, "scope.txt")
    if not os.path.exists(path):
        return None
    allow, deny = [], []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        (deny if line.startswith("!") else allow).append(line.lstrip("!"))
    if not allow:
        return None
    return allow, deny

def _net(s: str):
    try:
        return ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None

def _ip(s: str):
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None

def hit(rules, target: str) -> bool:
    for r in rules:
        n = _net(r)
        if n is not None:
            t_net = _net(target)
            if t_net is not None and t_net.version == n.version and t_net.subnet_of(n):
                return True  # CIDR 目标须整体 ⊆ 允许段;单 IP 也是 /32
            t_ip = _ip(target)
            if t_ip is not None and t_ip.version == n.version and t_ip in n:
                return True
        else:
            # 域名后缀规则: corp.local / .corp.local 匹配本身与子域
            suf = r.lower().lstrip(".")
            t = target.lower().rstrip(".")
            if t == suf or t.endswith("." + suf):
                return True
    return False

def main() -> int:
    if len(sys.argv) != 3:
        print("用法: scope.py <projdir> <target>")
        return 2
    projdir, target = sys.argv[1], sys.argv[2]
    rules = load_scope(projdir)
    if rules is None:
        return 2
    allow, deny = rules
    if hit(deny, target):
        return 1
    return 0 if hit(allow, target) else 1

if __name__ == "__main__":
    sys.exit(main())
