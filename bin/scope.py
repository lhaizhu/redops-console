#!/usr/bin/env python3
# scope.py — 薄 shim:实现已迁至 redops/scope.py(CLI 契约逐字不变)
# 用法: scope.py <projdir> <target>(见 redops/scope.py 文件头注释)
import os
import sys
sys.path.insert(0, os.path.expanduser("~/tools"))
from redops.scope import main

if __name__ == "__main__":
    sys.exit(main())
