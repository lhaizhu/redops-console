#!/usr/bin/env python3
# state.py — 薄 shim:实现已迁至 redops/state.py(CLI 契约逐字不变)
# 用法: state.py <projdir> <cmd> [args](见 redops/state.py 文件头注释)
import os
import sys
sys.path.insert(0, os.path.expanduser("~/tools"))
from redops.state import main

if __name__ == "__main__":
    sys.exit(main())
