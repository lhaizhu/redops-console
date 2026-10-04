"""config.py — 配置(兜底管理面;redops/config.json 建议入 .gitignore)+ 模块级可变状态"""
import json, os, tempfile
from .paths import BASE

CONFIG = BASE / "config.json"
BH_JSON = BASE / "bh.json"
CFG_DEFAULTS = {"ai_enabled": False, "proxy": "", "wordlist": "/usr/share/wordlists/rockyou.txt",
                "ai": {"format": "chat_completions", "base_url": "", "api_key": "", "model": ""}}

def cfg_get():
    """读 config.json;缺失/损坏 → 默认值并落盘"""
    try:
        d = json.loads(CONFIG.read_text(encoding="utf-8"))
        cfg = {**CFG_DEFAULTS, **{k: d[k] for k in CFG_DEFAULTS if k in d}}
    except Exception:
        cfg_save(dict(CFG_DEFAULTS))
        cfg = dict(CFG_DEFAULTS)
    if not isinstance(cfg.get("ai"), dict): cfg["ai"] = {}
    cfg["ai"] = {**CFG_DEFAULTS["ai"], **cfg["ai"]}  # ai 子键深合并:老配置缺键补默认
    return cfg

def cfg_save(cfg):
    """原子写 config.json(mkstemp 临时名 + replace;并发保存不抢同一固定 tmp 名)"""
    fd, tmp = tempfile.mkstemp(dir=CONFIG.parent, prefix=".config-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(cfg, ensure_ascii=False, indent=2))
    os.replace(tmp, CONFIG)

CFG = cfg_get()  # 启动加载;POST /api/config 原地更新并落盘

TIMEOUT_MULT = 1.0  # netcheck 实测网络超时倍数(成功运行后更新,clamp 0.5–8);影响所有 run/链步骤超时

def set_timeout_mult(v):
    """跨模块写 TIMEOUT_MULT 的显式 setter(engine._set_timeout_mult 调用)"""
    global TIMEOUT_MULT
    TIMEOUT_MULT = v
