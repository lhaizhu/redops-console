"""ai.py — 内置 LLM 客户端(stdlib urllib,三格式适配;60s 超时;错误一律干净 JSON 化,绝不炸 handler)
base_url 完全自定义(官方 / one-api / api2d / 自建网关任意子路径一等支持),URL 归一化见 _url()"""
import json
import urllib.error
import urllib.parse
import urllib.request

class _NoCrossHostRedirect(urllib.request.HTTPRedirectHandler):
    """重定向防线:base_url 是用户自定义的网关(SSRF 面),跨主机 30x 会把
    Authorization/x-api-key 重发到目标主机 → 一律拒绝;同主机重定向照常(保留头)"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlparse(newurl).netloc != urllib.parse.urlparse(req.full_url).netloc:
            raise urllib.error.HTTPError(req.full_url, code,
                f"拒绝跨主机重定向: {urllib.parse.urlparse(newurl).netloc}", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

_OPENER = urllib.request.build_opener(_NoCrossHostRedirect())

def _url(base, ep):
    """归一化端点:去尾 '/';路径已含 ep → 原样;以 /v1 结尾 → +ep;否则 +/v1/ep。
    网关子路径保留:https://x.com/abc/v1 → https://x.com/abc/v1/chat/completions(不拼 /v1/v1、不丢 /abc)"""
    b = (base or "").strip().rstrip("/")
    if b.endswith("/" + ep):
        return b
    return b + ("" if b.endswith("/v1") else "/v1") + "/" + ep

def call_llm(cfg_ai, system, user):
    """按 cfg_ai['format'] 调 LLM,返回文本;失败抛 RuntimeError(消息已脱敏截断,可直接回前端)"""
    cfg_ai = cfg_ai or {}
    fmt = str(cfg_ai.get("format") or "chat_completions").strip()
    model = str(cfg_ai.get("model") or "").strip()
    key = str(cfg_ai.get("api_key") or "").strip()
    base = str(cfg_ai.get("base_url") or "")
    if fmt == "messages":  # Anthropic Messages
        url = _url(base, "messages")
        body = {"model": model, "max_tokens": 2000, "system": system,
                "messages": [{"role": "user", "content": user}]}
        headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
        parse = lambda d: d["content"][0]["text"]
    elif fmt == "responses":  # OpenAI Responses API
        url = _url(base, "responses")
        body = {"model": model, "instructions": system, "input": user}
        headers = {"Authorization": f"Bearer {key}"}
        def parse(d):
            if d.get("output_text"):
                return d["output_text"]
            for o in d.get("output") or []:
                for c in o.get("content") or []:
                    if c.get("type") == "output_text" and c.get("text"):
                        return c["text"]
            raise KeyError("output_text")
    else:  # chat_completions(默认)
        url = _url(base, "chat/completions")
        body = {"model": model, "messages": [{"role": "system", "content": system},
                                             {"role": "user", "content": user}]}
        headers = {"Authorization": f"Bearer {key}"}
        parse = lambda d: d["choices"][0]["message"]["content"]
    req = urllib.request.Request(url, data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                                 method="POST",
                                 headers={**headers, "Content-Type": "application/json"})
    try:
        with _OPENER.open(req, timeout=60) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
    except urllib.error.HTTPError as e:
        try: detail = e.read().decode("utf-8", "ignore")[:300]
        except Exception: detail = ""
        raise RuntimeError(f"HTTP {e.code}: {detail or e.reason}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise RuntimeError(f"连接失败: {e}")
    try:
        text = str(parse(data)).strip()
    except Exception:
        raise RuntimeError("响应解析失败: 未找到文本字段")
    if not text:
        raise RuntimeError("响应解析失败: 内容为空")
    return text

def advise_prompt(brief):
    """brief(dict) → (system, user);user 为压缩版 brief JSON:tools_available 全表换 stage 计数"""
    system = ("你是资深域渗透顾问,基于给出的项目态势 JSON 给出下一步建议。"
              "红线:只说下一步做什么/为什么;不重复已尝试过的动作;"
              "危险动作(凭证爆破、票据伪造、批量修改等)必须标 [需人工确认]。")
    b = dict(brief or {})
    tools = b.pop("tools_available", None) or {}
    b["tools_by_stage"] = {k: len(v) for k, v in tools.items()}
    user = "当前项目态势(JSON):\n" + json.dumps(b, ensure_ascii=False)
    return system, user
