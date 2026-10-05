"""Make one small request to the configured contest model without logging secrets."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))
import scan_agent as agent  # noqa: E402


def redact(text: str) -> str:
    for name in ("LLM_API_KEY", "DASHSCOPE_API_KEY"):
        secret = os.environ.get(name)
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return re.sub(r"sk-[A-Za-z0-9_.-]+", "[REDACTED]", text)


def main() -> int:
    env_file = ROOT / "agent/.env"
    if env_file.is_file():
        for line in env_file.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                if key.strip() in {"LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL"}:
                    os.environ[key.strip()] = value.strip().strip("\"'")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out = ROOT / "outputs" / f"model-check-{stamp}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    summary = {"passed": False, "model": agent.contest_model(),
               "endpoint_host": urlparse(os.environ.get("LLM_BASE_URL", "")).hostname}
    try:
        client = agent.get_client().with_options(timeout=30.0, max_retries=0)
        response = client.chat.completions.create(
            model=agent.contest_model(),
            messages=[{"role": "user", "content": "Reply with the single word OK."}],
            max_tokens=64,
            extra_body={"enable_thinking": False},
        )
        content = response.choices[0].message.content or ""
        summary.update({"passed": bool(content.strip()), "response_model": response.model,
                        "finish_reason": response.choices[0].finish_reason,
                        "response": redact(content[:200]),
                        "usage": response.usage.model_dump() if response.usage else None})
    except Exception as error:
        summary.update({"error_type": type(error).__name__,
                        "http_status": getattr(error, "status_code", None),
                        "message": redact(str(error))[:1000]})
    summary["elapsed_seconds"] = round(time.monotonic() - started, 2)
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"Saved: {out}")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
