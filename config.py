"""Central settings — override with environment variables."""
from __future__ import annotations

import os


def login_username() -> str:
    return os.environ.get("AVS_USER", "admin")


def login_password() -> str:
    return os.environ.get("AVS_PASSWORD", "admin123")


def skip_login() -> bool:
    return os.environ.get("AVS_SKIP_LOGIN", "").lower() in ("1", "true", "yes")


def http_headers() -> dict[str, str]:
    import json
    headers_str = os.environ.get("AVS_HTTP_HEADERS", "")
    if headers_str:
        try:
            return dict(json.loads(headers_str))
        except Exception:
            pass
    return {}
