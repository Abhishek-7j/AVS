"""Central settings — override with environment variables."""
from __future__ import annotations

import os


def login_username() -> str:
    return os.environ.get("AVS_USER", "admin")


def login_password() -> str:
    return os.environ.get("AVS_PASSWORD", "admin123")


def skip_login() -> bool:
    return os.environ.get("AVS_SKIP_LOGIN", "").lower() in ("1", "true", "yes")
