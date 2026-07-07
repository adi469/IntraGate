"""Gateway configuration — minimal .env settings + dynamic DB-backed config.

Only GATEWAY_SECRET_KEY, HOST, PORT, and DATABASE_URL come from .env.
Everything else (Entra ID, apps, portal, session) is managed via the admin panel.
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the gateway root (one level above app/)
_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_ENV_FILE)


# ── Static Settings (from .env only) ─────────────────────────
SECRET_KEY = os.environ.get("GATEWAY_SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("GATEWAY_SECRET_KEY environment variable is missing or empty")
if len(SECRET_KEY) < 32:
    raise ValueError("GATEWAY_SECRET_KEY must be at least 32 characters long")

GATEWAY_ENCRYPTION_KEY = os.environ.get("GATEWAY_ENCRYPTION_KEY")
if not GATEWAY_ENCRYPTION_KEY:
    raise ValueError("GATEWAY_ENCRYPTION_KEY environment variable is missing or empty")
try:
    from cryptography.fernet import Fernet
    Fernet(GATEWAY_ENCRYPTION_KEY)
except Exception as e:
    raise ValueError(f"GATEWAY_ENCRYPTION_KEY is not a valid 32-byte URL-safe base64-encoded Fernet key: {e}")

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is missing or empty")

HOST = os.environ.get("GATEWAY_HOST", "0.0.0.0")
PORT = int(os.environ.get("GATEWAY_PORT", "9000"))
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "8585"))

# Developer Mode
DEV_MODE = os.environ.get("GATEWAY_DEV_MODE", "false").lower() == "true"
SECURE_COOKIE = not DEV_MODE

# Trusted Proxies parsing
_trusted_proxies_raw = os.environ.get("TRUSTED_PROXIES", "")
if _trusted_proxies_raw:
    TRUSTED_PROXIES = {ip.strip() for ip in _trusted_proxies_raw.split(",") if ip.strip()}
else:
    TRUSTED_PROXIES = {"127.0.0.1", "::1"}


# ── Legacy compatibility shim ────────────────────────────────
# The old 'settings' object is replaced by async config_store functions.
# This class exists only so any remaining imports don't crash at startup.
class _LegacySettings:
    SECRET_KEY = SECRET_KEY
    HOST = HOST
    PORT = PORT

settings = _LegacySettings()
