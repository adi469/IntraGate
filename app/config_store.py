"""High-level config access layer — reads gateway configuration from PostgreSQL.

All modules that need config should import from here instead of reading DB directly.
Results are cached in-memory and refreshed when admin makes changes.
"""
from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select

from .config import GATEWAY_ENCRYPTION_KEY
from .database import AsyncSessionLocal
from .db_models import (
    Application,
    EntraConfig,
    GatewaySettings,
    PortalSettings,
)

log = logging.getLogger("gateway.config_store")

# ── In-memory cache ──────────────────────────────────────────
_cache: dict[str, object] = {}
_cache_lock = asyncio.Lock()


async def invalidate_cache(key: str | None = None):
    """Clear cached config. Pass key to clear specific, or None for all."""
    async with _cache_lock:
        if key:
            _cache.pop(key, None)
        else:
            _cache.clear()


# ── Entra ID ─────────────────────────────────────────────────

async def get_entra_config() -> dict:
    """Get Entra ID configuration."""
    if "entra" in _cache:
        return _cache["entra"]

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(EntraConfig).where(EntraConfig.id == 1))
        row = result.scalar_one_or_none()

    if not row:
        return {
            "tenant_id": "", "client_id": "", "client_secret": "",
            "connection_verified": False, "last_verified_at": None,
        }

    secret_decrypted = ""
    if row.client_secret:
        if row.client_secret.startswith("gAAAAA"):
            try:
                from cryptography.fernet import Fernet
                fernet = Fernet(GATEWAY_ENCRYPTION_KEY)
                secret_decrypted = fernet.decrypt(row.client_secret.encode()).decode()
            except Exception as e:
                log.error("Failed to decrypt Entra client secret: %s", e)
                secret_decrypted = ""
        else:
            secret_decrypted = row.client_secret

    data = {
        "tenant_id": row.tenant_id,
        "client_id": row.client_id,
        "client_secret": secret_decrypted,
        "connection_verified": row.connection_verified,
        "last_verified_at": row.last_verified_at.isoformat() if row.last_verified_at else None,
    }
    _cache["entra"] = data
    return data


# ── Applications ─────────────────────────────────────────────

async def get_app_registry() -> dict[str, dict]:
    """Get the dynamic application registry (replaces static APP_REGISTRY)."""
    if "apps" in _cache:
        return _cache["apps"]

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Application)
            .where(Application.is_enabled)
            .order_by(Application.sort_order, Application.name)
        )
        apps = result.scalars().all()

    registry = {}
    for app in apps:
        registry[app.slug] = {
            "id": app.id,
            "name": app.name,
            "description": app.description,
            "icon": app.icon,
            "group_id": app.group_id,
            "upstream": app.upstream,
            "tls_verify": app.tls_verify,
            "color": app.color,
            "gradient": app.gradient,
        }

    _cache["apps"] = registry
    return registry


# ── Portal Settings ──────────────────────────────────────────

async def get_portal_settings() -> dict:
    """Get user portal customization settings."""
    if "portal" in _cache:
        return _cache["portal"]

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(PortalSettings).where(PortalSettings.id == 1)
        )
        row = result.scalar_one_or_none()

    if not row:
        data = {
            "org_name": "My Organization", "org_subtext": "",
            "logo_mode": "none", "logo_file_path": "", "logo_url": "",
            "primary_color": "#1f6b9a", "accent_color": "#9b59b6",
            "footer_text": "© 2026 All rights reserved. | Active Directory SSO Secured",
        }
    else:
        data = {
            "org_name": row.org_name,
            "org_subtext": row.org_subtext,
            "logo_mode": row.logo_mode,
            "logo_file_path": row.logo_file_path,
            "logo_url": row.logo_url,
            "primary_color": row.primary_color,
            "accent_color": row.accent_color,
            "footer_text": row.footer_text,
        }

    _cache["portal"] = data
    return data


# ── Gateway Settings ─────────────────────────────────────────

async def get_gateway_settings() -> dict:
    """Get gateway-level settings."""
    if "gateway" in _cache:
        return _cache["gateway"]

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(GatewaySettings).where(GatewaySettings.id == 1)
        )
        row = result.scalar_one_or_none()

    if not row:
        data = {
            "gateway_base_url": "https://gateway.example.com",
            "session_lifetime_hours": 12,
            "session_timeout_minutes": 60,
            "setup_complete": False,
        }
    else:
        data = {
            "gateway_base_url": row.gateway_base_url,
            "session_lifetime_hours": row.session_lifetime_hours,
            "session_timeout_minutes": row.session_timeout_minutes,
            "setup_complete": row.setup_complete,
        }

    _cache["gateway"] = data
    return data


async def is_setup_complete() -> bool:
    """Quick check if initial setup has been done."""
    settings = await get_gateway_settings()
    return settings.get("setup_complete", False)


# ── Derived Entra ID URLs ────────────────────────────────────

async def get_entra_urls() -> dict:
    """Compute Entra ID OIDC endpoints from tenant_id."""
    entra = await get_entra_config()
    tenant = entra.get("tenant_id", "")
    if not tenant:
        return {}
    authority = f"https://login.microsoftonline.com/{tenant}"
    return {
        "authority": authority,
        "oidc_discovery_url": f"{authority}/v2.0/.well-known/openid-configuration",
        "authorize_url": f"{authority}/oauth2/v2.0/authorize",
        "token_url": f"{authority}/oauth2/v2.0/token",
        "logout_url": f"{authority}/oauth2/v2.0/logout",
        "jwks_uri": f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys",
    }
