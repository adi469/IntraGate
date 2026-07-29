"""Database seeding logic.

Automatically migrates existing config from `.env` to the PostgreSQL database
on first launch. This ensures a seamless transition for existing deployments.
"""
from __future__ import annotations

import logging
import os

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .db_models import Application, EntraConfig, GatewaySettings, PortalSettings

log = logging.getLogger("gateway.seed")


def _parse_upstream(url: str) -> tuple[str, str, int]:
    """Parse scheme, host/ip and port from an upstream URL."""
    # E.g. http://dispatch-app:8001 -> ("http", "dispatch-app", 8001)
    # https://127.0.0.1:8002 -> ("https", "127.0.0.1", 8002)
    scheme = "https" if url.startswith("https://") else "http"
    clean = url.replace("http://", "").replace("https://", "").split("/")[0]
    if ":" in clean:
        parts = clean.split(":")
        return scheme, parts[0], int(parts[1])
    return scheme, clean, 443 if scheme == "https" else 80


async def seed_from_env(session: AsyncSession):
    """Seed the database using settings from the environment variables."""
    # 1. Seed EntraConfig
    entra_count = (await session.execute(select(func.count(EntraConfig.id)))).scalar()
    if entra_count == 0:
        tenant_id = os.environ.get("AZURE_TENANT_ID", "")
        client_id = os.environ.get("AZURE_CLIENT_ID", "")
        client_secret = os.environ.get("AZURE_CLIENT_SECRET", "")

        entra = EntraConfig(
            id=1,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            connection_verified=bool(tenant_id and client_id and client_secret),
        )
        session.add(entra)
        log.info("Seeded EntraConfig from environment variables")

    # 2. Seed PortalSettings
    portal_count = (await session.execute(select(func.count(PortalSettings.id)))).scalar()
    if portal_count == 0:
        portal = PortalSettings(
            id=1,
            org_name="IntraGate",
            org_subtext="SECURE GATEWAY",
            logo_mode="none",
            primary_color="#1F4E79",
            accent_color="#8E44AD",
            footer_text="© 2026 IntraGate. All rights reserved. | Active Directory SSO Secured",
        )
        session.add(portal)
        log.info("Seeded PortalSettings")
    else:
        # Automatically migrate database values from legacy name to IntraGate if pre-existing
        portal_result = await session.execute(select(PortalSettings).filter(PortalSettings.id == 1))
        portal = portal_result.scalar_one_or_none()
        if portal and (portal.org_name == "IntraGate Engineering" or portal.org_name == "INTRAGATE"):
            portal.org_name = "IntraGate"
            portal.footer_text = "© 2026 IntraGate. All rights reserved. | Active Directory SSO Secured"
            session.add(portal)
            log.info("Migrated existing DB portal settings from legacy name to IntraGate")

    # 3. Seed GatewaySettings
    gw_count = (await session.execute(select(func.count(GatewaySettings.id)))).scalar()
    if gw_count == 0:
        base_url = os.environ.get("GATEWAY_BASE_URL", "https://intragate.local")
        lifetime = int(os.environ.get("SESSION_LIFETIME_HOURS", "12"))

        # If we had env settings before, we mark setup as complete
        has_env_setup = bool(os.environ.get("AZURE_TENANT_ID") and os.environ.get("GROUP_DISPATCH"))

        gw = GatewaySettings(
            id=1,
            gateway_base_url=base_url,
            session_lifetime_hours=lifetime,
            session_timeout_minutes=60, # Default to 60 mins inactivity timeout
            setup_complete=has_env_setup,
        )
        session.add(gw)
        log.info("Seeded GatewaySettings (setup_complete=%s)", has_env_setup)

    # 4. Seed Applications
    app_count = (await session.execute(select(func.count(Application.id)))).scalar()
    if app_count == 0:
        default_apps = [
            {
                "slug": "dispatch",
                "name": "Dispatch Planning",
                "description": "Schneider Electric & Eaton dispatch schedule generator",
                "icon": "📦",
                "env_group": "GROUP_DISPATCH",
                "env_upstream": "DISPATCH_UPSTREAM",
                "default_group": "ae8dbe8c-f030-4f5c-8f56-060bccd6ace4",
                "default_upstream": "http://dispatch-app:8001",
                "color": "#1F4E79",
                "gradient": "linear-gradient(135deg, #1F4E79 0%, #2980B9 100%)",
                "sort_order": 0,
            },
            {
                "slug": "assembly",
                "name": "FG Assembly Planning",
                "description": "LUG assembly shift plan & manpower forecasting",
                "icon": "🏭",
                "env_group": "GROUP_ASSEMBLY",
                "env_upstream": "ASSEMBLY_UPSTREAM",
                "default_group": "2938b79a-b83e-41f2-9e21-01f70014e3ea",
                "default_upstream": "http://assembly-app:8002",
                "color": "#27AE60",
                "gradient": "linear-gradient(135deg, #27AE60 0%, #2ECC71 100%)",
                "sort_order": 1,
            },
            {
                "slug": "quality",
                "name": "Supplier Quality Dashboard",
                "description": "Supplier PPM monitoring & defect analytics",
                "icon": "📊",
                "env_group": "GROUP_QUALITY",
                "env_upstream": "QUALITY_UPSTREAM",
                "default_group": "ba805f21-2393-4593-92f2-91cfb9178718",
                "default_upstream": "http://quality-app:8003",
                "color": "#8E44AD",
                "gradient": "linear-gradient(135deg, #8E44AD 0%, #9B59B6 100%)",
                "sort_order": 2,
            },
            {
                "slug": "vmc",
                "name": "VMC Machine Planning",
                "description": "CNC machine scheduling & operator allocation",
                "icon": "⚙️",
                "env_group": "GROUP_VMC",
                "env_upstream": "VMC_UPSTREAM",
                "default_group": "18cabeb5-53a0-4eb5-b1df-55cece1fd69f",
                "default_upstream": "http://vmc-app:8004",
                "color": "#E74C3C",
                "gradient": "linear-gradient(135deg, #E74C3C 0%, #C0392B 100%)",
                "sort_order": 3,
            },
        ]

        for a in default_apps:
            group_id = os.environ.get(a["env_group"], a["default_group"])
            upstream_url = os.environ.get(a["env_upstream"], a["default_upstream"])
            up_scheme, up_ip, up_port = _parse_upstream(upstream_url)

            app = Application(
                slug=a["slug"],
                name=a["name"],
                description=a["description"],
                icon=a["icon"],
                group_id=group_id,
                upstream_scheme=up_scheme,
                upstream_ip=up_ip,
                upstream_port=up_port,
                color=a["color"],
                gradient=a["gradient"],
                is_enabled=True,
                sort_order=a["sort_order"],
            )
            session.add(app)
            log.info("Seeded default application: %s", a["name"])

    try:
        await session.commit()
    except Exception as e:
        await session.rollback()
        # If it's a unique constraint or duplicate key error, the database has already been seeded by another process/worker.
        log.info("Database seeding skipped or already completed: %s", str(e))

