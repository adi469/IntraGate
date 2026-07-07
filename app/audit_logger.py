"""Audit logging utility for security events, user logins, and access tracking."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import Request
from sqlalchemy import delete

from .database import AsyncSessionLocal
from .db_models import SecurityLog

log = logging.getLogger("gateway.audit")


from .config import TRUSTED_PROXIES


def get_client_ip(request: Request) -> str:
    """Safely extract the real client IP address, checking proxy headers only if from a trusted proxy."""
    direct_ip = request.client.host if request.client else "unknown"
    if direct_ip in TRUSTED_PROXIES:
        x_forwarded_for = request.headers.get("x-forwarded-for")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        x_real_ip = request.headers.get("x-real-ip")
        if x_real_ip:
            return x_real_ip
    return direct_ip


async def log_security_event(
    event_type: str,
    user_email: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
    app_slug: str | None = None,
    app_name: str | None = None,
    details: str | None = None,
):
    """Asynchronously record a security event into the database.

    Guarantees exceptions are caught and logged to stdout rather than crashing requests.
    """
    try:
        async with AsyncSessionLocal() as session:
            entry = SecurityLog(
                event_type=event_type,
                user_email=user_email,
                ip_address=ip_address,
                user_agent=user_agent[:500] if user_agent else None,
                app_slug=app_slug,
                app_name=app_name,
                details=details,
            )
            session.add(entry)
            await session.commit()
            log.info("Audit log recorded: [%s] user=%s event=%s", datetime.now(timezone.utc).isoformat(), user_email, event_type)
    except Exception as e:
        log.error("Failed to write to security_logs database: %s", e)


async def prune_expired_logs() -> int:
    """Delete log entries older than 30 days. Returns number of rows deleted."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    try:
        async with AsyncSessionLocal() as session:
            q = delete(SecurityLog).where(SecurityLog.timestamp < cutoff)
            result = await session.execute(q)
            await session.commit()
            deleted_count = result.rowcount
            if deleted_count > 0:
                log.info("Pruned %d expired security logs older than 30 days", deleted_count)
            return deleted_count
    except Exception as e:
        log.error("Failed to prune old security logs: %s", e)
        return 0
