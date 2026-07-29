"""Admin authentication — local username/password + optional TOTP.

Completely separate from Entra ID. Uses bcrypt for password hashing
and pyotp for TOTP (Google Authenticator, Authy, etc.).
"""
from __future__ import annotations

import base64
import io
import logging
import secrets
import time

import bcrypt
import pyotp
import qrcode
from sqlalchemy import delete, func, select

from .database import AsyncSessionLocal
from .db_models import AdminSession, AdminUser

log = logging.getLogger("gateway.admin_auth")

_ADMIN_SESSION_MAX_AGE = 3600 * 8  # 8 hours
ADMIN_COOKIE_NAME = "intragate_admin_sid"


def _hash_password(password: str) -> str:
    """Hash a password with bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def _generate_totp_secret() -> str:
    """Generate a new TOTP secret."""
    return pyotp.random_base32()


def _verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code against a secret."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def generate_totp_qr(secret: str, username: str, issuer: str = "IntraGate") -> str:
    """Generate a QR code PNG as base64 for TOTP enrollment."""
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name=issuer)
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer)
    buffer.seek(0)
    return base64.b64encode(buffer.read()).decode("utf-8")


# ── Admin user management ────────────────────────────────────

async def admin_exists() -> bool:
    """Check if any admin user exists (for first-time setup)."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(func.count(AdminUser.id)))
        count = result.scalar()
        return count > 0


async def create_admin(username: str, password: str) -> dict:
    """Create the admin user (first-time setup only)."""
    if await admin_exists():
        raise ValueError("Admin user already exists")

    hashed = _hash_password(password)
    admin = AdminUser(username=username, password_hash=hashed)

    async with AsyncSessionLocal() as session:
        session.add(admin)
        await session.commit()
        await session.refresh(admin)

    log.info("Admin user created: %s", username)
    return {"id": admin.id, "username": admin.username}


async def authenticate_admin(username: str, password: str) -> dict | None:
    """Authenticate admin. Returns admin dict or None."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AdminUser).where(AdminUser.username == username)
        )
        admin = result.scalar_one_or_none()

    if not admin:
        return None
    if not _verify_password(password, admin.password_hash):
        return None

    return {
        "id": admin.id,
        "username": admin.username,
        "totp_enabled": admin.totp_enabled,
        "totp_secret": admin.totp_secret,
    }


async def verify_admin_totp(admin_id: str, code: str) -> bool:
    """Verify TOTP code for an admin user."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AdminUser).where(AdminUser.id == admin_id)
        )
        admin = result.scalar_one_or_none()

    if not admin or not admin.totp_secret:
        return False

    return _verify_totp(admin.totp_secret, code)


async def setup_totp(admin_id: str) -> dict:
    """Generate a new TOTP secret and QR code for enrollment."""
    secret = _generate_totp_secret()

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AdminUser).where(AdminUser.id == admin_id)
        )
        admin = result.scalar_one_or_none()
        if not admin:
            raise ValueError("Admin not found")

        admin.totp_secret = secret
        await session.commit()
        await session.refresh(admin)

    qr_base64 = generate_totp_qr(secret, admin.username)
    return {"secret": secret, "qr_code": qr_base64}


async def confirm_totp(admin_id: str, code: str) -> bool:
    """Confirm TOTP enrollment by verifying first code and enabling."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AdminUser).where(AdminUser.id == admin_id)
        )
        admin = result.scalar_one_or_none()
        if not admin or not admin.totp_secret:
            return False

        if not _verify_totp(admin.totp_secret, code):
            return False

        admin.totp_enabled = True
        await session.commit()

    log.info("TOTP enabled for admin: %s", admin.username)
    return True


async def disable_totp(admin_id: str) -> bool:
    """Disable TOTP for an admin user."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AdminUser).where(AdminUser.id == admin_id)
        )
        admin = result.scalar_one_or_none()
        if not admin:
            return False

        admin.totp_enabled = False
        admin.totp_secret = None
        await session.commit()

    log.info("TOTP disabled for admin: %s", admin.username)
    return True


async def change_admin_password(admin_id: str, old_password: str, new_password: str) -> bool:
    """Change admin password."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AdminUser).where(AdminUser.id == admin_id)
        )
        admin = result.scalar_one_or_none()
        if not admin:
            return False

        if not _verify_password(old_password, admin.password_hash):
            return False

        admin.password_hash = _hash_password(new_password)
        await session.commit()

    log.info("Password changed for admin: %s", admin.username)
    return True


# ── Admin session management ─────────────────────────────────

async def create_admin_session(admin_id: str, username: str) -> str:
    """Create an admin session in the database and return the session ID."""
    sid = secrets.token_hex(24)
    now = time.time()
    async with AsyncSessionLocal() as session:
        db_sess = AdminSession(
            session_id=sid,
            admin_id=admin_id,
            username=username,
            created_at=now,
            last_active=now,
        )
        session.add(db_sess)
        await session.commit()
    return sid


async def validate_admin_session(sid: str | None) -> dict | None:
    """Validate an admin session. Returns session data or None."""
    if not sid:
        return None
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AdminSession).where(AdminSession.session_id == sid)
        )
        db_sess = result.scalar_one_or_none()

    if not db_sess:
        return None

    now = time.time()
    if now - db_sess.created_at > _ADMIN_SESSION_MAX_AGE:
        async with AsyncSessionLocal() as session:
            await session.execute(
                delete(AdminSession).where(AdminSession.session_id == sid)
            )
            await session.commit()
        return None

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AdminSession).where(AdminSession.session_id == sid)
        )
        db_sess = result.scalar_one_or_none()
        if db_sess:
            db_sess.last_active = now
            await session.commit()

            return {
                "admin_id": db_sess.admin_id,
                "username": db_sess.username,
                "created_at": db_sess.created_at,
                "last_active": now,
            }
    return None


async def destroy_admin_session(sid: str | None) -> None:
    """Destroy an admin session."""
    if sid:
        async with AsyncSessionLocal() as session:
            await session.execute(
                delete(AdminSession).where(AdminSession.session_id == sid)
            )
            await session.commit()


async def cleanup_expired_admin_sessions() -> int:
    """Purge expired admin sessions from database."""
    now = time.time()
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            delete(AdminSession).where(
                (AdminSession.created_at < now - _ADMIN_SESSION_MAX_AGE) |
                (AdminSession.last_active < now - _ADMIN_SESSION_MAX_AGE)
            )
        )
        count = result.rowcount
        await session.commit()
    return count
