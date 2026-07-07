"""Server-side session store backed by PostgreSQL with token encryption at rest.

Sessions are keyed by a random session ID stored in a signed cookie.
The actual session data (user info, groups, tokens) lives server-side in the database.
Access and ID tokens are encrypted at rest using Fernet with the GATEWAY_ENCRYPTION_KEY.
"""
from __future__ import annotations

import logging
import secrets
import time

from cryptography.fernet import Fernet
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import delete, select

from .config import GATEWAY_ENCRYPTION_KEY, SECRET_KEY
from .database import AsyncSessionLocal
from .db_models import UserSession
from .models import GatewayUser

log = logging.getLogger("gateway.session")

_serializer = URLSafeTimedSerializer(SECRET_KEY)
COOKIE_NAME = "intragate_sid"

# Default values — overridden dynamically from config_store
_DEFAULT_MAX_AGE = 12 * 3600  # 12 hours
_DEFAULT_INACTIVITY_TIMEOUT = 60 * 60  # 60 minutes


def encrypt_tokens(user_dict: dict) -> dict:
    """Encrypt access_token and id_token in the user dictionary using Fernet."""
    d = dict(user_dict)
    fernet = Fernet(GATEWAY_ENCRYPTION_KEY)
    if d.get("access_token"):
        d["access_token"] = fernet.encrypt(d["access_token"].encode()).decode()
    if d.get("id_token"):
        d["id_token"] = fernet.encrypt(d["id_token"].encode()).decode()
    return d


def decrypt_tokens(user_dict: dict) -> dict:
    """Decrypt access_token and id_token in the user dictionary using Fernet."""
    d = dict(user_dict)
    fernet = Fernet(GATEWAY_ENCRYPTION_KEY)
    if d.get("access_token"):
        try:
            d["access_token"] = fernet.decrypt(d["access_token"].encode()).decode()
        except Exception as e:
            log.error("Failed to decrypt access token: %s", e)
            d["access_token"] = None
    if d.get("id_token"):
        try:
            d["id_token"] = fernet.decrypt(d["id_token"].encode()).decode()
        except Exception as e:
            log.error("Failed to decrypt id token: %s", e)
            d["id_token"] = None
    return d


async def create_session(user: GatewayUser) -> str:
    """Create a new database-backed session and return the signed cookie value."""
    sid = secrets.token_hex(24)
    now = time.time()
    user_dict_encrypted = encrypt_tokens(user.to_dict())

    async with AsyncSessionLocal() as session:
        db_sess = UserSession(
            session_id=sid,
            user_data=user_dict_encrypted,
            created_at=now,
            last_active=now,
        )
        session.add(db_sess)
        await session.commit()

    return _serializer.dumps(sid)


async def load_session(
    cookie_value: str | None,
    max_age_seconds: int | None = None,
    inactivity_seconds: int | None = None,
) -> GatewayUser | None:
    """Load a user from a database session. Returns None if invalid.

    Checks both absolute expiry and inactivity timeout.
    """
    if not cookie_value:
        return None

    effective_max_age = max_age_seconds or _DEFAULT_MAX_AGE

    try:
        sid = _serializer.loads(cookie_value, max_age=effective_max_age)
    except (BadSignature, SignatureExpired):
        return None

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(UserSession).where(UserSession.session_id == sid)
        )
        db_sess = result.scalar_one_or_none()

    if not db_sess:
        return None

    now = time.time()

    # Check absolute expiry
    if now - db_sess.created_at > effective_max_age:
        async with AsyncSessionLocal() as session:
            await session.execute(
                delete(UserSession).where(UserSession.session_id == sid)
            )
            await session.commit()
        return None

    # Check inactivity timeout
    effective_inactivity = inactivity_seconds or _DEFAULT_INACTIVITY_TIMEOUT
    if now - db_sess.last_active > effective_inactivity:
        async with AsyncSessionLocal() as session:
            await session.execute(
                delete(UserSession).where(UserSession.session_id == sid)
            )
            await session.commit()
        return None

    user_dict_decrypted = decrypt_tokens(db_sess.user_data)
    return GatewayUser.from_dict(user_dict_decrypted)


async def touch_session(cookie_value: str | None) -> None:
    """Update the last_active timestamp for a session (called on every request)."""
    if not cookie_value:
        return
    try:
        sid = _serializer.loads(cookie_value)
    except (BadSignature, SignatureExpired):
        return

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(UserSession).where(UserSession.session_id == sid)
        )
        db_sess = result.scalar_one_or_none()
        if db_sess:
            db_sess.last_active = time.time()
            await session.commit()


async def destroy_session(cookie_value: str | None) -> None:
    """Remove a session from the database store."""
    if not cookie_value:
        return
    try:
        sid = _serializer.loads(cookie_value)
    except (BadSignature, SignatureExpired):
        return

    async with AsyncSessionLocal() as session:
        await session.execute(
            delete(UserSession).where(UserSession.session_id == sid)
        )
        await session.commit()


async def cleanup_expired() -> int:
    """Purge expired sessions from the database. Returns count removed."""
    now = time.time()
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            delete(UserSession).where(
                (UserSession.created_at < now - _DEFAULT_MAX_AGE) |
                (UserSession.last_active < now - _DEFAULT_INACTIVITY_TIMEOUT)
            )
        )
        count = result.rowcount
        await session.commit()
    return count
