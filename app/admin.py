"""Admin Panel — FastAPI application running on port 8585.

Provides API endpoints for managing gateway configuration:
Entra ID, applications, portal customization, and settings.
"""
from __future__ import annotations

import logging
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, func, select
from starlette.middleware.sessions import SessionMiddleware

from .admin_auth import (
    ADMIN_COOKIE_NAME,
    admin_exists,
    authenticate_admin,
    change_admin_password,
    confirm_totp,
    create_admin,
    create_admin_session,
    destroy_admin_session,
    disable_totp,
    setup_totp,
    validate_admin_session,
    verify_admin_totp,
)
from .audit_logger import get_client_ip, log_security_event
from .config import GATEWAY_ENCRYPTION_KEY, SECRET_KEY
from .config_store import get_entra_config, invalidate_cache
from .database import AsyncSessionLocal, init_db
from .db_models import (
    AdminUser,
    Application,
    EntraConfig,
    GatewaySettings,
    PortalSettings,
    SecurityLog,
)

log = logging.getLogger("gateway.admin")

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "data" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

import time

admin_app = FastAPI(title="IntraGate Gateway Admin")
admin_app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
admin_app.mount(
    "/static",
    StaticFiles(directory=str(BASE_DIR / "static")),
    name="admin_static",
)

# Rate limiting trackers
_login_failures_ip: dict[str, dict[str, float | int]] = {}
_login_failures_user: dict[str, dict[str, float | int]] = {}


@admin_app.middleware("http")
async def admin_csrf_middleware(request: Request, call_next):
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if request.url.path.startswith("/admin/api/"):
            sec_fetch_site = request.headers.get("sec-fetch-site")
            if sec_fetch_site and sec_fetch_site == "cross-site":
                return JSONResponse({"detail": "CSRF validation failed: cross-site requests not allowed"}, status_code=403)

            host = request.headers.get("host", "")
            origin = request.headers.get("origin")
            referer = request.headers.get("referer")

            if not origin and not referer:
                return JSONResponse({"detail": "CSRF validation failed: missing Origin/Referer"}, status_code=403)

            if origin:
                from urllib.parse import urlparse
                parsed_origin = urlparse(origin)
                if parsed_origin.netloc != host:
                    return JSONResponse({"detail": "CSRF validation failed: origin mismatch"}, status_code=403)
            elif referer:
                from urllib.parse import urlparse
                parsed_referer = urlparse(referer)
                if parsed_referer.netloc != host:
                    return JSONResponse({"detail": "CSRF validation failed: referer mismatch"}, status_code=403)
    return await call_next(request)


@admin_app.middleware("http")
async def admin_security_headers_middleware(request: Request, call_next):
    nonce = secrets.token_urlsafe(16)
    request.state.nonce = nonce
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "connect-src 'self';"
    )
    return response


# ── Helpers ───────────────────────────────────────────────────

async def _get_admin_session(request: Request) -> dict:
    """Extract and validate admin session from cookie."""
    if hasattr(request.state, 'admin_session'):
        return request.state.admin_session
    sid = request.cookies.get(ADMIN_COOKIE_NAME)
    session = await validate_admin_session(sid)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    request.state.admin_session = session
    return session


def _set_session_cookie(response, sid: str):
    response.set_cookie(
        ADMIN_COOKIE_NAME, sid,
        max_age=3600 * 8, httponly=True, samesite="lax", path="/",
    )
    return response


def _slugify(name: str) -> str:
    slug = name.lower().strip()
    slug = re.sub(r'[^a-z0-9]+', '-', slug)
    slug = slug.strip('-')
    return slug or "app"


# ── Startup ───────────────────────────────────────────────────

@admin_app.on_event("startup")
async def startup():
    await init_db()


# ── Admin UI Page ─────────────────────────────────────────────

@admin_app.get("/", response_class=HTMLResponse)
async def admin_index(request: Request):
    admin_html = BASE_DIR / "static" / "admin" / "index.html"
    if admin_html.exists():
        html_content = admin_html.read_text()
        nonce = getattr(request.state, "nonce", "")
        html_content = html_content.replace('{{ nonce }}', nonce)
        return HTMLResponse(html_content)
    return HTMLResponse("<h1>Admin panel files not found</h1>", status_code=500)


# ── Setup & Auth ──────────────────────────────────────────────

@admin_app.get("/admin/api/check-setup")
async def check_setup():
    exists = await admin_exists()
    return {"admin_exists": exists}


@admin_app.post("/admin/api/setup")
async def first_time_setup(request: Request):
    if await admin_exists():
        raise HTTPException(400, "Admin already configured")
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "").strip()
    if not username or len(password) < 8:
        raise HTTPException(400, "Username required, password min 8 chars")
    admin = await create_admin(username, password)
    sid = await create_admin_session(admin["id"], admin["username"])
    await log_security_event(
        event_type="settings_change",
        user_email=admin["username"],
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details="Gateway initial administrator setup completed."
    )
    resp = JSONResponse({"ok": True, "username": admin["username"]})
    return _set_session_cookie(resp, sid)


@admin_app.post("/admin/api/login")
async def admin_login(request: Request):
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "")
    totp_code = body.get("totp_code", "")

    now = time.time()
    ip_addr = get_client_ip(request)

    # Check brute force lockout status for both IP and username
    lockout_ip = _login_failures_ip.get(ip_addr)
    if lockout_ip and lockout_ip["lockout_until"] > now:
        remaining = int(lockout_ip["lockout_until"] - now)
        raise HTTPException(
            429,
            f"Too many failed login attempts from this IP. Temporarily locked. Try again in {remaining} seconds."
        )

    lockout_user = _login_failures_user.get(username)
    if lockout_user and lockout_user["lockout_until"] > now:
        remaining = int(lockout_user["lockout_until"] - now)
        raise HTTPException(
            429,
            f"Too many failed login attempts for this user account. Temporarily locked. Try again in {remaining} seconds."
        )

    admin = await authenticate_admin(username, password)
    if not admin:
        # Increment failed attempts for both IP and user
        ip_data = _login_failures_ip.get(ip_addr, {"attempts": 0, "lockout_until": 0.0})
        user_data = _login_failures_user.get(username, {"attempts": 0, "lockout_until": 0.0})

        ip_data["attempts"] += 1
        user_data["attempts"] += 1

        is_ip_lockout = ip_data["attempts"] >= 5
        is_user_lockout = user_data["attempts"] >= 5

        if is_ip_lockout:
            ip_data["lockout_until"] = now + 300.0
        if is_user_lockout:
            user_data["lockout_until"] = now + 300.0

        _login_failures_ip[ip_addr] = ip_data
        _login_failures_user[username] = user_data

        if is_ip_lockout or is_user_lockout:
            trigger = "IP and username" if (is_ip_lockout and is_user_lockout) else ("IP" if is_ip_lockout else "username")
            await log_security_event(
                event_type="brute_force_lockout",
                user_email=username,
                ip_address=ip_addr,
                user_agent=request.headers.get("user-agent"),
                details=f"Admin login locked out for 5 minutes due to 5 consecutive failures triggered by {trigger} limit"
            )
            raise HTTPException(429, f"Too many failed login attempts. Locked out for 5 minutes by {trigger} limit.")
        else:
            await log_security_event(
                event_type="failed_login",
                user_email=username,
                ip_address=ip_addr,
                user_agent=request.headers.get("user-agent"),
                details=f"Admin login failed (IP attempts: {ip_data['attempts']}/5, Username attempts: {user_data['attempts']}/5)"
            )
            raise HTTPException(401, "Invalid credentials")

    if admin["totp_enabled"]:
        if not totp_code:
            return JSONResponse({"requires_totp": True})
        if not await verify_admin_totp(admin["id"], totp_code):
            # Increment failed attempts for both IP and user
            ip_data = _login_failures_ip.get(ip_addr, {"attempts": 0, "lockout_until": 0.0})
            user_data = _login_failures_user.get(username, {"attempts": 0, "lockout_until": 0.0})

            ip_data["attempts"] += 1
            user_data["attempts"] += 1

            is_ip_lockout = ip_data["attempts"] >= 5
            is_user_lockout = user_data["attempts"] >= 5

            if is_ip_lockout:
                ip_data["lockout_until"] = now + 300.0
            if is_user_lockout:
                user_data["lockout_until"] = now + 300.0

            _login_failures_ip[ip_addr] = ip_data
            _login_failures_user[username] = user_data

            if is_ip_lockout or is_user_lockout:
                trigger = "IP and username" if (is_ip_lockout and is_user_lockout) else ("IP" if is_ip_lockout else "username")
                await log_security_event(
                    event_type="brute_force_lockout",
                    user_email=username,
                    ip_address=ip_addr,
                    user_agent=request.headers.get("user-agent"),
                    details=f"Admin login locked out for 5 minutes due to 5 consecutive failures (TOTP) triggered by {trigger} limit"
                )
                raise HTTPException(429, f"Too many failed login attempts. Locked out for 5 minutes by {trigger} limit.")
            else:
                await log_security_event(
                    event_type="failed_login",
                    user_email=username,
                    ip_address=ip_addr,
                    user_agent=request.headers.get("user-agent"),
                    details=f"Admin TOTP verification failed (IP attempts: {ip_data['attempts']}/5, Username attempts: {user_data['attempts']}/5)"
                )
                raise HTTPException(401, "Invalid TOTP code")

    # Clear login failures on success
    _login_failures_ip.pop(ip_addr, None)
    _login_failures_user.pop(username, None)

    sid = await create_admin_session(admin["id"], admin["username"])
    await log_security_event(
        event_type="admin_login",
        user_email=admin["username"],
        ip_address=ip_addr,
        user_agent=request.headers.get("user-agent"),
        details="Administrator logged in successfully"
    )
    resp = JSONResponse({"ok": True, "username": admin["username"]})
    return _set_session_cookie(resp, sid)


@admin_app.post("/admin/api/logout")
async def admin_logout(request: Request):
    sid = request.cookies.get(ADMIN_COOKIE_NAME)
    session = await validate_admin_session(sid)
    username = session["username"] if session else "admin"
    await destroy_admin_session(sid)
    await log_security_event(
        event_type="admin_logout",
        user_email=username,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details="Administrator logged out"
    )
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(ADMIN_COOKIE_NAME, path="/")
    return resp


@admin_app.get("/admin/api/me")
async def admin_me(request: Request):
    session = await _get_admin_session(request)
    # Fetch TOTP status
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(AdminUser).where(AdminUser.id == session["admin_id"])
        )
        admin = result.scalar_one_or_none()
    return {
        "username": session["username"],
        "totp_enabled": admin.totp_enabled if admin else False,
    }


# ── TOTP Management ──────────────────────────────────────────

@admin_app.post("/admin/api/totp/setup")
async def totp_setup_endpoint(request: Request):
    session = await _get_admin_session(request)
    data = await setup_totp(session["admin_id"])
    return data


@admin_app.post("/admin/api/totp/confirm")
async def totp_confirm_endpoint(request: Request):
    session = await _get_admin_session(request)
    body = await request.json()
    code = body.get("code", "")
    ok = await confirm_totp(session["admin_id"], code)
    if not ok:
        raise HTTPException(400, "Invalid TOTP code")
    await log_security_event(
        event_type="totp_enable",
        user_email=session["username"],
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details="Two-factor authentication (TOTP) successfully enabled"
    )
    return {"ok": True}


@admin_app.post("/admin/api/totp/disable")
async def totp_disable_endpoint(request: Request):
    session = await _get_admin_session(request)
    await disable_totp(session["admin_id"])
    await log_security_event(
        event_type="totp_disable",
        user_email=session["username"],
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details="Two-factor authentication (TOTP) disabled"
    )
    return {"ok": True}


# ── Password Change ───────────────────────────────────────────

@admin_app.post("/admin/api/change-password")
async def change_password_endpoint(request: Request):
    session = await _get_admin_session(request)
    body = await request.json()
    ok = await change_admin_password(
        session["admin_id"],
        body.get("old_password", ""),
        body.get("new_password", ""),
    )
    if not ok:
        raise HTTPException(400, "Invalid current password")
    await log_security_event(
        event_type="password_change",
        user_email=session["username"],
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details="Administrator password changed successfully"
    )
    return {"ok": True}


# ── Entra ID ──────────────────────────────────────────────────

@admin_app.get("/admin/api/entra")
async def get_entra(request: Request):
    await _get_admin_session(request)
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(EntraConfig).where(EntraConfig.id == 1))
        row = result.scalar_one_or_none()
    if not row:
        return {"tenant_id": "", "client_id": "", "client_secret_set": False,
                "connection_verified": False, "last_verified_at": None}
    return {
        "tenant_id": row.tenant_id,
        "client_id": row.client_id,
        "client_secret_set": bool(row.client_secret),
        "connection_verified": row.connection_verified,
        "last_verified_at": row.last_verified_at.isoformat() if row.last_verified_at else None,
    }


@admin_app.post("/admin/api/entra")
async def save_entra(request: Request):
    await _get_admin_session(request)
    body = await request.json()
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(EntraConfig).where(EntraConfig.id == 1))
        row = result.scalar_one_or_none()
        if not row:
            row = EntraConfig(id=1)
            session.add(row)
        row.tenant_id = body.get("tenant_id", "").strip()
        row.client_id = body.get("client_id", "").strip()
        secret = body.get("client_secret", "").strip()
        if secret:
            from cryptography.fernet import Fernet
            f = Fernet(GATEWAY_ENCRYPTION_KEY)
            row.client_secret = f.encrypt(secret.encode()).decode()
        row.connection_verified = False
        await session.commit()
    await invalidate_cache("entra")
    admin_session = await _get_admin_session(request)
    await log_security_event(
        event_type="settings_change",
        user_email=admin_session["username"],
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details="Administrator updated Microsoft Entra ID credentials"
    )
    return {"ok": True}


@admin_app.post("/admin/api/entra/test")
async def test_entra(request: Request):
    await _get_admin_session(request)
    entra_config = await get_entra_config()
    tenant_id = entra_config.get("tenant_id")
    client_id = entra_config.get("client_id")
    client_secret = entra_config.get("client_secret")

    if not tenant_id:
        raise HTTPException(400, "Entra ID not configured")

    steps = []
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    discovery = f"{authority}/v2.0/.well-known/openid-configuration"

    # Step 1: OIDC Discovery
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(discovery)
        if resp.status_code == 200:
            steps.append({"step": "OIDC Discovery", "status": "ok", "detail": "Tenant found"})
        else:
            steps.append({"step": "OIDC Discovery", "status": "error",
                          "detail": f"HTTP {resp.status_code}"})
            return {"steps": steps, "verified": False}
    except Exception as e:
        steps.append({"step": "OIDC Discovery", "status": "error", "detail": str(e)})
        return {"steps": steps, "verified": False}

    # Step 2: Client credentials test
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{authority}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                },
            )
        if resp.status_code == 200:
            steps.append({"step": "Client Auth", "status": "ok",
                          "detail": "Credentials valid"})
        else:
            detail = resp.json().get("error_description", f"HTTP {resp.status_code}")
            steps.append({"step": "Client Auth", "status": "error", "detail": detail[:200]})
            return {"steps": steps, "verified": False}
    except Exception as e:
        steps.append({"step": "Client Auth", "status": "error", "detail": str(e)})
        return {"steps": steps, "verified": False}

    # Step 3: Check Graph API permissions
    try:
        token = resp.json().get("access_token", "")
        async with httpx.AsyncClient(timeout=10) as client:
            resp2 = await client.get(
                "https://graph.microsoft.com/v1.0/organization",
                headers={"Authorization": f"Bearer {token}"},
            )
        if resp2.status_code == 200:
            steps.append({"step": "Graph API", "status": "ok",
                          "detail": "Permissions OK"})
        else:
            steps.append({"step": "Graph API", "status": "warning",
                          "detail": "Limited permissions (delegated flow may still work)"})
    except Exception as e:
        steps.append({"step": "Graph API", "status": "warning", "detail": str(e)})

    # Mark as verified
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(EntraConfig).where(EntraConfig.id == 1))
        row = result.scalar_one_or_none()
        if row:
            row.connection_verified = True
            row.last_verified_at = datetime.now(timezone.utc)
            await db.commit()
    await invalidate_cache("entra")
    return {"steps": steps, "verified": True}


# ── Applications ──────────────────────────────────────────────

@admin_app.get("/admin/api/apps")
async def list_apps(request: Request):
    await _get_admin_session(request)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Application).order_by(Application.sort_order, Application.name)
        )
        apps = result.scalars().all()
    return [
        {
            "id": a.id, "slug": a.slug, "name": a.name,
            "description": a.description, "icon": a.icon,
            "group_id": a.group_id, "upstream_scheme": a.upstream_scheme,
            "upstream_ip": a.upstream_ip,
            "upstream_port": a.upstream_port, "tls_verify": a.tls_verify,
            "color": a.color, "gradient": a.gradient, "is_enabled": a.is_enabled,
            "sort_order": a.sort_order,
        }
        for a in apps
    ]


@admin_app.post("/admin/api/apps")
async def create_app(request: Request):
    await _get_admin_session(request)
    body = await request.json()
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(400, "Name is required")
    slug = body.get("slug", "").strip() or _slugify(name)
    # Check uniqueness
    async with AsyncSessionLocal() as session:
        exists = await session.execute(
            select(Application).where(Application.slug == slug)
        )
        if exists.scalar_one_or_none():
            raise HTTPException(409, f"App slug '{slug}' already exists")
        app = Application(
            slug=slug, name=name,
            description=body.get("description", ""),
            icon=body.get("icon", "🔧"),
            group_id=body.get("group_id", ""),
            upstream_scheme=body.get("upstream_scheme", "http").strip() or "http",
            upstream_ip=body.get("upstream_ip", "127.0.0.1"),
            upstream_port=int(body.get("upstream_port", 8080)),
            tls_verify=body.get("tls_verify", True),
            color=body.get("color", "#1F4E79"),
            gradient=body.get("gradient", "linear-gradient(135deg, #1F4E79 0%, #2980B9 100%)"),
            is_enabled=body.get("is_enabled", True),
            sort_order=int(body.get("sort_order", 0)),
        )
        session.add(app)
        await session.commit()
        await session.refresh(app)
    await invalidate_cache("apps")
    admin_session = await _get_admin_session(request)
    await log_security_event(
        event_type="settings_change",
        user_email=admin_session["username"],
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details=f"Administrator added application '{name}' (slug: {slug})"
    )
    return {"ok": True, "id": app.id, "slug": app.slug}


@admin_app.put("/admin/api/apps/{slug}")
async def update_app(request: Request, slug: str):
    await _get_admin_session(request)
    body = await request.json()
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Application).where(Application.slug == slug)
        )
        app = result.scalar_one_or_none()
        if not app:
            raise HTTPException(404, "App not found")
        for field in ["name", "description", "icon", "group_id",
                      "upstream_scheme", "upstream_ip", "color", "gradient", "tls_verify"]:
            if field in body:
                setattr(app, field, body[field])
        if "upstream_port" in body:
            app.upstream_port = int(body["upstream_port"])
        if "is_enabled" in body:
            app.is_enabled = bool(body["is_enabled"])
        if "sort_order" in body:
            app.sort_order = int(body["sort_order"])
        await session.commit()
    await invalidate_cache("apps")
    admin_session = await _get_admin_session(request)
    await log_security_event(
        event_type="settings_change",
        user_email=admin_session["username"],
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details=f"Administrator updated application settings for slug: {slug}"
    )
    return {"ok": True}


@admin_app.delete("/admin/api/apps/{slug}")
async def delete_app(request: Request, slug: str):
    await _get_admin_session(request)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Application).where(Application.slug == slug)
        )
        app = result.scalar_one_or_none()
        if not app:
            raise HTTPException(404, "App not found")
        await session.delete(app)
        await session.commit()
    await invalidate_cache("apps")
    admin_session = await _get_admin_session(request)
    await log_security_event(
        event_type="settings_change",
        user_email=admin_session["username"],
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details=f"Administrator deleted application: {slug}"
    )
    return {"ok": True}


# ── Portal Settings ───────────────────────────────────────────

@admin_app.get("/admin/api/portal")
async def get_portal(request: Request):
    await _get_admin_session(request)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(PortalSettings).where(PortalSettings.id == 1)
        )
        row = result.scalar_one_or_none()
    if not row:
        return {}
    return {
        "org_name": row.org_name, "org_subtext": row.org_subtext,
        "logo_mode": row.logo_mode, "logo_url": row.logo_url,
        "logo_file_path": row.logo_file_path,
        "primary_color": row.primary_color, "accent_color": row.accent_color,
        "footer_text": row.footer_text,
    }


@admin_app.put("/admin/api/portal")
async def update_portal(request: Request):
    await _get_admin_session(request)
    body = await request.json()

    # Validate hex colors if present
    color_regex = re.compile(r"^#[0-9a-fA-F]{3,8}$")
    for field in ("primary_color", "accent_color"):
        if field in body and body[field]:
            val = str(body[field]).strip()
            if not color_regex.match(val):
                raise HTTPException(400, f"Invalid color hex code format for {field}")

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(PortalSettings).where(PortalSettings.id == 1)
        )
        row = result.scalar_one_or_none()
        if not row:
            row = PortalSettings(id=1)
            session.add(row)
        for field in ["org_name", "org_subtext", "logo_mode", "logo_url",
                      "primary_color", "accent_color", "footer_text"]:
            if field in body:
                setattr(row, field, body[field])
        await session.commit()
    await invalidate_cache("portal")
    admin_session = await _get_admin_session(request)
    await log_security_event(
        event_type="settings_change",
        user_email=admin_session["username"],
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details="Administrator updated user portal customization/branding settings"
    )
    return {"ok": True}


@admin_app.post("/admin/api/portal/logo")
async def upload_logo(request: Request, file: UploadFile = File(...)):
    await _get_admin_session(request)
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(400, "File too large (max 5MB)")

    import io

    from PIL import Image

    try:
        # Load image via PIL to verify it's a real image and check dimensions
        image = Image.open(io.BytesIO(content))
        image.verify()  # Verifies image integrity

        # Re-open because verify() closes/invalidates the file object
        image = Image.open(io.BytesIO(content))
        width, height = image.size
        if width > 400 or height > 400:
            raise HTTPException(400, f"Image dimensions ({width}x{height}) exceed 400x400 limit")

        # Restrict format to safe formats
        fmt = (image.format or "").upper()
        if fmt not in ("PNG", "JPEG", "GIF", "WEBP"):
            raise HTTPException(400, f"Unsupported image format: {fmt}. Please use PNG, JPEG, GIF or WEBP.")
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(400, "Invalid image file or corrupt image data")

    # Sanitize filename & extension based on PIL format (avoid using client-supplied filename directly)
    ext = ".jpg" if fmt == "JPEG" else f".{fmt.lower()}"
    filename = f"org_logo{ext}"
    dest = UPLOAD_DIR / filename

    import aiofiles
    async with aiofiles.open(dest, "wb") as f:
        await f.write(content)

    # Update DB
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(PortalSettings).where(PortalSettings.id == 1)
        )
        row = result.scalar_one_or_none()
        if row:
            row.logo_mode = "file"
            row.logo_file_path = f"/uploads/{filename}"
            await session.commit()
    await invalidate_cache("portal")
    admin_session = await _get_admin_session(request)
    await log_security_event(
        event_type="settings_change",
        user_email=admin_session["username"],
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details="Administrator uploaded new organization logo image"
    )
    return {"ok": True, "path": f"/uploads/{filename}"}


# ── Gateway Settings ──────────────────────────────────────────

@admin_app.get("/admin/api/settings")
async def get_settings(request: Request):
    await _get_admin_session(request)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(GatewaySettings).where(GatewaySettings.id == 1)
        )
        row = result.scalar_one_or_none()
    if not row:
        return {}
    return {
        "gateway_base_url": row.gateway_base_url,
        "session_lifetime_hours": row.session_lifetime_hours,
        "session_timeout_minutes": row.session_timeout_minutes,
        "setup_complete": row.setup_complete,
    }


@admin_app.put("/admin/api/settings")
async def update_settings(request: Request):
    await _get_admin_session(request)
    body = await request.json()

    if "gateway_base_url" in body:
        url = body["gateway_base_url"].strip()
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            if not parsed.scheme or parsed.scheme not in ("http", "https") or not parsed.netloc:
                raise ValueError()
        except Exception:
            raise HTTPException(400, "Invalid gateway base URL format. Must be a valid http or https URL.")

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(GatewaySettings).where(GatewaySettings.id == 1)
        )
        row = result.scalar_one_or_none()
        if not row:
            row = GatewaySettings(id=1)
            session.add(row)
        if "gateway_base_url" in body:
            row.gateway_base_url = body["gateway_base_url"].strip().rstrip("/")
        if "session_lifetime_hours" in body:
            row.session_lifetime_hours = max(1, min(720, int(body["session_lifetime_hours"])))
        if "session_timeout_minutes" in body:
            row.session_timeout_minutes = max(5, min(480, int(body["session_timeout_minutes"])))
        if "setup_complete" in body:
            row.setup_complete = bool(body["setup_complete"])
        await session.commit()
    await invalidate_cache("gateway")
    admin_session = await _get_admin_session(request)
    await log_security_event(
        event_type="settings_change",
        user_email=admin_session["username"],
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details="Administrator updated global gateway settings"
    )
    return {"ok": True}


# ── System Status ─────────────────────────────────────────────

@admin_app.get("/admin/api/status")
async def system_status(request: Request):
    await _get_admin_session(request)
    async with AsyncSessionLocal() as session:
        entra = (await session.execute(
            select(EntraConfig).where(EntraConfig.id == 1)
        )).scalar_one_or_none()
        app_count = (await session.execute(
            select(func.count(Application.id))
        )).scalar()
        gw = (await session.execute(
            select(GatewaySettings).where(GatewaySettings.id == 1)
        )).scalar_one_or_none()

        import time

        from .db_models import UserSession
        now = time.time()
        max_age = ((gw.session_lifetime_hours if gw else 12) or 12) * 3600
        inactivity = ((gw.session_timeout_minutes if gw else 60) or 60) * 60

        active_sessions = (await session.execute(
            select(func.count(UserSession.session_id)).where(
                (UserSession.created_at >= now - max_age) &
                (UserSession.last_active >= now - inactivity)
            )
        )).scalar() or 0

    return {
        "entra_connected": entra.connection_verified if entra else False,
        "app_count": app_count or 0,
        "active_user_sessions": active_sessions,
        "session_timeout_minutes": gw.session_timeout_minutes if gw else 60,
        "setup_complete": gw.setup_complete if gw else False,
    }


# ── Audit Logs API ───────────────────────────────────────────

@admin_app.get("/admin/api/logs")
async def get_audit_logs(
    request: Request,
    event_type: str | None = None,
    user_email: str | None = None,
    limit: int = 100,
    offset: int = 0
):
    await _get_admin_session(request)
    async with AsyncSessionLocal() as session:
        q = select(SecurityLog)

        # Apply filters
        if event_type and event_type != "all":
            q = q.where(SecurityLog.event_type == event_type)
        if user_email:
            q = q.where(SecurityLog.user_email.ilike(f"%{user_email.strip()}%"))

        # Get total count for pagination
        count_q = select(func.count()).select_from(q.subquery())
        total_count = (await session.execute(count_q)).scalar() or 0

        # Order by newest first
        q = q.order_by(desc(SecurityLog.timestamp)).offset(offset).limit(limit)
        result = await session.execute(q)
        logs = result.scalars().all()

    return {
        "logs": [
            {
                "id": log.id,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "event_type": log.event_type,
                "user_email": log.user_email,
                "ip_address": log.ip_address,
                "user_agent": log.user_agent,
                "app_slug": log.app_slug,
                "app_name": log.app_name,
                "details": log.details
            } for log in logs
        ],
        "total_count": total_count,
        "limit": limit,
        "offset": offset
    }


@admin_app.get("/admin/api/logs/export/csv")
async def export_logs_csv(
    request: Request,
    event_type: str | None = None,
    user_email: str | None = None
):
    await _get_admin_session(request)

    async with AsyncSessionLocal() as session:
        q = select(SecurityLog)
        if event_type and event_type != "all":
            q = q.where(SecurityLog.event_type == event_type)
        if user_email:
            q = q.where(SecurityLog.user_email.ilike(f"%{user_email.strip()}%"))

        q = q.order_by(desc(SecurityLog.timestamp))
        result = await session.execute(q)
        logs = result.scalars().all()

    import csv
    from io import StringIO

    from fastapi.responses import StreamingResponse

    def generate():
        output = StringIO()
        writer = csv.writer(output)
        # Header row
        writer.writerow(["ID", "Timestamp (UTC)", "Event Type", "User Email", "IP Address", "User Agent", "App Slug", "App Name", "Details"])
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)

        for log in logs:
            ts = log.timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.timestamp else ""
            writer.writerow([
                log.id,
                ts,
                log.event_type,
                log.user_email,
                log.ip_address or "",
                log.user_agent or "",
                log.app_slug or "",
                log.app_name or "",
                log.details or ""
            ])
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

    headers = {
        'Content-Disposition': 'attachment; filename="security_logs_export.csv"',
        'Content-Type': 'text/csv'
    }
    return StreamingResponse(generate(), headers=headers)


@admin_app.get("/admin/api/logs/export/pdf")
async def export_logs_pdf(
    request: Request,
    event_type: str | None = None,
    user_email: str | None = None
):
    await _get_admin_session(request)

    async with AsyncSessionLocal() as session:
        q = select(SecurityLog)
        if event_type and event_type != "all":
            q = q.where(SecurityLog.event_type == event_type)
        if user_email:
            q = q.where(SecurityLog.user_email.ilike(f"%{user_email.strip()}%"))

        q = q.order_by(desc(SecurityLog.timestamp))
        result = await session.execute(q)
        logs = result.scalars().all()

    from io import BytesIO

    from fastapi.responses import Response
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Table, TableStyle

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom color palette matching IntraGate dark/sleek theme
    primary_color = colors.HexColor("#1e293b")
    border_color = colors.HexColor("#cbd5e1")

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        textColor=primary_color,
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        textColor=colors.HexColor("#475569"),
        spaceAfter=15
    )

    table_text_style = ParagraphStyle(
        'TableText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        textColor=colors.HexColor("#0f172a")
    )

    header_text_style = ParagraphStyle(
        'TableHeaderText',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        textColor=colors.white
    )

    elements = []

    elements.append(Paragraph("IntraGate Secure Gateway", title_style))
    elements.append(Paragraph(f"Security Audit Log Report — Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))

    # Header row for table
    data = [
        [
            Paragraph("Timestamp (UTC)", header_text_style),
            Paragraph("Event", header_text_style),
            Paragraph("User", header_text_style),
            Paragraph("IP Address", header_text_style),
            Paragraph("Details", header_text_style)
        ]
    ]

    for log in logs:
        ts_str = log.timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.timestamp else "N/A"
        event_str = log.event_type.upper().replace("_", " ")
        details_str = log.details or ""

        # Color coding for Event type
        event_color = "#334155"
        if log.event_type == "access_denied":
            event_color = "#ef4444"
        elif log.event_type in ("login", "admin_login"):
            event_color = "#10b981"
        elif log.event_type == "app_access":
            event_color = "#3b82f6"

        event_p_style = ParagraphStyle(
            'EventStyle',
            parent=table_text_style,
            fontName='Helvetica-Bold',
            textColor=colors.HexColor(event_color)
        )

        data.append([
            Paragraph(ts_str, table_text_style),
            Paragraph(event_str, event_p_style),
            Paragraph(log.user_email, table_text_style),
            Paragraph(log.ip_address or "N/A", table_text_style),
            Paragraph(details_str, table_text_style)
        ])

    col_widths = [100, 85, 115, 80, 160]

    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), primary_color),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('TOPPADDING', (0,0), (-1,0), 6),
        ('BOTTOMPADDING', (0,1), (-1,-1), 5),
        ('TOPPADDING', (0,1), (-1,-1), 5),
        ('GRID', (0,0), (-1,-1), 0.5, border_color),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
    ]))

    elements.append(t)
    doc.build(elements)

    pdf_bytes = buffer.getvalue()
    buffer.close()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename=\"security_logs_export.pdf\""
        }
    )


# ── Serve uploaded files ──────────────────────────────────────


@admin_app.get("/uploads/{filename}")
async def serve_upload(filename: str):
    # Prevent path traversal
    safe_filename = Path(filename).name
    file_path = UPLOAD_DIR / safe_filename
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(404, "File not found")

    headers = {
        "Content-Security-Policy": "default-src 'none'",
        "X-Content-Type-Options": "nosniff",
        "Content-Disposition": "inline",
    }
    from fastapi.responses import FileResponse
    return FileResponse(str(file_path), headers=headers)
