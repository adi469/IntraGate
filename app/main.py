"""Main FastAPI Gateway Application.

Combines the OIDC auth flow, auth enforcement middleware,
portal views, and reverse-proxy routing for all internal apps.

Now uses dynamic config from admin panel (PostgreSQL) instead of
hardcoded .env-based APP_REGISTRY.
"""
from __future__ import annotations

import asyncio
import logging
import secrets
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .audit_logger import get_client_ip, log_security_event, prune_expired_logs
from .auth import callback, login, logout
from .config import SECRET_KEY
from .config_store import get_app_registry, get_portal_settings
from .database import close_db, init_db
from .middleware import AuthMiddleware
from .proxy import close_client, proxy_request

# Set up logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("gateway.main")

def inject_nonce(request: Request) -> dict:
    return {"nonce": getattr(request.state, "nonce", "")}

# Setup templates and static pathing
BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "data" / "uploads"
templates = Jinja2Templates(
    directory=str(BASE_DIR / "templates"),
    context_processors=[inject_nonce]
)


app = FastAPI(title="IntraGate Secure Gateway")

# Mount static files for CSS/Images
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/uploads/{filename}")
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


# Add SessionMiddleware (REQUIRED by authlib for storing oauth states/nonces)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# Add custom Auth Enforcement Middleware
app.add_middleware(AuthMiddleware)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
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


async def log_cleanup_worker():
    """Background worker to prune security logs older than 30 days every 24 hours."""
    while True:
        log.info("Starting background log cleanup task...")
        try:
            await prune_expired_logs()
        except Exception as e:
            log.error("Error in background log cleanup: %s", e)
        await asyncio.sleep(86400)


async def session_cleanup_worker():
    """Background worker to purge expired user and admin sessions every 1 hour."""
    from .admin_auth import cleanup_expired_admin_sessions
    from .session import cleanup_expired
    while True:
        log.info("Starting background session cleanup task...")
        try:
            user_cleaned = await cleanup_expired()
            admin_cleaned = await cleanup_expired_admin_sessions()
            log.info("Cleaned up %d user sessions and %d admin sessions.", user_cleaned, admin_cleaned)
        except Exception as e:
            log.error("Error in background session cleanup: %s", e)
        await asyncio.sleep(3600)


@app.on_event("startup")
async def startup_event():
    """Initialize database tables and run migration/seeding on startup."""
    await init_db()
    asyncio.create_task(log_cleanup_worker())
    asyncio.create_task(session_cleanup_worker())



@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup connections on application shutdown."""
    await close_client()
    await close_db()



# ─── Auth Endpoints ───────────────────────────────────────────

@app.get("/auth/login")
async def route_login(request: Request):
    """Initiate Microsoft Entra ID Login Flow."""
    return await login(request)


@app.get("/auth/callback")
async def route_callback(request: Request):
    """Handle callback from Microsoft Entra ID."""
    return await callback(request)


@app.get("/auth/logout")
async def route_logout(request: Request):
    """Clear local session and log out from Microsoft Entra ID."""
    return await logout(request)


# ─── Portal and Public Endpoints ──────────────────────────────

@app.get("/health")
async def health_check():
    """Health check endpoint for Traefik or local pinging."""
    return {"status": "healthy"}


@app.get("/setup-required", response_class=HTMLResponse)
async def setup_required_page(request: Request):
    """Shown when admin hasn't completed first-time setup."""
    portal = await get_portal_settings()
    return templates.TemplateResponse(
        request,
        "setup_required.html",
        {"portal": portal},
    )


@app.get("/", response_class=HTMLResponse)
async def portal_index(request: Request):
    """Render the application portal showing authorized apps."""
    user = getattr(request.state, "user", None)
    if not user:
        return RedirectResponse(url="/auth/login")

    # Load dynamic config
    app_registry = await get_app_registry()
    portal = await get_portal_settings()

    # Filter apps user has access to
    authorized_apps = []
    for slug, meta in app_registry.items():
        if not meta["group_id"]:
            log.warning("App '%s' has no group configured. Access denied.", slug)
            continue
        if user.in_group(meta["group_id"]):
            authorized_apps.append({
                "slug": slug,
                "name": meta["name"],
                "description": meta["description"],
                "icon": meta["icon"],
                "gradient": meta.get("gradient", "#34495e"),
            })

    return templates.TemplateResponse(
        request,
        "portal.html",
        {
            "user": user,
            "apps": authorized_apps,
            "portal": portal,
        }
    )


@app.get("/error", response_class=HTMLResponse)
async def error_page(request: Request, msg: str = "unknown"):
    """Generic error page."""
    portal = await get_portal_settings()
    messages = {
        "auth_failed": "Authentication with Microsoft Entra ID failed. Please try again.",
        "session_expired": "Your session has expired. Please log in again.",
        "setup_required": "Gateway setup is not complete. Please contact your administrator.",
        "unknown": "An unexpected error occurred."
    }
    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "message": messages.get(msg, messages["unknown"]),
            "portal": portal,
        }
    )


# ─── App Reverse Proxy Route ──────────────────────────────────

@app.api_route("/app/{app_slug}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def route_reverse_proxy(request: Request, app_slug: str, path: str):
    """Authorize and reverse-proxy requests to the internal applications."""
    user = getattr(request.state, "user", None)
    if not user:
        return RedirectResponse(url="/auth/login")

    # Get dynamic app configuration
    app_registry = await get_app_registry()
    app_info = app_registry.get(app_slug)
    if not app_info:
        raise HTTPException(status_code=404, detail="Application not found")

    # Verify authorization (Group Membership)
    required_group = app_info["group_id"]
    if not required_group or not user.in_group(required_group):
        log.warning(
            "User %s denied access to '%s' (required group: %s)",
            user.email, app_slug, required_group
        )
        await log_security_event(
            event_type="access_denied",
            user_email=user.email,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            app_slug=app_slug,
            app_name=app_info["name"],
            details=f"Access Denied: Missing Microsoft Entra Group ID {required_group}"
        )
        portal = await get_portal_settings()
        return templates.TemplateResponse(
            request,
            "forbidden.html",
            {
                "app_name": app_info["name"],
                "user": user,
                "portal": portal,
            },
            status_code=403
        )

    # Log successful app launch on first root access to application
    if not path or path == "/":
        await log_security_event(
            event_type="app_access",
            user_email=user.email,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            app_slug=app_slug,
            app_name=app_info["name"],
            details=f"Launched application: {app_info['name']}"
        )

    # Proxy the request
    response = await proxy_request(request, app_slug, user)
    response.set_cookie(
        "gateway_active_app",
        app_slug,
        path="/",
        httponly=True,
        samesite="lax",
    )
    return response


# Trapping root calls for apps to handle clean sub-routes
@app.api_route("/app/{app_slug}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def route_reverse_proxy_root(request: Request, app_slug: str):
    """Redirect root path without trailing slash to with trailing slash."""
    response = RedirectResponse(url=f"/app/{app_slug}/", status_code=307)
    response.set_cookie(
        "gateway_active_app",
        app_slug,
        path="/",
        httponly=True,
        samesite="lax",
    )
    return response
