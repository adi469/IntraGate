"""Auth enforcement middleware.

Runs on every request. Whitelists public paths (/auth/*, /static/*, /health, /uploads/*)
and requires a valid session for everything else.

Now includes:
- Setup-complete check: redirects to setup page if admin hasn't configured yet
- Inactivity timeout: reads dynamic settings from config_store
- Activity tracking: calls touch_session() on every authenticated request
- Referer-based fallback proxy routing: dynamically routes 404s for app assets (like `/static/*` or `/api/*`)
  using the HTTP Referer header, allowing unmodified internal apps to resolve their absolute links correctly.
"""
from __future__ import annotations

import logging
import re

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from .config_store import get_app_registry, get_gateway_settings, is_setup_complete
from .session import COOKIE_NAME, load_session, touch_session

log = logging.getLogger("gateway.middleware")

# Paths that do NOT require authentication
_PUBLIC_PREFIXES = (
    "/auth/",
    "/static/",
    "/health",
    "/favicon.ico",
    "/uploads/",
    "/setup-required",
    "/error",
)



class AuthMiddleware(BaseHTTPMiddleware):
    """Enforce authentication on all non-public routes."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        path = request.url.path

        # 1. Allow public paths through without auth, but check 404s for referer fallback routing
        if any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            response = await call_next(request)
            if response.status_code == 404:
                cookie_value = request.cookies.get(COOKIE_NAME)
                user = await self._get_user_from_cookie(cookie_value)
                if user:
                    fallback_resp = await self._handle_referer_fallback(request, path, user)
                    if fallback_resp:
                        return fallback_resp
            return response

        # Check if setup is complete
        try:
            setup_done = await is_setup_complete()
            if not setup_done and path not in ("/error",):
                return RedirectResponse(url="/setup-required", status_code=302)
        except Exception:
            # DB might not be ready yet — let the request through
            pass

        # 2. Authenticated path check
        cookie_value = request.cookies.get(COOKIE_NAME)
        user = await self._get_user_with_dynamic_lifetime(cookie_value)

        if user is None:
            if cookie_value:
                # Session cookie present but expired/invalid — redirect to session expired error page
                log.debug("Session expired for %s — redirecting to error page", path)
                response = RedirectResponse(url="/error?msg=session_expired", status_code=302)
                response.delete_cookie(COOKIE_NAME, path="/")
                return response
            else:
                # No session cookie at all — redirect to login
                log.debug("No session for %s — redirecting to login", path)
                return RedirectResponse(url="/auth/login", status_code=302)

        # Track activity for inactivity timeout
        await touch_session(cookie_value)

        # Attach the user to the request state for downstream handlers
        request.state.user = user

        response = await call_next(request)

        # 3. Referer fallback check for authenticated path 404s (e.g. backend /api calls)
        if response.status_code == 404:
            fallback_resp = await self._handle_referer_fallback(request, path, user)
            if fallback_resp:
                return fallback_resp

        return response

    async def _get_user_from_cookie(self, cookie_value: str | None):
        if not cookie_value:
            return None
        try:
            gw_settings = await get_gateway_settings()
            max_age = gw_settings.get("session_lifetime_hours", 12) * 3600
            inactivity = gw_settings.get("session_timeout_minutes", 60) * 60
        except Exception:
            max_age = 12 * 3600
            inactivity = 60 * 60
        try:
            return await load_session(cookie_value, max_age_seconds=max_age, inactivity_seconds=inactivity)
        except Exception:
            return None

    async def _get_user_with_dynamic_lifetime(self, cookie_value: str | None):
        try:
            gw_settings = await get_gateway_settings()
            max_age = gw_settings.get("session_lifetime_hours", 12) * 3600
            inactivity = gw_settings.get("session_timeout_minutes", 60) * 60
        except Exception:
            max_age = 12 * 3600
            inactivity = 60 * 60
        return await load_session(cookie_value, max_age_seconds=max_age, inactivity_seconds=inactivity)


    async def _handle_referer_fallback(self, request: Request, path: str, user) -> Response | None:
        referer = request.headers.get("referer", "")
        app_slug = None

        # 1. Try to extract app slug from referer
        if referer:
            match = re.search(r"/app/([a-zA-Z0-9_-]+)", referer)
            if match:
                app_slug = match.group(1)

        # 2. If referer failed (e.g. strict Referrer-Policy), try to get active app from cookie
        if not app_slug:
            app_slug = request.cookies.get("gateway_active_app")

        if not app_slug:
            return None

        app_registry = await get_app_registry()
        if app_slug not in app_registry:
            return None

        meta = app_registry[app_slug]
        if meta["group_id"] and user.in_group(meta["group_id"]):
            from .proxy import proxy_request
            log.info("Fallback proxying '%s' to app '%s' (via referer/cookie)", path, app_slug)
            return await proxy_request(request, app_slug, user)
        return None
