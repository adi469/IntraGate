"""Microsoft Entra ID OIDC authentication — login, callback, logout.

Uses authlib for the Authorization Code flow with PKCE.
Group memberships are extracted from the ID token's 'groups' claim.
If the groups claim is missing (overage), we fall back to Microsoft
Graph API to fetch group memberships.

Now uses dynamic Entra ID credentials from the admin-managed config store.
"""
from __future__ import annotations

import logging
import secrets
from urllib.parse import urlencode

import httpx
from authlib.integrations.starlette_client import OAuth
from starlette.requests import Request
from starlette.responses import RedirectResponse

from .audit_logger import get_client_ip, log_security_event
from .config import DEV_MODE, SECURE_COOKIE
from .config_store import (
    get_entra_config,
    get_entra_urls,
    get_gateway_settings,
    is_setup_complete,
)
from .models import GatewayUser
from .session import COOKIE_NAME, create_session, destroy_session, load_session

log = logging.getLogger("gateway.auth")

# ── Dynamic OAuth client ─────────────────────────────────────
# Re-created when Entra credentials change

_oauth: OAuth | None = None
_registered_tenant: str = ""


async def _get_oauth() -> OAuth:
    """Get or re-create the OAuth client with current Entra credentials."""
    global _oauth, _registered_tenant

    entra = await get_entra_config()
    current_tenant = entra.get("tenant_id", "")
    current_client = entra.get("client_id", "")
    current_secret = entra.get("client_secret", "")

    if not current_tenant or not current_client:
        raise ValueError("Entra ID not configured — complete setup in admin panel")

    # Re-register if credentials changed
    if _oauth is None or _registered_tenant != current_tenant:
        urls = await get_entra_urls()
        _oauth = OAuth()
        _oauth.register(
            name="entra",
            client_id=current_client,
            client_secret=current_secret,
            server_metadata_url=urls["oidc_discovery_url"],
            client_kwargs={
                "scope": "openid profile email",
                "token_endpoint_auth_method": "client_secret_post",
            },
        )
        _registered_tenant = current_tenant
        log.info("OAuth client registered for tenant: %s", current_tenant)

    return _oauth


async def login(request: Request) -> RedirectResponse:
    """Redirect the user to Microsoft Entra ID for login."""
    setup_done = await is_setup_complete()
    if DEV_MODE and not setup_done and request.query_params.get("mock") == "true":
        log.info("Developer Mock Login triggered - creating local session bypass")
        from .config_store import get_app_registry
        app_registry = await get_app_registry()
        mock_groups = [meta["group_id"] for meta in app_registry.values() if meta["group_id"]]

        user = GatewayUser(
            oid="mock-dev-user-id",
            name="Aditya (Developer)",
            email="developer@intragate.local",
            groups=mock_groups,
            access_token="mock-access-token",
            id_token=None,
        )

        gw = await get_gateway_settings()
        cookie_value = await create_session(user)
        await log_security_event(
            event_type="login",
            user_email=user.email,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            details="Developer Mock Bypass Login Successful"
        )
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie(
            COOKIE_NAME,
            cookie_value,
            max_age=gw.get("session_lifetime_hours", 12) * 3600,
            httponly=True,
            secure=SECURE_COOKIE,
            samesite="lax",
            path="/",
        )
        return response

    try:
        oauth = await _get_oauth()
    except ValueError:
        return RedirectResponse(url="/error?msg=setup_required", status_code=302)

    gw = await get_gateway_settings()
    redirect_uri = f"{gw['gateway_base_url']}/auth/callback"
    nonce = secrets.token_urlsafe(16)
    request.session["oauth_nonce"] = nonce
    return await oauth.entra.authorize_redirect(
        request,
        redirect_uri,
        nonce=nonce,
    )


async def callback(request: Request) -> RedirectResponse:
    """Handle the OIDC callback from Entra ID."""
    try:
        oauth = await _get_oauth()
    except ValueError:
        return RedirectResponse(url="/error?msg=setup_required", status_code=302)

    try:
        nonce = request.session.pop("oauth_nonce", None)
        token = await oauth.entra.authorize_access_token(request, nonce=nonce)
    except Exception as exc:
        log.error("OIDC token exchange failed: %s", exc)
        return RedirectResponse(url="/error?msg=auth_failed", status_code=302)

    # Extract user info from the ID token
    userinfo = token.get("userinfo") or {}
    id_token_claims = {}
    if "id_token" in token:
        try:
            id_token_claims = token.get("id_token", {})
            if not hasattr(id_token_claims, "get"):
                id_token_claims = {}
        except Exception:
            id_token_claims = {}

    # Merge claims: userinfo + id_token
    claims = {**userinfo, **id_token_claims} if isinstance(id_token_claims, dict) else userinfo

    # Extract group memberships
    groups = claims.get("groups", [])

    # Handle group overage (too many groups for the token)
    if not groups and "_claim_names" in claims:
        log.info("Group overage detected — fetching groups from Graph API")
        groups = await _fetch_groups_from_graph(token.get("access_token", ""))

    # Build our user object
    user = GatewayUser(
        oid=claims.get("oid", claims.get("sub", "")),
        name=claims.get("name", "Unknown User"),
        email=claims.get("preferred_username", claims.get("email", "")),
        groups=groups,
        access_token=token.get("access_token"),
        id_token=token.get("id_token") if isinstance(token.get("id_token"), str) else None,
    )

    log.info("User logged in: %s (%s) — %d groups", user.name, user.email, len(user.groups))
    await log_security_event(
        event_type="login",
        user_email=user.email,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details=f"Microsoft Entra ID login successful. User: {user.name}"
    )

    # Create a server-side session
    gw = await get_gateway_settings()
    cookie_value = await create_session(user)
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        COOKIE_NAME,
        cookie_value,
        max_age=gw["session_lifetime_hours"] * 3600,
        httponly=True,
        secure=SECURE_COOKIE,
        samesite="lax",
        path="/",
    )
    return response


async def logout(request: Request) -> RedirectResponse:
    """Clear the local session and redirect to Entra ID logout."""
    cookie_value = request.cookies.get(COOKIE_NAME)
    user = await load_session(cookie_value)
    user_email = user.email if user else "unknown"
    await destroy_session(cookie_value)

    await log_security_event(
        event_type="logout",
        user_email=user_email,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details="User logged out"
    )

    gw = await get_gateway_settings()
    urls = await get_entra_urls()

    post_logout_uri = gw["gateway_base_url"]
    logout_url = urls.get("logout_url", "")
    if logout_url:
        entra_logout = f"{logout_url}?{urlencode({'post_logout_redirect_uri': post_logout_uri})}"
    else:
        entra_logout = "/"

    response = RedirectResponse(url=entra_logout, status_code=302)
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


async def _fetch_groups_from_graph(access_token: str) -> list[str]:
    """Fallback: fetch user's group memberships from Microsoft Graph API."""
    if not access_token:
        return []
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://graph.microsoft.com/v1.0/me/memberOf",
                headers={"Authorization": f"Bearer {access_token}"},
                params={"$select": "id", "$top": "999"},
                timeout=10,
            )
            if resp.status_code != 200:
                log.warning("Graph API returned %d: %s", resp.status_code, resp.text[:200])
                return []
            data = resp.json()
            return [
                entry["id"]
                for entry in data.get("value", [])
                if entry.get("@odata.type") == "#microsoft.graph.group"
            ]
    except Exception as exc:
        log.error("Graph API group fetch failed: %s", exc)
        return []
