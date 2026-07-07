"""Reverse proxy — forwards authenticated requests to internal apps.

Uses httpx to stream requests/responses, supporting:
  - Regular GET/POST requests
  - Server-Sent Events (SSE) for VMC live logs
  - Large file downloads (Excel/PDF)
  - Multi-part file uploads
"""
from __future__ import annotations

import logging

import httpx
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse

from .config_store import get_app_registry
from .models import GatewayUser

log = logging.getLogger("gateway.proxy")

# Shared async clients — reused across requests for connection pooling
_client_verify: httpx.AsyncClient | None = None
_client_no_verify: httpx.AsyncClient | None = None


async def get_client(verify: bool = True) -> httpx.AsyncClient:
    """Get or create the shared httpx client depending on verify flag."""
    global _client_verify, _client_no_verify
    if verify:
        if _client_verify is None or _client_verify.is_closed:
            _client_verify = httpx.AsyncClient(
                timeout=httpx.Timeout(connect=10, read=300, write=60, pool=10),
                follow_redirects=False,
                verify=True,
                limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
            )
        return _client_verify
    else:
        if _client_no_verify is None or _client_no_verify.is_closed:
            _client_no_verify = httpx.AsyncClient(
                timeout=httpx.Timeout(connect=10, read=300, write=60, pool=10),
                follow_redirects=False,
                verify=False,  # Allow self-signed certificates on the internal network
                limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
            )
        return _client_no_verify


async def close_client() -> None:
    """Shutdown the httpx clients (called on app shutdown)."""
    global _client_verify, _client_no_verify
    if _client_verify and not _client_verify.is_closed:
        await _client_verify.aclose()
        _client_verify = None
    if _client_no_verify and not _client_no_verify.is_closed:
        await _client_no_verify.aclose()
        _client_no_verify = None


# Headers to NOT forward in either direction (standard hop-by-hop headers).
# Referrer-Policy is NOT hop-by-hop and should not be stripped.
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
})


async def proxy_request(
    request: Request,
    app_slug: str,
    user: GatewayUser,
) -> Response:
    """Forward a request to the internal app and stream back the response.

    The URL path /app/{slug}/... is stripped to /... before forwarding.
    Authorization is already verified before this function is called.
    """
    app_registry = await get_app_registry()
    app_info = app_registry.get(app_slug)
    if not app_info:
        return Response("App not found", status_code=404)

    upstream = app_info["upstream"]

    # Strip the /app/{slug} prefix from the path
    prefix = f"/app/{app_slug}"
    path = request.url.path
    if path.startswith(prefix):
        path = path[len(prefix):] or "/"
    # Preserve query string
    if request.url.query:
        target_url = f"{upstream}{path}?{request.url.query}"
    else:
        target_url = f"{upstream}{path}"

    # Build upstream headers (filter hop-by-hop and strip client-supplied identity headers)
    headers = {}
    for key, value in request.headers.items():
        kl = key.lower()
        if kl in _HOP_BY_HOP:
            continue
        # Strip client-supplied identity headers (X-Gateway-* / SEC-*) to prevent spoofing
        if kl.startswith("x-gateway-") or kl.startswith("sec-"):
            continue
        headers[key] = value

    # Filter out gateway session cookies from the Cookie header
    cookie_str = headers.get("cookie", "")
    if cookie_str:
        cookies = [c.strip() for c in cookie_str.split(";")]
        filtered_cookies = [
            c for c in cookies
            if not c.startswith("intragate_sid=") and not c.startswith("intragate_admin_sid=")
        ]
        if filtered_cookies:
            headers["cookie"] = "; ".join(filtered_cookies)
        else:
            headers.pop("cookie", None)

    # Override Host to match upstream
    headers["host"] = upstream.split("//", 1)[-1]
    # Inject user identity headers (so internal apps can optionally use them)
    headers["x-gateway-user"] = user.email
    headers["x-gateway-user-name"] = user.name
    headers["x-gateway-user-oid"] = user.oid

    tls_verify = app_info.get("tls_verify", True)
    client = await get_client(verify=tls_verify)

    try:
        # Read the request body (needed for POST/PUT/PATCH)
        body = await request.body()

        # Build the upstream request
        upstream_req = client.build_request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body if body else None,
        )

        # Stream the response back
        upstream_resp = await client.send(upstream_req, stream=True)

        # Filter response headers
        resp_headers = {}
        for key, value in upstream_resp.headers.items():
            if key.lower() not in _HOP_BY_HOP and not key.startswith(":"):
                resp_headers[key] = value

        # Handle redirects from internal apps: rewrite Location header
        if "location" in resp_headers:
            loc = resp_headers["location"]
            from urllib.parse import urlparse, urlunparse
            try:
                parsed_loc = urlparse(loc)
                parsed_up = urlparse(upstream)
                # If it's relative or matches the upstream host/port
                if not parsed_loc.netloc or parsed_loc.netloc.lower() == parsed_up.netloc.lower():
                    path = parsed_loc.path
                    if not path.startswith("/"):
                        path = f"/{path}"

                    # Prevent duplicating the app slug prefix if already present
                    prefix = f"/app/{app_slug}"
                    if not path.startswith(prefix):
                        new_path = f"{prefix}{path}"
                    else:
                        new_path = path

                    resp_headers["location"] = urlunparse((
                        "", "", new_path,
                        parsed_loc.params, parsed_loc.query, parsed_loc.fragment
                    ))
            except Exception as e:
                log.warning("Failed to rewrite Location header '%s': %s", loc, e)

        async def stream_body():
            try:
                async for chunk in upstream_resp.aiter_raw(chunk_size=8192):
                    yield chunk
            finally:
                await upstream_resp.aclose()

        return StreamingResponse(
            content=stream_body(),
            status_code=upstream_resp.status_code,
            headers=resp_headers,
            media_type=upstream_resp.headers.get("content-type"),
        )

    except httpx.ConnectError:
        log.error("Cannot connect to upstream %s for app '%s'", upstream, app_slug)
        return Response(
            content=f"Service '{app_info['name']}' is not running. Please contact the administrator.",
            status_code=502,
            media_type="text/plain",
        )
    except httpx.TimeoutException:
        log.error("Upstream timeout for app '%s' at %s", app_slug, target_url)
        return Response(
            content=f"Service '{app_info['name']}' timed out. The request may be too large or the server is overloaded.",
            status_code=504,
            media_type="text/plain",
        )
    except Exception as exc:
        log.error("Proxy error for app '%s': %s", app_slug, exc, exc_info=True)
        return Response(
            content="An unexpected error occurred while connecting to the internal service.",
            status_code=500,
            media_type="text/plain",
        )
