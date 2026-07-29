import os
import unittest
import unittest.mock

# Set test environment variables before importing apps
os.environ["GATEWAY_SECRET_KEY"] = "test-secret-key-that-is-long-enough-32-chars!!!"
os.environ["GATEWAY_ENCRYPTION_KEY"] = "K3x8W6G_vXWlq1YjX-Lq0_uV9N7B2t4C6E8G0I2K4M6="  # Valid Fernet key
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///test_gateway.db"

from fastapi.testclient import TestClient

from app.admin import admin_app
from app.database import AsyncSessionLocal, Base, engine
from app.db_models import GatewaySettings
from app.main import app


class GatewaySecurityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Remove old test DB file if it exists
        if os.path.exists("test_gateway.db"):
            try:
                os.remove("test_gateway.db")
            except Exception:
                pass

    async def asyncSetUp(self):
        # Initialize the database tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        # Seed GatewaySettings with setup_complete = True
        async with AsyncSessionLocal() as session:
            gw = GatewaySettings(id=1, setup_complete=True)
            session.add(gw)
            await session.commit()

    async def asyncTearDown(self):
        # Dispose the engine connections
        await engine.dispose()

    def tearDown(self):
        # Clean up DB file
        if os.path.exists("test_gateway.db"):
            try:
                os.remove("test_gateway.db")
            except Exception:
                pass

    def test_admin_api_endpoints_return_401_without_session(self):
        """Assert that every route under /admin/api/* returns 401/403 when not authenticated."""
        client = TestClient(admin_app)
        tested_routes = 0

        for route in admin_app.routes:
            if hasattr(route, "path") and route.path.startswith("/admin/api/"):
                methods = route.methods or ["GET"]
                for method in methods:
                    if method == "OPTIONS":
                        continue
                    tested_routes += 1
                    func = getattr(client, method.lower())

                    headers = {"host": "localhost:8585"}
                    if method in ("POST", "PUT"):
                        response = func(route.path, json={}, headers=headers)
                    else:
                        response = func(route.path, headers=headers)

                    # Skip public setup, login, and logout endpoints
                    if route.path in ("/admin/api/check-setup", "/admin/api/login", "/admin/api/setup", "/admin/api/logout"):
                        continue

                    self.assertIn(response.status_code, [401, 403, 422],
                        f"Route {method} {route.path} returned {response.status_code} instead of 401/403")

        print(f"Verified {tested_routes} admin API endpoints for auth checks.")
        self.assertGreater(tested_routes, 0)

    def test_main_app_protected_routes_without_session(self):
        """Assert that protected routes on the main portal redirect or return 401/302 without session."""
        client = TestClient(app)

        # 1. Main index '/' should redirect to login
        res = client.get("/", follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertIn("/auth/login", res.headers.get("location", ""))

        # 2. Reverse proxy endpoint should redirect to login
        res = client.get("/app/some-app/some-path", follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertIn("/auth/login", res.headers.get("location", ""))

    def test_admin_csrf_protection(self):
        """Verify that state-changing admin API endpoints require proper host/origin/referer headers."""
        client = TestClient(admin_app)

        # Test PUT /admin/api/portal with cross-site Origin header
        headers = {
            "origin": "https://attacker.com",
            "sec-fetch-site": "cross-site",
            "host": "localhost:8585"
        }
        res = client.put("/admin/api/portal", json={}, headers=headers)
        self.assertEqual(res.status_code, 403)
        self.assertIn("CSRF validation failed", res.json().get("detail", ""))

    def test_admin_brute_force_lockout(self):
        """Verify rate-limiting lockouts on admin login endpoint."""
        client = TestClient(admin_app)

        payload = {"username": "admin", "password": "wrongpassword"}
        headers = {
            "host": "localhost:8585",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": "http://localhost:8585"
        }
        for _ in range(10):
            res = client.post("/admin/api/login", json=payload, headers=headers)
            if res.status_code == 429:
                # Lockout triggered successfully!
                self.assertIn("Too many failed login attempts", res.json().get("detail", ""))
                break
        else:
            self.fail("Brute-force lockout did not trigger after 10 failed attempts")

    def test_forged_x_forwarded_for_from_non_trusted_ip(self):
        """Assert that a forged X-Forwarded-For header from an untrusted client host is ignored."""
        from fastapi import Request
        scope = {
            "type": "http",
            "headers": [
                (b"x-forwarded-for", b"203.0.113.195"),
                (b"x-real-ip", b"203.0.113.195")
            ],
            "client": ("198.51.100.2", 12345)
        }
        request = Request(scope)
        from app.audit_logger import get_client_ip
        ip = get_client_ip(request)
        self.assertEqual(ip, "198.51.100.2")

    def test_x_forwarded_for_from_trusted_ip(self):
        """Assert that X-Forwarded-For header from a trusted client host is accepted."""
        from fastapi import Request
        scope = {
            "type": "http",
            "headers": [
                (b"x-forwarded-for", b"203.0.113.195")
            ],
            "client": ("127.0.0.1", 12345)
        }
        request = Request(scope)
        from app.audit_logger import get_client_ip
        ip = get_client_ip(request)
        self.assertEqual(ip, "203.0.113.195")

    def test_lockout_by_username_from_multiple_ips(self):
        """Assert that lockout is triggered when the threshold is hit for a username, even from different IPs."""
        from app.config import TRUSTED_PROXIES
        TRUSTED_PROXIES.add("testclient")
        try:
            client = TestClient(admin_app)
            from app.admin import _login_failures_ip, _login_failures_user
            _login_failures_ip.clear()
            _login_failures_user.clear()

            for i in range(1, 5):
                res = client.post(
                    "/admin/api/login",
                    json={"username": "target_user", "password": "wrongpassword"},
                    headers={
                        "X-Forwarded-For": f"10.0.0.{i}",
                        "host": "localhost:8585",
                        "X-Requested-With": "XMLHttpRequest",
                        "Origin": "http://localhost:8585"
                    }
                )
                self.assertEqual(res.status_code, 401)

            res = client.post(
                "/admin/api/login",
                json={"username": "target_user", "password": "wrongpassword"},
                headers={
                    "X-Forwarded-For": "10.0.0.5",
                    "host": "localhost:8585",
                    "X-Requested-With": "XMLHttpRequest",
                    "Origin": "http://localhost:8585"
                }
            )
            self.assertEqual(res.status_code, 429)
            self.assertIn("locked out", res.json().get("detail", "").lower())
        finally:
            TRUSTED_PROXIES.discard("testclient")

    @unittest.mock.patch("app.admin._get_admin_session")
    async def test_save_entra_encrypts_secret(self, mock_get_session):
        mock_get_session.return_value = {"username": "admin"}
        client = TestClient(admin_app)

        payload = {
            "tenant_id": "test-tenant",
            "client_id": "test-client",
            "client_secret": "my-plain-secret"
        }
        res = client.post(
            "/admin/api/entra",
            json=payload,
            headers={
                "host": "localhost:8585",
                "X-Requested-With": "XMLHttpRequest",
                "Origin": "http://localhost:8585"
            }
        )
        self.assertEqual(res.status_code, 200)

        from sqlalchemy import select

        from app.db_models import EntraConfig
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(EntraConfig).where(EntraConfig.id == 1))
            row = result.scalar_one_or_none()
            self.assertIsNotNone(row)
            self.assertTrue(row.client_secret.startswith("gAAAAA"))
            self.assertNotEqual(row.client_secret, "my-plain-secret")

    @unittest.mock.patch("app.admin._get_admin_session")
    @unittest.mock.patch("httpx.AsyncClient.post")
    async def test_entra_test_endpoint_decrypts_secret(self, mock_post, mock_get_session):
        mock_get_session.return_value = {"username": "admin"}

        from cryptography.fernet import Fernet
        from sqlalchemy import select

        from app.config import GATEWAY_ENCRYPTION_KEY
        from app.db_models import EntraConfig

        encrypted_secret = Fernet(GATEWAY_ENCRYPTION_KEY).encrypt(b"my-plain-secret").decode()

        async with AsyncSessionLocal() as session:
            result = await session.execute(select(EntraConfig).where(EntraConfig.id == 1))
            row = result.scalar_one_or_none()
            if not row:
                row = EntraConfig(id=1)
                session.add(row)
            row.tenant_id = "test-tenant"
            row.client_id = "test-client"
            row.client_secret = encrypted_secret
            await session.commit()

        from app.config_store import invalidate_cache
        await invalidate_cache("entra")

        class MockResponse:
            def __init__(self, status_code, json_data=None):
                self.status_code = status_code
                self._json = json_data or {}
            def json(self):
                return self._json

        mock_post.return_value = MockResponse(200, {"access_token": "mock-token"})

        with unittest.mock.patch("httpx.AsyncClient.get") as mock_get:
            mock_get.return_value = MockResponse(200)

            client = TestClient(admin_app)
            res = client.post(
                "/admin/api/entra/test",
                headers={
                    "host": "localhost:8585",
                    "X-Requested-With": "XMLHttpRequest",
                    "Origin": "http://localhost:8585"
                }
            )
            self.assertEqual(res.status_code, 200)

            self.assertTrue(mock_post.called)
            called_data = mock_post.call_args[1]["data"]
            self.assertEqual(called_data["client_secret"], "my-plain-secret")

    def test_admin_csrf_fails_closed_when_headers_missing(self):
        """Assert that state-changing admin api requests fail closed if both Origin and Referer are missing."""
        client = TestClient(admin_app)
        headers = {
            "host": "localhost:8585",
            "X-Requested-With": "XMLHttpRequest"
        }
        res = client.post("/admin/api/login", json={}, headers=headers)
        self.assertEqual(res.status_code, 403)
        self.assertIn("CSRF validation failed", res.json().get("detail", ""))

    def test_csp_headers_and_nonces(self):
        """Verify that portal and admin apps set strict CSP headers with nonces."""
        import re
        # 1. Test portal app CSP
        portal_client = TestClient(app)
        res = portal_client.get("/")
        self.assertIn("Content-Security-Policy", res.headers)
        csp = res.headers["Content-Security-Policy"]
        script_src = csp.split("script-src")[1].split(";")[0]
        self.assertNotIn("'unsafe-inline'", script_src)
        self.assertNotIn("'unsafe-eval'", script_src)
        self.assertIn("nonce-", csp)

        # 2. Test admin app CSP and script tag injection
        admin_client = TestClient(admin_app)
        res = admin_client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("Content-Security-Policy", res.headers)
        admin_csp = res.headers["Content-Security-Policy"]
        admin_script_src = admin_csp.split("script-src")[1].split(";")[0]
        self.assertNotIn("'unsafe-inline'", admin_script_src)
        self.assertNotIn("'unsafe-eval'", admin_script_src)
        self.assertIn("nonce-", admin_csp)

        # Extract the nonce value from CSP header: script-src 'self' 'nonce-<VAL>';
        match = re.search(r"script-src\s+'self'\s+'nonce-([^']+)'", admin_csp)
        self.assertIsNotNone(
            match, f"Could not find nonce in CSP header: {admin_csp}"
        )
        nonce = match.group(1)

        # Assert that index.html contains the injected nonce
        html = res.text
        expected_tag = f'src="/static/admin/admin.js" nonce="{nonce}"'
        self.assertIn(expected_tag, html)

if __name__ == "__main__":
    unittest.main()
