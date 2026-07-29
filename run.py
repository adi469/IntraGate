"""IntraGate — Dual-Port Launcher

Starts both the user-facing gateway (port 9000) and the admin panel (port 8585)
in separate threads using uvicorn.
"""
import os
import sys
import threading
import logging

import uvicorn
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(__file__).resolve().parent / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
log = logging.getLogger("gateway.launcher")

GATEWAY_HOST = os.environ.get("GATEWAY_HOST", "0.0.0.0")
GATEWAY_PORT = int(os.environ.get("GATEWAY_PORT", "9000"))
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "8585"))


def run_gateway():
    """Run the main gateway on the configured port."""
    log.info("Starting Gateway on %s:%d", GATEWAY_HOST, GATEWAY_PORT)
    uvicorn.run(
        "app.main:app",
        host=GATEWAY_HOST,
        port=GATEWAY_PORT,
        log_level="info",
        access_log=True,
        loop="asyncio",
    )


def run_admin():
    """Run the admin panel on port 8585."""
    log.info("Starting Admin Panel on %s:%d", GATEWAY_HOST, ADMIN_PORT)
    uvicorn.run(
        "app.admin:admin_app",
        host=GATEWAY_HOST,
        port=ADMIN_PORT,
        log_level="info",
        access_log=True,
        loop="asyncio",
    )


if __name__ == "__main__":
    log.info("=" * 56)
    log.info("  INTRAGATE SECURE GATEWAY — Starting Services")
    log.info("=" * 56)
    log.info("  Gateway (user portal):  http://%s:%d", GATEWAY_HOST, GATEWAY_PORT)
    log.info("  Admin Panel:            http://%s:%d", GATEWAY_HOST, ADMIN_PORT)
    log.info("=" * 56)

    # Start admin panel in a background thread
    admin_thread = threading.Thread(target=run_admin, daemon=True)
    admin_thread.start()

    # Run gateway in the main thread (blocks)
    try:
        run_gateway()
    except KeyboardInterrupt:
        log.info("Shutting down...")
        sys.exit(0)
