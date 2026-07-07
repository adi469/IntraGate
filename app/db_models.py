"""SQLAlchemy ORM models for the IntraGate Gateway admin configuration."""
from __future__ import annotations

import os
import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

DATABASE_URL = os.environ.get("DATABASE_URL", "")
if DATABASE_URL and DATABASE_URL.startswith("postgresql"):
    from sqlalchemy.dialects.postgresql import JSONB as JSON_TYPE
else:
    JSON_TYPE = JSON


from .database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class AdminUser(Base):
    """Local admin user — NOT tied to Entra ID."""
    __tablename__ = "admin_users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class EntraConfig(Base):
    """Microsoft Entra ID configuration — single-row table."""
    __tablename__ = "entra_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False, default="")
    client_id: Mapped[str] = mapped_column(String(100), nullable=False, default="")
    client_secret: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    connection_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Application(Base):
    """An application that can be accessed through the gateway."""
    __tablename__ = "applications"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    icon: Mapped[str] = mapped_column(String(10), default="🔧")
    group_id: Mapped[str] = mapped_column(
        String(100), nullable=False, comment="Entra security group Object ID"
    )
    upstream_scheme: Mapped[str] = mapped_column(String(10), default="http", nullable=False)
    upstream_ip: Mapped[str] = mapped_column(String(255), nullable=False)
    upstream_port: Mapped[int] = mapped_column(Integer, nullable=False)
    color: Mapped[str] = mapped_column(String(20), default="#1F4E79")
    gradient: Mapped[str] = mapped_column(
        String(200), default="linear-gradient(135deg, #1F4E79 0%, #2980B9 100%)"
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    tls_verify: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    @property
    def upstream(self) -> str:
        return f"{self.upstream_scheme}://{self.upstream_ip}:{self.upstream_port}"


class PortalSettings(Base):
    """User portal customization — single-row table."""
    __tablename__ = "portal_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    org_name: Mapped[str] = mapped_column(String(200), default="My Organization")
    org_subtext: Mapped[str] = mapped_column(String(200), default="")
    logo_mode: Mapped[str] = mapped_column(
        String(10), default="none", comment="none | file | url"
    )
    logo_file_path: Mapped[str] = mapped_column(String(500), default="")
    logo_url: Mapped[str] = mapped_column(String(1000), default="")
    primary_color: Mapped[str] = mapped_column(String(20), default="#1f6b9a")
    accent_color: Mapped[str] = mapped_column(String(20), default="#9b59b6")
    footer_text: Mapped[str] = mapped_column(
        Text, default="© 2026 All rights reserved. | Active Directory SSO Secured"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class GatewaySettings(Base):
    """Global gateway settings — single-row table."""
    __tablename__ = "gateway_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    gateway_base_url: Mapped[str] = mapped_column(
        String(500), default="https://gateway.example.com"
    )
    session_lifetime_hours: Mapped[int] = mapped_column(Integer, default=12)
    session_timeout_minutes: Mapped[int] = mapped_column(
        Integer, default=60, comment="Inactivity timeout in minutes"
    )
    setup_complete: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class SecurityLog(Base):
    """Audit log entry for security and access tracking."""
    __tablename__ = "security_logs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_uuid
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    user_email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)
    app_slug: Mapped[str | None] = mapped_column(String(100), nullable=True)
    app_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)


class UserSession(Base):
    """User sessions stored in database for async, distributed access."""
    __tablename__ = "user_sessions"

    session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_data: Mapped[dict] = mapped_column(JSON_TYPE, nullable=False)
    created_at: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    last_active: Mapped[float] = mapped_column(Float, nullable=False, index=True)


class AdminSession(Base):
    """Admin sessions stored in database for async, distributed access."""
    __tablename__ = "admin_sessions"

    session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    admin_id: Mapped[str] = mapped_column(String(36), nullable=False)
    username: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    last_active: Mapped[float] = mapped_column(Float, nullable=False, index=True)

