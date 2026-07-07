"""Data models for the gateway."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class GatewayUser:
    """Represents an authenticated user (built from Entra ID token claims)."""

    oid: str  # Entra Object ID (unique user identifier)
    name: str  # Display name
    email: str  # UPN / email
    groups: list[str] = field(default_factory=list)  # Entra group Object IDs
    login_at: datetime = field(default_factory=datetime.utcnow)

    # Token data (kept for potential Graph API calls)
    access_token: str | None = None
    id_token: str | None = None

    def in_group(self, group_id: str) -> bool:
        """Check if the user is a member of a specific Entra group."""
        return group_id in self.groups

    def to_dict(self) -> dict:
        """Serialize for session storage."""
        return {
            "oid": self.oid,
            "name": self.name,
            "email": self.email,
            "groups": self.groups,
            "login_at": self.login_at.isoformat(),
            "access_token": self.access_token,
            "id_token": self.id_token,
        }

    @classmethod
    def from_dict(cls, d: dict) -> GatewayUser:
        """Deserialize from session storage."""
        return cls(
            oid=d["oid"],
            name=d["name"],
            email=d["email"],
            groups=d.get("groups", []),
            login_at=datetime.fromisoformat(d["login_at"]),
            access_token=d.get("access_token"),
            id_token=d.get("id_token"),
        )
