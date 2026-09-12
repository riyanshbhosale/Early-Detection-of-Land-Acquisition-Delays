"""
Static demo users — used as a fallback when the database is unavailable
or a user is not found in the DB.

These map directly to the demo credentials shown on the login page.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from app.db.models import UserRole

# Fixed timestamp for all static users (epoch = "always existed")
_EPOCH = datetime(2024, 1, 1, tzinfo=timezone.utc)


@dataclass
class StaticUser:
    id: int
    username: str
    email: str
    hashed_password: str
    full_name: str
    role: UserRole
    state: str | None
    district: str | None
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: _EPOCH)

    # Stubs so code that touches ORM relationships doesn't crash
    audit_logs: list = field(default_factory=list)
    alerts: list = field(default_factory=list)
    actions_assigned: list = field(default_factory=list)
    actions_created: list = field(default_factory=list)
    last_login: object = None


# IDs are large negatives so they never collide with real DB rows
STATIC_USERS: dict[str, StaticUser] = {
    "admin": StaticUser(
        id=-1,
        username="admin",
        email="admin@dolr.gov.in",
        hashed_password="$2b$12$BOvNug6c6TR1vBMi0u/9F.DZpQq0ubHXiKCe5vDByM/ikEsqcfrUq",
        full_name="Central Admin",
        role=UserRole.CENTRAL,
        state=None,
        district=None,
    ),
    "up_officer": StaticUser(
        id=-2,
        username="up_officer",
        email="up_officer@dolr.gov.in",
        hashed_password="$2b$12$4pwD4/1Aosd6g1pfZBqai.kNfJOovaQIsrx/2P/06L1oSL7mRSuHq",
        full_name="UP State Officer",
        role=UserRole.STATE,
        state="Uttar Pradesh",
        district=None,
    ),
    "lucknow_officer": StaticUser(
        id=-3,
        username="lucknow_officer",
        email="lucknow_officer@dolr.gov.in",
        hashed_password="$2b$12$GQwyOmQUOwJmBPss9KftX.O2Er2Bl4dCmNNVnp.TnyfWk0OT695zO",
        full_name="Lucknow District Officer",
        role=UserRole.DISTRICT,
        state="Uttar Pradesh",
        district="Lucknow",
    ),
}


def get_static_user(username: str) -> StaticUser | None:
    return STATIC_USERS.get(username)
