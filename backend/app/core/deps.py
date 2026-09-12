"""FastAPI dependencies — current user extraction, RBAC guards, audit logging."""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.security import decode_token
from app.core.static_users import get_static_user, STATIC_USERS
from app.db.database import get_db
from app.db.models import User, UserRole, AuditLog

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# Reverse map: negative id → StaticUser (built once at import time)
_STATIC_BY_ID = {u.id: u for u in STATIC_USERS.values()}


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Session = Depends(get_db),
) -> User:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exc
    except JWTError:
        raise credentials_exc

    uid = int(user_id)

    # ── Static demo user (negative ID) — no DB needed ─────────────────────────
    if uid < 0:
        static = _STATIC_BY_ID.get(uid)
        if not static or not static.is_active:
            raise credentials_exc
        return static  # type: ignore[return-value]

    # ── Normal DB user ─────────────────────────────────────────────────────────
    try:
        user = db.query(User).filter(User.id == uid).first()
    except Exception:
        raise credentials_exc
    if not user or not user.is_active:
        raise credentials_exc
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*roles: UserRole):
    """Returns a FastAPI dependency that enforces role membership."""
    def _check(current_user: CurrentUser):
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {[r.value for r in roles]}",
            )
        return current_user
    return _check


def log_action(
    db: Session,
    user,
    action: str,
    resource: str | None = None,
    resource_id: str | None = None,
    detail: str | None = None,
    ip_address: str | None = None,
):
    """Write one row to audit_logs. Silently skips for static/demo users or if DB is down."""
    # Static users have negative IDs — don't try to write to DB
    if user is not None and getattr(user, "id", 0) < 0:
        return
    try:
        entry = AuditLog(
            user_id=user.id if user else None,
            action=action,
            resource=resource,
            resource_id=str(resource_id) if resource_id else None,
            detail=detail,
            ip_address=ip_address,
            created_at=datetime.now(timezone.utc),
        )
        db.add(entry)
        db.commit()
    except Exception:
        pass
