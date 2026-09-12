"""Auth routes — login, register, me."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.deps import CurrentUser, get_db, log_action
from app.core.security import create_access_token, hash_password, verify_password
from app.core.static_users import get_static_user
from app.db.models import User, UserRole
from app.schemas.schemas import LoginRequest, TokenResponse, UserCreate, UserOut

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = None

    # ── Try DB first ──────────────────────────────────────────────────────────
    try:
        user = db.query(User).filter(User.username == payload.username).first()
    except Exception:
        pass  # DB unavailable — fall through to static users

    if user is not None:
        # Found in DB — normal flow
        if not verify_password(payload.password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")
        try:
            user.last_login = datetime.now(timezone.utc)
            db.commit()
            log_action(db, user, "LOGIN", ip_address=request.client.host if request.client else None)
        except Exception:
            pass
    else:
        # ── Fall back to static demo users ────────────────────────────────────
        static = get_static_user(payload.username)
        if not static or not verify_password(payload.password, static.hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        user = static  # type: ignore[assignment]

    token = create_access_token(user.id, user.role.value)

    return TokenResponse(
        access_token=token,
        role=user.role.value,
        username=user.username,
        state=user.state,
        district=user.district,
    )


@router.post("/register", response_model=UserOut, status_code=201)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    try:
        role = UserRole(payload.role)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid role: {payload.role}")

    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role=role,
        state=payload.state,
        district=payload.district,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.get("/me", response_model=UserOut)
def me(current_user: CurrentUser):
    return current_user
