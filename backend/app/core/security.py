"""Security primitives: JWT, password hashing, RBAC, Fernet encryption."""
from __future__ import annotations

import base64
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import jwt
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, status
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.user import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

Role = Literal["viewer", "analyst", "engineer", "admin"]
ROLE_HIERARCHY: dict[str, int] = {"viewer": 1, "analyst": 2, "engineer": 3, "admin": 4}

ALGORITHM = "HS256"


# ── Password hashing ──────────────────────────────────────────
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ── JWT ───────────────────────────────────────────────────────
def _create_token(subject: str, expires_delta: timedelta, token_type: str, extra: dict | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": now + expires_delta,
        "type": token_type,
        "jti": secrets.token_urlsafe(16),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def create_access_token(user: User) -> str:
    return _create_token(
        str(user.id),
        timedelta(minutes=settings.access_token_expire_minutes),
        "access",
        {"role": user.role, "email": user.email},
    )


def create_refresh_token(user: User) -> str:
    return _create_token(
        str(user.id),
        timedelta(days=settings.refresh_token_expire_days),
        "refresh",
    )


def decode_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")


# ── RBAC ──────────────────────────────────────────────────────
def require_role(min_role: Role):
    """FastAPI dependency enforcing a minimum role."""
    from fastapi import Depends  # local import to avoid cycle

    from app.core.deps import get_current_user

    def _checker(user: User = Depends(get_current_user)) -> User:
        if ROLE_HIERARCHY.get(user.role, 0) < ROLE_HIERARCHY[min_role]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user

    return _checker


# ── Fernet encryption for stored secrets (auth profiles) ──────
def _fernet() -> Fernet | None:
    if not settings.encryption_key:
        return None
    return Fernet(settings.encryption_key.encode())


def encrypt_secret(plaintext: str) -> str:
    f = _fernet()
    if f is None:
        # Dev fallback: base64-obfuscate (NOT secure). Warn in logs.
        return "b64:" + base64.b64encode(plaintext.encode()).decode()
    return "f:" + f.encrypt(plaintext.encode()).decode()


def decrypt_secret(stored: str) -> str:
    if stored.startswith("b64:"):
        return base64.b64decode(stored[4:]).decode()
    if stored.startswith("f:"):
        f = _fernet()
        if f is None:
            raise RuntimeError("Encrypted value present but ENCRYPTION_KEY unset")
        try:
            return f.decrypt(stored[2:].encode()).decode()
        except InvalidToken as e:
            raise RuntimeError("Cannot decrypt secret") from e
    return stored


def authenticate_user(db: Session, email: str, password: str) -> User | None:
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user
