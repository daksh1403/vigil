"""Tests for security primitives."""
from __future__ import annotations

from app.core.security import decrypt_secret, encrypt_secret, hash_password, verify_password


def test_password_hashing():
    h = hash_password("s3cret-pass")
    assert h != "s3cret-pass"
    assert verify_password("s3cret-pass", h)
    assert not verify_password("wrong", h)


def test_secret_encryption_b64_fallback():
    # Without ENCRYPTION_KEY set, falls back to base64 (dev only)
    stored = encrypt_secret("AKIAIOSFODNN7EXAMPLE")
    assert stored.startswith("b64:")
    assert decrypt_secret(stored) == "AKIAIOSFODNN7EXAMPLE"


def test_jwt_roundtrip():
    from app.core.security import create_access_token, decode_token
    from app.models.user import User

    class _U:
        id = "user-123"
        email = "a@b.com"
        role = "admin"

    token = create_access_token(_U())  # type: ignore[arg-type]
    payload = decode_token(token)
    assert payload["sub"] == "user-123"
    assert payload["type"] == "access"
    assert payload["role"] == "admin"
