import hashlib
import hmac
import os
import time
from typing import Optional

from dotenv import load_dotenv
from fastapi import APIRouter, Cookie, HTTPException, Response, status
from pydantic import BaseModel

load_dotenv()


router = APIRouter(prefix="/auth", tags=["auth"])

USERNAME:       str = os.getenv("NM_USERNAME")
PASSWORD_HASH:  str = os.getenv("NM_PASSWORD_HASH")
SESSION_SECRET: bytes = os.getenv("NM_SESSION_SECRET").encode()
SESSION_TTL:    int   = int(os.getenv("NM_SESSION_TTL"))

# In-memory session store: { token: expires_at }
_sessions: dict[str, float] = {}


# ===================== MODELS =====================
class LoginRequest(BaseModel):
    username: str
    password: str


# ===================== HELPERS =====================
def _hash_password(password: str) -> str:
    """SHA-256 hash a password string."""
    return hashlib.sha256(password.encode()).hexdigest()


def _generate_token() -> str:
    """Generate a cryptographically random session token."""
    return hmac.new(SESSION_SECRET, os.urandom(32), hashlib.sha256).hexdigest()


def _create_session() -> tuple[str, float]:
    """Create a new session and return (token, expires_at)."""
    token      = _generate_token()
    expires_at = time.time() + SESSION_TTL
    _sessions[token] = expires_at
    return token, expires_at


def _validate_session(token: Optional[str]) -> bool:
    """Return True if token exists and has not expired."""
    if not token:
        return False
    expires_at = _sessions.get(token)
    if expires_at is None:
        return False
    if time.time() > expires_at:
        _sessions.pop(token, None)   # clean up expired session
        return False
    return True


def _revoke_session(token: Optional[str]) -> None:
    """Remove a session token."""
    if token:
        _sessions.pop(token, None)


# ===================== ROUTES =====================
@router.post("/login")
def login(body: LoginRequest, response: Response) -> dict:
    """
    Validate credentials and set a session cookie.

    The cookie is:
    - HttpOnly  — not readable by JavaScript (XSS protection)
    - SameSite=Strict — not sent on cross-site requests (CSRF protection)
    - Secure    — only sent over HTTPS (set to False in local dev)
    """
    # Constant-time comparison prevents timing attacks
    username_ok = hmac.compare_digest(body.username, USERNAME)
    password_ok = hmac.compare_digest(_hash_password(body.password), PASSWORD_HASH)

    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="INVALID CREDENTIALS",
        )

    token, expires_at = _create_session()

    response.set_cookie(
        key="nm_session",
        value=token,
        httponly=True,
        samesite="strict",
        secure=False,                          # set True in production (HTTPS)
        max_age=SESSION_TTL,
        expires=int(expires_at),
    )

    return {"status": "ok"}


@router.post("/logout")
def logout(
    response: Response,
    nm_session: Optional[str] = Cookie(default=None),
) -> dict:
    """Revoke the session and clear the cookie."""
    _revoke_session(nm_session)

    response.delete_cookie(
        key="nm_session",
        httponly=True,
        samesite="strict",
    )

    return {"status": "ok"}


@router.get("/me")
def me(nm_session: Optional[str] = Cookie(default=None)) -> dict:
    """
    Session check endpoint — called by index.html on every load.
    Returns 200 if authenticated, 401 otherwise.
    """
    if not _validate_session(nm_session):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="NOT AUTHENTICATED",
        )

    return {"status": "ok", "username": USERNAME}