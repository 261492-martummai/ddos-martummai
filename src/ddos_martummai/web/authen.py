import hashlib
import hmac
import os
import time
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

USERNAME: str = os.getenv("NM_USERNAME", "")
PASSWORD_HASH: str = os.getenv("NM_PASSWORD_HASH", "")
SESSION_SECRET: bytes = os.getenv("NM_SESSION_SECRET", "dev").encode()
SESSION_TTL: int = int(os.getenv("NM_SESSION_TTL", "600"))

sessions: dict[str, float] = {}


def _hash_password(password: str) -> str:
    """SHA-256 hash a password string."""
    return hashlib.sha256(password.encode()).hexdigest()


def _generate_token() -> str:
    """Generate a cryptographically random session token."""
    return hmac.new(SESSION_SECRET, os.urandom(32), hashlib.sha256).hexdigest()


def _create_session() -> tuple[str, float]:
    """Create a new session and return (token, expires_at)."""
    token = _generate_token()
    expires_at = time.time() + SESSION_TTL
    sessions[token] = expires_at
    return token, expires_at


def _validate_session(token: Optional[str]) -> bool:
    """Return True if token exists and has not expired."""
    if not token:
        return False
    expires_at = sessions.get(token)
    if expires_at is None:
        return False
    if time.time() > expires_at:
        sessions.pop(token, None)  # clean up expired session
        return False
    return True


def _revoke_session(token: Optional[str]) -> None:
    """Remove a session token."""
    if token:
        sessions.pop(token, None)
