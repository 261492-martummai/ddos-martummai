import hmac
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Cookie, HTTPException, Response, status
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse

from ddos_martummai.init_models import LoginRequest
from ddos_martummai.web.authen import (
    PASSWORD_HASH,
    SESSION_TTL,
    USERNAME,
    _create_session,
    _hash_password,
    _revoke_session,
    _validate_session,
)
from ddos_martummai.web.drift_monitor import save_baseline

# ===================== ROUTER SETUP =====================
router = APIRouter()
current_dir = Path(__file__).parent.resolve()
NM_HOST: str = os.getenv("NM_HOST", "localhost")
NM_PORT: int = int(os.getenv("NM_PORT", "8000"))


# ===================== PAGE ROUTES =====================
@router.get("/")
def root():
    """Redirect root to login page."""
    return RedirectResponse(url="/login")


@router.get("/login")
def login_page():
    """Serve login.html with cache-busting headers."""
    return FileResponse(
        current_dir / "static" / "login.html",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@router.get("/monitor")
def monitor_page():
    """Serve index.html with injected WS_HOST configuration."""
    html_path = current_dir / "static" / "index.html"

    # Read HTML template
    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    config_script = f"""
            <script>
                window.NM_HOST = "{NM_HOST}";
                window.NM_PORT = "{NM_PORT}";
            </script>
        </head>"""
    html_content = html_content.replace("</head>", config_script)

    return HTMLResponse(
        content=html_content,
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


# ===================== AUTH ROUTES =====================
@router.post("/auth/login")
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
        secure=False,  # set True in production (HTTPS)
        max_age=SESSION_TTL,
        expires=int(expires_at),
    )

    return {"status": "ok"}


@router.post("/auth/logout")
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


@router.get("/auth/me")
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


@router.post("/ml/baseline")
def api_save_baseline(nm_session: Optional[str] = Cookie(default=None)):
    if not _validate_session(nm_session):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="NOT AUTHENTICATED",
        )

    save_baseline()
    return {"status": "ok", "message": "Baseline updated"}
