from fastapi import APIRouter, HTTPException, Header, status
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime, timezone
import os
import hashlib
import hmac
import json
import base64
import time
import secrets
import logging
import re

from backend.config import GOOGLE_CLIENT_ID
from backend.memory.sqlite.database import get_connection
import sqlite3
from backend.services.google_verify import GoogleVerificationError, verify_google_credential

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

def _load_secret_key():
    key = os.environ.get("CRACKAPP_SECRET_KEY", "").strip()
    if not key:
        try:
            from dotenv import dotenv_values
            key = (dotenv_values().get("CRACKAPP_SECRET_KEY") or "").strip()
        except Exception:
            key = ""
    if not key:
        raise RuntimeError("CRACKAPP_SECRET_KEY is not configured; refusing to use an insecure default")
    return key


SECRET_KEY = _load_secret_key()


# ── Token Helpers ─────────────────────────────────────────────────────────────

def _generate_token(user_id: int, username: str, email: str) -> str:
    payload = {
        "user_id": user_id,
        "username": username,
        "email": email,
        "iat": time.time(),
        "exp": int(time.time()) + 86400 * 7  # 7 days
    }
    raw_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    signature = hmac.new(SECRET_KEY.encode(), raw_payload.encode(), hashlib.sha256).hexdigest()
    return f"{raw_payload}.{signature}"


def verify_token(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        raw_payload, sig = parts
        expected_sig = hmac.new(SECRET_KEY.encode(), raw_payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        payload = json.loads(base64.urlsafe_b64decode(raw_payload.encode()).decode())
        if payload.get("exp", 0) < int(time.time()):
            return None
        # session invalidation: reject tokens issued before an account security reset
        try:
            conn = get_connection()
            try:
                row = conn.execute("SELECT tokens_invalidated_before FROM users WHERE id = ?", (payload.get("user_id"),)).fetchone()
            finally:
                conn.close()
        except sqlite3.OperationalError:
            row = None  # tokens_invalidated_before not migrated yet
        if row:
            tib = row["tokens_invalidated_before"] if "tokens_invalidated_before" in row.keys() else 0
            issued = payload.get("iat") or (payload.get("exp", 0) - 86400 * 7)
            if tib and issued < tib:
                return None
        return payload
    except Exception as e:
        logger.debug("Token verification error: %s", e)
        return None


def get_current_user_from_header(authorization: Optional[str] = Header(None)) -> Optional[dict]:
    if not authorization or not isinstance(authorization, str) or not authorization.startswith("Bearer "):
        return None
    token = authorization[7:].strip()
    return verify_token(token)


# ── Schemas ───────────────────────────────────────────────────────────────────

class SignUpRequest(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username_or_email: str
    password: str


class GoogleAuthRequest(BaseModel):
    credential: Optional[str] = None
    email: Optional[str] = None
    name: Optional[str] = None
    google_id: Optional[str] = None
    avatar_url: Optional[str] = None


class AuthResponse(BaseModel):
    token: str
    user: dict


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/signup", response_model=AuthResponse)
def signup(payload: SignUpRequest):
    username = payload.username.strip()
    email = payload.email.strip().lower()
    password = payload.password

    if not username or len(username) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username must be at least 3 characters long."
        )

    if not email or "@" not in email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A valid email address is required."
        )

    if not password or len(password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 6 characters long."
        )

    conn = get_connection()
    try:
        cursor = conn.cursor()
        # Check if username or email exists
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        existing = cursor.fetchone()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A user with that username or email already exists."
            )

        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
        created_at = datetime.now(timezone.utc).isoformat()

        cursor.execute(
            "INSERT INTO users (username, email, password_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)",
            (username, email, password_hash, salt, created_at)
        )
        conn.commit()
        user_id = cursor.lastrowid

        token = _generate_token(user_id, username, email)
        return {
            "token": token,
            "user": {
                "id": user_id,
                "username": username,
                "email": email,
                "created_at": created_at
            }
        }
    finally:
        conn.close()


@router.post("/login", response_model=AuthResponse)
def login(payload: LoginRequest):
    identifier = payload.username_or_email.strip()
    password = payload.password

    if not identifier or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username/email and password are required."
        )

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, email, password_hash, salt, created_at FROM users WHERE username = ? OR email = ?",
            (identifier, identifier.lower())
        )
        user = cursor.fetchone()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password."
            )

        salt = user["salt"]
        expected_hash = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
        if not hmac.compare_digest(user["password_hash"], expected_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password."
            )

        token = _generate_token(user["id"], user["username"], user["email"])
        return {
            "token": token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "created_at": user["created_at"]
            }
        }
    finally:
        conn.close()


@router.get("/google/config")
def google_config():
    """Return public Google OAuth client configuration."""
    import os
    client_id = os.getenv("GOOGLE_CLIENT_ID") or GOOGLE_CLIENT_ID
    if not client_id:
        try:
            from dotenv import dotenv_values
            vals = dotenv_values()
            client_id = vals.get("GOOGLE_CLIENT_ID", "")
        except Exception:
            pass
    return {
        "google_client_id": client_id or ""
    }


@router.post("/google", response_model=AuthResponse)
def google_auth(payload: GoogleAuthRequest):
    # Only a Google-issued ID token verified server-side may establish identity.
    # Client-supplied email/name/google_id/avatar are never accepted.
    if not payload.credential:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "GOOGLE_CREDENTIAL_REQUIRED",
                    "message": "Google sign-in requires the Google credential token."},
        )
    try:
        claims = verify_google_credential(payload.credential)
    except GoogleVerificationError as e:
        http_status = (status.HTTP_503_SERVICE_UNAVAILABLE
                       if e.code == "GOOGLE_VERIFICATION_UNAVAILABLE"
                       else status.HTTP_401_UNAUTHORIZED)
        raise HTTPException(status_code=http_status,
                            detail={"code": e.code, "message": e.message})

    email = claims["email"].strip().lower()
    name = claims.get("name") or None
    google_id = claims["sub"]
    avatar_url = claims.get("picture") or None

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, email, avatar_url, google_id, auth_provider, google_verified, created_at FROM users WHERE email = ?",
            (email,))
        user = cursor.fetchone()

        if user:
            provider = user["auth_provider"] if "auth_provider" in user.keys() else "local"
            if provider != "google":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={"code": "GOOGLE_LINK_REQUIRES_PASSWORD",
                            "message": "This email belongs to a password account. Sign in with your password instead."},
                )
            user_id = user["id"]
            username = user["username"]
            created_at = user["created_at"]
            was_verified = user["google_verified"] if "google_verified" in user.keys() else 0
            if was_verified:
                # Already verified by the server-verified flow: plain refresh.
                cursor.execute(
                    "UPDATE users SET google_id = ?, avatar_url = COALESCE(avatar_url, ?) WHERE id = ?",
                    (google_id, avatar_url, user_id))
            else:
                # First verified login for a pre-verification Google row. The old
                # endpoint accepted client-supplied email/google_id, so nothing on
                # this row is trustworthy - not even a matching subject. Rebind
                # the subject, invalidate every prior session, revoke grants.
                now_ts = time.time()
                cursor.execute(
                    "UPDATE users SET google_id = ?, avatar_url = COALESCE(avatar_url, ?), google_verified = 1, tokens_invalidated_before = ? WHERE id = ?",
                    (google_id, avatar_url, now_ts, user_id))
                try:
                    cursor.execute("DELETE FROM verified_targets WHERE username = ?", (username,))
                except sqlite3.OperationalError:
                    pass  # grants table not created yet
            conn.commit()
        else:
            base_username = ""
            if name:
                base_username = re.sub(r"[^a-zA-Z0-9_]", "", name.lower().replace(" ", "_"))
            if not base_username or len(base_username) < 3:
                base_username = re.sub(r"[^a-zA-Z0-9_]", "", email.split("@")[0].lower())
            if len(base_username) < 3:
                base_username = f"analyst_{secrets.token_hex(2)}"

            candidate_username = base_username
            cursor.execute("SELECT id FROM users WHERE username = ?", (candidate_username,))
            if cursor.fetchone():
                candidate_username = f"{base_username}_{secrets.token_hex(2)}"

            username = candidate_username
            salt = secrets.token_hex(16)
            dummy_hash = hashlib.sha256((salt + "google_oauth_no_direct_login").encode("utf-8")).hexdigest()
            created_at = datetime.now(timezone.utc).isoformat()

            cursor.execute(
                """
                INSERT INTO users (username, email, password_hash, salt, auth_provider, avatar_url, google_id, google_verified, created_at)
                VALUES (?, ?, ?, ?, 'google', ?, ?, 1, ?)
                """,
                (username, email, dummy_hash, salt, avatar_url, google_id, created_at))
            conn.commit()
            user_id = cursor.lastrowid

        token = _generate_token(user_id, username, email)
        return {
            "token": token,
            "user": {
                "id": user_id,
                "username": username,
                "email": email,
                "avatar_url": avatar_url,
                "auth_provider": "google",
                "created_at": created_at
            }
        }
    finally:
        conn.close()



@router.get("/me")
def me(authorization: Optional[str] = Header(None)):
    user_payload = get_current_user_from_header(authorization)
    if not user_payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated."
        )

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, email, avatar_url, auth_provider, created_at FROM users WHERE id = ?",
            (user_payload["user_id"],)
        )
        user = cursor.fetchone()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )
        return {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "avatar_url": user["avatar_url"] if "avatar_url" in user.keys() else None,
            "auth_provider": user["auth_provider"] if "auth_provider" in user.keys() else "local",
            "created_at": user["created_at"]
        }
    finally:
        conn.close()
