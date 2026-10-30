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


def _decode_google_jwt(credential: str) -> dict:
    """Safely decode the JSON payload of a Google JWT, verifying with Google tokeninfo if reachable."""
    try:
        import urllib.request
        req = urllib.request.Request(f"https://oauth2.googleapis.com/tokeninfo?id_token={credential}")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if "email" in data:
                return data
    except Exception:
        pass

    try:
        parts = credential.split(".")
        if len(parts) != 3:
            return {}
        payload_b64 = parts[1]
        padding = 4 - (len(payload_b64) % 4)
        if padding != 4:
            payload_b64 += "=" * padding
        decoded = base64.urlsafe_b64decode(payload_b64).decode("utf-8")
        return json.loads(decoded)
    except Exception as e:
        logger.warning("Failed to decode Google credential token: %s", e)
        return {}


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
    email = payload.email
    name = payload.name
    google_id = payload.google_id
    avatar_url = payload.avatar_url

    # If a Google credential JWT was provided, extract user details from it
    if payload.credential:
        decoded = _decode_google_jwt(payload.credential)
        if decoded:
            email = decoded.get("email") or email
            name = decoded.get("name") or name
            google_id = decoded.get("sub") or google_id
            avatar_url = decoded.get("picture") or avatar_url

    if not email or "@" not in email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A valid Google email is required."
        )

    email = email.strip().lower()

    conn = get_connection()
    try:
        cursor = conn.cursor()
        # Check if user already exists with this email
        cursor.execute("SELECT id, username, email, avatar_url, google_id, created_at FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user:
            user_id = user["id"]
            username = user["username"]
            created_at = user["created_at"]
            if (not user["google_id"] and google_id) or (not user["avatar_url"] and avatar_url):
                cursor.execute(
                    "UPDATE users SET google_id = COALESCE(google_id, ?), avatar_url = COALESCE(avatar_url, ?) WHERE id = ?",
                    (google_id, avatar_url, user_id)
                )
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
                INSERT INTO users (username, email, password_hash, salt, auth_provider, avatar_url, google_id, created_at)
                VALUES (?, ?, ?, ?, 'google', ?, ?, ?)
                """,
                (username, email, dummy_hash, salt, avatar_url, google_id, created_at)
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
