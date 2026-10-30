"""Server-side Google ID-token verification for sign-in (Sniff backend).

Follows Google's official guidance: an ID token is trusted only after its
signature is verified by Google - either locally with the google-auth
library (preferred, verifies against Google's certs) or via Google's
tokeninfo endpoint. Both paths then enforce, against OUR configuration:
  - aud == our configured OAuth client ID
  - iss in Google's issuer set
  - exp in the future
  - email_verified true
  - email + sub claims present
There is deliberately NO unverified-decode fallback anywhere in this module.
"""
import json
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    from backend.config import GOOGLE_CLIENT_ID
except Exception:  # module importable outside the project (tests)
    GOOGLE_CLIENT_ID = ""

GOOGLE_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}


class GoogleVerificationError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def _client_id():
    import os
    cid = (os.getenv("GOOGLE_CLIENT_ID") or GOOGLE_CLIENT_ID or "").strip()
    if not cid:
        try:
            from dotenv import dotenv_values
            cid = (dotenv_values().get("GOOGLE_CLIENT_ID") or "").strip()
        except Exception:
            pass
    if not cid:
        raise GoogleVerificationError(
            "GOOGLE_NOT_CONFIGURED",
            "Google sign-in is not configured on the server.",
        )
    return cid


def _check_claims(data, cid):
    if data.get("aud", "") != cid:
        raise GoogleVerificationError(
            "GOOGLE_TOKEN_INVALID", "Google token was not issued for this app.")
    if data.get("iss", "") not in GOOGLE_ISSUERS:
        raise GoogleVerificationError(
            "GOOGLE_TOKEN_INVALID", "Google token issuer is not Google.")
    try:
        exp = int(data.get("exp", "0"))
    except (TypeError, ValueError):
        exp = 0
    if exp <= int(time.time()):
        raise GoogleVerificationError(
            "GOOGLE_TOKEN_EXPIRED", "Google sign-in token has expired.")
    if str(data.get("email_verified", "")).lower() != "true":
        raise GoogleVerificationError(
            "GOOGLE_EMAIL_UNVERIFIED", "The Google account email is not verified.")
    if not data.get("email") or not data.get("sub"):
        raise GoogleVerificationError(
            "GOOGLE_TOKEN_INVALID", "Google token is missing identity claims.")
    return {
        "email": data["email"],
        "sub": data["sub"],
        "name": data.get("name", ""),
        "picture": data.get("picture", ""),
    }


def _verify_with_library(credential, cid):
    from google.oauth2 import id_token as google_id_token
    from google.auth.transport import requests as google_requests
    return google_id_token.verify_oauth2_token(
        credential, google_requests.Request(), cid)


def _verify_with_tokeninfo(credential, cid):
    url = ("https://oauth2.googleapis.com/tokeninfo?id_token="
           + urllib.parse.quote(credential, safe=""))
    try:
        with urllib.request.urlopen(urllib.request.Request(url), timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError:
        raise GoogleVerificationError(
            "GOOGLE_TOKEN_INVALID", "Google rejected the sign-in token.")
    except GoogleVerificationError:
        raise
    except Exception:
        raise GoogleVerificationError(
            "GOOGLE_VERIFICATION_UNAVAILABLE",
            "Could not reach Google to verify the sign-in. Please try again.")


def verify_google_credential(credential):
    """Return verified identity claims {email, sub, name, picture} or raise
    GoogleVerificationError. Never returns unverified claims."""
    if not credential or not isinstance(credential, str) or credential.count(".") != 2:
        raise GoogleVerificationError(
            "GOOGLE_TOKEN_INVALID", "Missing or malformed Google credential.")
    cid = _client_id()
    try:
        data = _verify_with_library(credential, cid)
    except ImportError:
        data = _verify_with_tokeninfo(credential, cid)
    except ValueError:
        raise GoogleVerificationError(
            "GOOGLE_TOKEN_INVALID", "Google sign-in token failed verification.")
    return _check_claims(data, cid)
