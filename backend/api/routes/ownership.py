from typing import Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from backend.services import ownership

router = APIRouter()

WEAK_IDENTITY_MESSAGE = (
    "This Google sign-in predates server verification. Sign out and sign in with Google again, or use a password account. "
    "Use a password account, or use the demo target."
)


class ChallengeRequest(BaseModel):
    url: str


class VerifyRequest(BaseModel):
    url: str
    method: str


def _demo_payload():
    return {
        "mode": "demo",
        "verified": True,
        "demo": True,
        "message": "Demo target: the local mock server only. No real website is scanned and no ownership proof is required.",
    }


def _require_strong(authorization):
    user, code = ownership.get_strong_user(authorization)
    if user:
        return user
    if code == "AUTH_WEAK_IDENTITY":
        raise HTTPException(status_code=403, detail={"code": code, "message": WEAK_IDENTITY_MESSAGE})
    raise HTTPException(status_code=401, detail={"code": "AUTH_REQUIRED", "message": "Sign in to verify and scan real targets."})


@router.post("/ownership/challenge")
def create_challenge(payload: ChallengeRequest, authorization: Optional[str] = Header(None)):
    url = payload.url.strip()
    if ownership.is_demo_url(url):
        return _demo_payload()
    user = _require_strong(authorization)
    try:
        return ownership.create_challenge(url, user["username"])
    except ownership.OwnershipError as e:
        raise HTTPException(status_code=400, detail={"code": e.code, "message": e.message})


@router.post("/ownership/verify")
def verify_target(payload: VerifyRequest, authorization: Optional[str] = Header(None)):
    url = payload.url.strip()
    if ownership.is_demo_url(url):
        return _demo_payload()
    user = _require_strong(authorization)
    method = (payload.method or "").strip().lower()
    if method not in ("file", "dns"):
        raise HTTPException(status_code=400, detail={"code": "INVALID_METHOD", "message": "method must be 'file' or 'dns'"})
    try:
        return ownership.verify(url, user["username"], method)
    except ownership.OwnershipError as e:
        status = 403 if e.code in ("VERIFICATION_FAILED", "NO_CHALLENGE", "CHALLENGE_EXPIRED") else 400
        raise HTTPException(status_code=status, detail={"code": e.code, "message": e.message})


@router.get("/ownership/status")
def ownership_status(url: str, authorization: Optional[str] = Header(None)):
    if ownership.is_demo_url(url.strip()):
        return {"verified": True, "demo": True}
    user, code = ownership.get_strong_user(authorization)
    if not user:
        return {"verified": False, "demo": False, "code": code}
    allowed, reason = ownership.is_verified(url, user["username"])
    return {"verified": allowed, "demo": False, "message": reason}
