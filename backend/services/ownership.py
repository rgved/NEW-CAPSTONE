"""Target ownership verification: challenges, proof checks and scan gating.

Proves technical CONTROL of an exact host (DNS TXT record or a well-known
file). It does NOT prove legal authorization; UI copy keeps that distinction.
Grants are per user, per exact host:port, and expire.
"""
import ipaddress
import secrets
import socket
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone

from backend.memory.sqlite.database import get_connection

DEMO_HOSTS = {"localhost", "127.0.0.1"}
DEMO_PORT = 8080
CHALLENGE_TTL_HOURS = 24
GRANT_TTL_DAYS = 30
TOKEN_PREFIX = "crackapp-site-verification="
TXT_PREFIX = "_crackapp-verification."
WELL_KNOWN_PATH = "/.well-known/crackapp-verification.txt"
MAX_PROOF_BYTES = 8192

_db_path = None


def set_db_path(p):
    global _db_path
    _db_path = p


def _conn():
    return get_connection(_db_path) if _db_path else get_connection()


def ensure_table():
    conn = _conn()
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS verified_targets ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "host_key TEXT NOT NULL, "
            "username TEXT NOT NULL, "
            "token TEXT NOT NULL, "
            "method TEXT, "
            "status TEXT NOT NULL DEFAULT 'pending', "
            "created_at TEXT NOT NULL, "
            "verified_at TEXT, "
            "expires_at TEXT, "
            "UNIQUE(host_key, username))"
        )
        conn.commit()
    finally:
        conn.close()


class OwnershipError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.isoformat()


def _parse(url):
    from urllib.parse import urlparse
    p = urlparse(url.strip())
    if p.scheme not in ("http", "https"):
        raise OwnershipError("INVALID_TARGET", "URL must start with http:// or https://")
    if p.username or p.password:
        raise OwnershipError("INVALID_TARGET", "URLs with embedded credentials are not allowed")
    host = (p.hostname or "").lower().rstrip(".")
    if not host:
        raise OwnershipError("INVALID_TARGET", "URL has no host")
    try:
        port = p.port
    except ValueError:
        raise OwnershipError("INVALID_TARGET", "Invalid port")
    if port is None:
        port = 443 if p.scheme == "https" else 80
    return p.scheme, host, port


def is_demo_url(url):
    """Only the fixed local mock qualifies: http on loopback, port 8080 only."""
    try:
        scheme, host, port = _parse(url)
    except OwnershipError:
        return False
    return scheme == "http" and host in DEMO_HOSTS and port == DEMO_PORT


def _is_global_ip(ip_s):
    try:
        return ipaddress.ip_address(ip_s).is_global
    except ValueError:
        return False


def default_resolver(host):
    out = []
    for fam, _, _, _, sa in socket.getaddrinfo(host, None):
        out.append(sa[0])
    return sorted(set(out))


def validate_public_target(url, resolver=None):
    """Reject non-public targets. Returns (scheme, host, port, host_key)."""
    resolver = resolver or default_resolver
    scheme, host, port = _parse(url)
    try:
        ipaddress.ip_address(host)
        ips = [host]
    except ValueError:
        if host in DEMO_HOSTS or host.endswith(".localhost") or host.endswith(".local") or host.endswith(".internal"):
            raise OwnershipError("INVALID_TARGET", "Local hostnames cannot be verified as public targets")
        try:
            ips = resolver(host)
        except Exception as e:
            raise OwnershipError("INVALID_TARGET", "Could not resolve host: %s" % e)
    if not ips:
        raise OwnershipError("INVALID_TARGET", "Host did not resolve to any address")
    bad = [ip for ip in ips if not _is_global_ip(ip)]
    if bad:
        raise OwnershipError("INVALID_TARGET", "Target resolves to a non-public address (%s). Private, loopback, link-local and reserved ranges cannot be verified." % bad[0])
    return scheme, host, port, "%s:%d" % (host, port)


def default_fetcher(url):
    """Fetch a proof file: no redirects, size cap, strict timeout."""
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "CrackApp-OwnershipCheck/1.0"})
    with opener.open(req, timeout=6) as resp:
        data = resp.read(MAX_PROOF_BYTES + 1)
    if len(data) > MAX_PROOF_BYTES:
        raise OwnershipError("VERIFICATION_FAILED", "Proof file too large")
    return data.decode("utf-8", "ignore")


def default_txt_resolver(name):
    """Return TXT record strings for a DNS name (dnspython, else nslookup)."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(name, "TXT", lifetime=8)
        out = []
        for r in answers:
            out.append("".join(s.decode() if isinstance(s, bytes) else s for s in r.strings))
        return out
    except ImportError:
        pass
    except Exception:
        return []
    try:
        proc = subprocess.run(["nslookup", "-type=TXT", name], capture_output=True, text=True, timeout=10)
        out = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if "text" in line.lower() and "=" in line:
                out.append(line.split("=", 1)[1].strip().strip('"'))
            elif line.startswith('"') and line.endswith('"'):
                out.append(line.strip('"'))
        return out
    except Exception:
        return []


def create_challenge(url, username, resolver=None):
    scheme, host, port, host_key = validate_public_target(url, resolver=resolver)
    ensure_table()
    token = TOKEN_PREFIX + secrets.token_urlsafe(24)
    conn = _conn()
    try:
        conn.execute(
            "INSERT INTO verified_targets (host_key, username, token, method, status, created_at) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(host_key, username) DO UPDATE SET token=excluded.token, status='pending', method=NULL, created_at=excluded.created_at, verified_at=NULL, expires_at=NULL",
            (host_key, username, token, None, "pending", _iso(_now())),
        )
        conn.commit()
    finally:
        conn.close()
    default_port = 443 if scheme == "https" else 80
    netloc = host if port == default_port else "%s:%d" % (host, port)
    return {
        "mode": "verify",
        "host": host,
        "host_key": host_key,
        "token": token,
        "txt_record": TXT_PREFIX + host,
        "file_url": "%s://%s%s" % (scheme, netloc, WELL_KNOWN_PATH),
        "challenge_expires_hours": CHALLENGE_TTL_HOURS,
    }


def verify(url, username, method, resolver=None, fetcher=None, txt_resolver=None):
    fetcher = fetcher or default_fetcher
    txt_resolver = txt_resolver or default_txt_resolver
    scheme, host, port, host_key = validate_public_target(url, resolver=resolver)
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT * FROM verified_targets WHERE host_key=? AND username=?", (host_key, username)
        ).fetchone()
    finally:
        conn.close()
    if not row or row["status"] != "pending":
        raise OwnershipError("NO_CHALLENGE", "No pending verification for this target. Request a verification token first.")
    created = datetime.fromisoformat(row["created_at"])
    if _now() - created > timedelta(hours=CHALLENGE_TTL_HOURS):
        raise OwnershipError("CHALLENGE_EXPIRED", "Verification token expired. Request a new one.")
    token = row["token"]
    if method == "file":
        default_port = 443 if scheme == "https" else 80
        netloc = host if port == default_port else "%s:%d" % (host, port)
        file_url = "%s://%s%s" % (scheme, netloc, WELL_KNOWN_PATH)
        try:
            body = fetcher(file_url)
        except OwnershipError:
            raise
        except Exception as e:
            raise OwnershipError("VERIFICATION_FAILED", "Could not fetch %s: %s" % (file_url, e))
        found = token in body
    elif method == "dns":
        records = txt_resolver(TXT_PREFIX + host)
        found = any(token in (r or "") for r in records)
    else:
        raise OwnershipError("INVALID_METHOD", "method must be 'file' or 'dns'")
    if not found:
        raise OwnershipError("VERIFICATION_FAILED", "Token not found via the %s method yet. DNS can take minutes to propagate." % method)
    now = _now()
    exp = now + timedelta(days=GRANT_TTL_DAYS)
    conn = _conn()
    try:
        conn.execute(
            "UPDATE verified_targets SET status='verified', method=?, verified_at=?, expires_at=? WHERE id=?",
            (method, _iso(now), _iso(exp), row["id"]),
        )
        conn.commit()
    finally:
        conn.close()
    return {"verified": True, "host_key": host_key, "method": method, "expires_at": _iso(exp)}


def is_verified(url, username):
    if is_demo_url(url):
        return True, "demo"
    try:
        scheme, host, port = _parse(url)
    except OwnershipError as e:
        return False, e.message
    ensure_table()
    host_key = "%s:%d" % (host, port)
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT * FROM verified_targets WHERE host_key=? AND username=? AND status='verified'",
            (host_key, username),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return False, "Ownership of %s is not verified for your account." % host_key
    if not row["expires_at"] or datetime.fromisoformat(row["expires_at"]) <= _now():
        return False, "Ownership verification for %s expired. Please re-verify." % host_key
    return True, "verified"


def get_strong_user(authorization):
    """Return (user_dict, None) only for a valid token backed by a password
    (local) account. Google-path identities are self-asserted today (the
    client-supplied email/name fallback), so they cannot authorize grants.
    """
    from backend.api.routes.auth import get_current_user_from_header
    user = get_current_user_from_header(authorization)
    if not user:
        return None, "AUTH_REQUIRED"
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT username, auth_provider, google_verified FROM users WHERE id = ?", (user.get("user_id"),)
        ).fetchone()
    except Exception:
        row = None
    finally:
        conn.close()
    if not row:
        return None, "AUTH_REQUIRED"
    provider = row["auth_provider"] if "auth_provider" in row.keys() else "local"
    if provider == "google":
        verified = row["google_verified"] if "google_verified" in row.keys() else 0
        if not verified:
            return None, "AUTH_WEAK_IDENTITY"
    elif provider != "local":
        return None, "AUTH_WEAK_IDENTITY"
    return {"user_id": user.get("user_id"), "username": row["username"]}, None
