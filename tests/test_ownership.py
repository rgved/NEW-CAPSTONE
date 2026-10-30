"""Ownership gate unit tests with injected resolver/fetcher. No network, no third-party calls."""
import datetime
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.services import ownership

TMP = tempfile.mkdtemp(prefix="owntest_")
ownership.set_db_path(os.path.join(TMP, "test.db"))
ownership.ensure_table()

RESULTS = []


def check(name, cond):
    RESULTS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


pub = lambda host: ["93.184.216.34"]
priv = lambda host: ["192.168.1.10"]

check("demo localhost:8080 allowed", ownership.is_demo_url("http://localhost:8080"))
check("demo 127.0.0.1:8080 allowed", ownership.is_demo_url("http://127.0.0.1:8080/"))
check("localhost:9000 is NOT demo", not ownership.is_demo_url("http://localhost:9000"))
check("https localhost:8080 is NOT demo", not ownership.is_demo_url("https://localhost:8080"))
check("other loopback port is NOT demo", not ownership.is_demo_url("http://127.0.0.1:3000"))
check("169.254 host is NOT demo", not ownership.is_demo_url("http://169.254.1.1:8080"))

try:
    ownership.validate_public_target("http://192.168.1.1/", resolver=pub)
    check("private IP literal rejected", False)
except ownership.OwnershipError:
    check("private IP literal rejected", True)

try:
    ownership.validate_public_target("http://169.254.169.254/latest", resolver=pub)
    check("cloud metadata IP rejected", False)
except ownership.OwnershipError:
    check("cloud metadata IP rejected", True)

try:
    ownership.validate_public_target("ftp://example.com", resolver=pub)
    check("non-http scheme rejected", False)
except ownership.OwnershipError:
    check("non-http scheme rejected", True)

try:
    ownership.validate_public_target("https://internal.example.com", resolver=priv)
    check("host resolving to private IP rejected", False)
except ownership.OwnershipError:
    check("host resolving to private IP rejected", True)

s, h, p, hk = ownership.validate_public_target("https://example.com", resolver=pub)
check("public https target accepted with default port", hk == "example.com:443")

ch = ownership.create_challenge("https://example.com", "alice", resolver=pub)
check("challenge token + well-known url",
      ch["token"].startswith(ownership.TOKEN_PREFIX)
      and ch["file_url"] == "https://example.com/.well-known/crackapp-verification.txt")

try:
    ownership.verify("https://example.com", "alice", "file", resolver=pub, fetcher=lambda u: "no token here")
    check("wrong token stays unverified", False)
except ownership.OwnershipError as e:
    check("wrong token stays unverified", e.code == "VERIFICATION_FAILED")
check("no grant created on failure", not ownership.is_verified("https://example.com", "alice")[0])

seen = {}
def good_fetch(u):
    seen["url"] = u
    return "anything\n" + ch["token"] + "\n"

res = ownership.verify("https://example.com", "alice", "file", resolver=pub, fetcher=good_fetch)
check("correct token verifies", res["verified"] is True)
check("fetch hit only the exact well-known URL", seen.get("url") == "https://example.com/.well-known/crackapp-verification.txt")
check("is_verified true after success", ownership.is_verified("https://example.com", "alice")[0])
check("another user NOT authorized by alice proof", not ownership.is_verified("https://example.com", "bob")[0])
check("subdomain NOT authorized by root proof", not ownership.is_verified("https://api.example.com", "alice")[0])

ch2 = ownership.create_challenge("https://example.org", "alice", resolver=pub)
try:
    ownership.verify("https://example.org", "alice", "dns", resolver=pub, txt_resolver=lambda n: ["v=spf1 include:x"])
    check("dns wrong record rejected", False)
except ownership.OwnershipError:
    check("dns wrong record rejected", True)
res2 = ownership.verify("https://example.org", "alice", "dns", resolver=pub, txt_resolver=lambda n: [ch2["token"]])
check("dns correct record verifies", res2["verified"] is True)

past = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).isoformat()
conn = ownership._conn()
conn.execute("UPDATE verified_targets SET expires_at=? WHERE host_key=?", (past, "example.com:443"))
conn.commit()
conn.close()
ok, reason = ownership.is_verified("https://example.com", "alice")
check("expired grant rejected", not ok)

try:
    ownership.verify("https://no-challenge.example.net", "alice", "file", resolver=pub, fetcher=lambda u: "x")
    check("verify without challenge rejected", False)
except ownership.OwnershipError as e:
    check("verify without challenge rejected", e.code == "NO_CHALLENGE")


fails = [n for n, c in RESULTS if not c]
print("RESULT: %d passed, %d failed" % (len(RESULTS) - len(fails), len(fails)))
sys.exit(1 if fails else 0)


fails = [n for n, c in RESULTS if not c]
print("RESULT: %d passed, %d failed" % (len(RESULTS) - len(fails), len(fails)))
sys.exit(1 if fails else 0)

# --- identity strength tests (spoof resistance) ---
from backend.api.routes.auth import _generate_token

conn = ownership._conn()
conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, auth_provider TEXT)")
conn.execute("INSERT INTO users (id, username, auth_provider) VALUES (1, 'localuser', 'local')")
conn.execute("INSERT INTO users (id, username, auth_provider) VALUES (2, 'googleuser', 'google')")
conn.commit()
conn.close()

u, code = ownership.get_strong_user("Bearer " + _generate_token(1, "localuser", "l@x.com"))
check("local password account accepted", u is not None and u["username"] == "localuser")
u, code = ownership.get_strong_user("Bearer " + _generate_token(2, "googleuser", "g@x.com"))
check("google-path identity rejected for grants", u is None and code == "AUTH_WEAK_IDENTITY")
u, code = ownership.get_strong_user("Bearer garbage.token")
check("garbage token rejected", u is None and code == "AUTH_REQUIRED")
u, code = ownership.get_strong_user(None)
check("missing token rejected", u is None and code == "AUTH_REQUIRED")
u, code = ownership.get_strong_user("Bearer " + _generate_token(999, "ghost", "ghost@x.com"))
check("token for nonexistent user rejected", u is None and code == "AUTH_REQUIRED")
