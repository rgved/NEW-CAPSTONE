import json, warnings
from backend.services.severity_model import get_severity_model
CASES = [
 ("Apache HTTP Server Path Traversal","An attacker can read arbitrary files on the server through a crafted path"),
 ("CVE-2021-41773 Apache RCE","Remote code execution via path normalization flaw in Apache 2.4.49"),
 ("WordPress SQL Injection","The plugin parameter id is vulnerable to SQL injection allowing database extraction"),
 ("Reflected XSS in search parameter","User input is reflected without encoding in the search results page"),
 ("Directory listing enabled","The server exposes a directory listing at /backup revealing file names"),
 ("Missing X-Frame-Options header","The response lacks clickjacking protection headers"),
 ("Default admin credentials","The admin panel accepts admin/admin login"),
 ("TLS certificate expired","The server presents an expired SSL certificate"),
 ("Server version disclosure","The Server header reveals nginx 1.18.0 version information"),
 ("Git repository exposed","The .git directory is publicly accessible allowing source code download"),
 ("Outdated jQuery 1.8.3","The site loads a jQuery version with known XSS vulnerabilities"),
 ("Critical severity info","severity cvss high low medium informational info test"),
]
warnings.simplefilter("always")
m = get_severity_model()
out = {"available": m.available, "load_error": m.load_error, "preds": []}
for t, d in CASES:
    r = m.predict(t, d)
    out["preds"].append({"title": t, "label": r["model_label"], "sev": r["model_severity"]})
print("RESULTS-JSON:" + json.dumps(out))
