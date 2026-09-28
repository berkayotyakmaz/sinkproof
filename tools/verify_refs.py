#!/usr/bin/env python3
"""Verify the reference line of knowledge files against primary sources.

Usage: python tools/verify_refs.py <file.md> [<file.md> ...]

Line 2 of each file must be `CWE-<n> · OWASP A<nn>:2021 · ASVS V<x.y.z>`.
Checks: the CWE exists (MITRE CWE API), the CWE is listed under the OWASP Top 10
2021 category (or the file says "does not map CWE-<n>"), and the ASVS 4.0.3
requirement exists. Prints one JSON object per file with the CWE name and the
ASVS requirement text so a human or agent can judge that they fit the file.
Exit status 1 if any file fails.

Development tool only; not shipped with the skill.
"""
import json
import re
import sys
import urllib.request

REF_RE = re.compile(r"^CWE-(\d+) · OWASP (A\d{2}):2021 · ASVS V(\d+)\.(\d+)\.(\d+)$")
NOTE_RE = re.compile(r"does not map CWE-\d+", re.I)

CWE_API = "https://cwe-api.mitre.org/api/v1/cwe/weakness/{}"
TOP10_URL = "https://raw.githubusercontent.com/OWASP/Top10/master/2021/docs/en/{}"
ASVS_URL = "https://raw.githubusercontent.com/OWASP/ASVS/v4.0.3/4.0/en/{}"

TOP10 = {
    "A01": "A01_2021-Broken_Access_Control.md",
    "A02": "A02_2021-Cryptographic_Failures.md",
    "A03": "A03_2021-Injection.md",
    "A04": "A04_2021-Insecure_Design.md",
    "A05": "A05_2021-Security_Misconfiguration.md",
    "A06": "A06_2021-Vulnerable_and_Outdated_Components.md",
    "A07": "A07_2021-Identification_and_Authentication_Failures.md",
    "A08": "A08_2021-Software_and_Data_Integrity_Failures.md",
    "A09": "A09_2021-Security_Logging_and_Monitoring_Failures.md",
    "A10": "A10_2021-Server-Side_Request_Forgery_(SSRF).md",
}
ASVS = {
    1: "0x10-V1-Architecture.md",
    2: "0x11-V2-Authentication.md",
    3: "0x12-V3-Session-management.md",
    4: "0x12-V4-Access-Control.md",
    5: "0x13-V5-Validation-Sanitization-Encoding.md",
    6: "0x14-V6-Cryptography.md",
    7: "0x15-V7-Error-Logging.md",
    8: "0x16-V8-Data-Protection.md",
    9: "0x17-V9-Communications.md",
    10: "0x18-V10-Malicious.md",
    11: "0x19-V11-BusLogic.md",
    12: "0x20-V12-Files-Resources.md",
    13: "0x21-V13-API.md",
    14: "0x22-V14-Config.md",
}

_cache = {}


def fetch(url):
    if url not in _cache:
        with urllib.request.urlopen(url, timeout=30) as response:
            _cache[url] = response.read().decode("utf-8")
    return _cache[url]


def _cwe_name(number, fetch):
    try:
        data = json.loads(fetch(CWE_API.format(number)))
    except (OSError, ValueError):
        return None
    entries = data.get("Weaknesses") or data.get("Categories") or []
    return entries[0].get("Name") if entries else None


def check(text, fetch=fetch):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    match = REF_RE.match(lines[1]) if len(lines) > 1 else None
    if not match:
        return {"ok": False, "error": "reference line not in expected format"}
    cwe, category, major, minor, patch = match.groups()
    if category not in TOP10:
        return {"ok": False, "error": f"unknown OWASP Top 10 2021 category {category}"}
    if int(major) not in ASVS:
        return {"ok": False, "error": f"unknown ASVS chapter V{major}"}
    result = {"cwe": f"CWE-{cwe}", "cwe_name": _cwe_name(cwe, fetch)}
    try:
        top10 = fetch(TOP10_URL.format(TOP10[category]))
        asvs = fetch(ASVS_URL.format(ASVS[int(major)]))
    except OSError as exc:
        return dict(result, ok=False, error=str(exc))
    if re.search(rf"CWE-{cwe}(?!\d)", top10):
        result["owasp"] = "mapped"
    elif NOTE_RE.search(text):
        result["owasp"] = "unofficial-noted"
    else:
        result["owasp"] = "not-mapped"
    requirement = re.search(rf"\*\*{major}\.{minor}\.{patch}\*\*\s*\|\s*([^|]+)", asvs)
    result["asvs_text"] = requirement.group(1).strip()[:200] if requirement else None
    result["ok"] = bool(result["cwe_name"]) and result["owasp"] != "not-mapped" and bool(requirement)
    return result


def main(paths):
    sys.stdout.reconfigure(encoding="utf-8")
    failed = False
    for path in paths:
        with open(path, encoding="utf-8") as f:
            result = check(f.read())
        result = {"file": path, **result}
        failed = failed or not result["ok"]
        print(json.dumps(result, ensure_ascii=False))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
