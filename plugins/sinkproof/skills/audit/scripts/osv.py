#!/usr/bin/env python3
"""Query OSV.dev for known vulnerabilities in specific package versions.

Usage: python osv.py < packages.json

Input:  [{"ecosystem": "npm", "name": "lodash", "version": "4.17.15"}, ...]
        Ecosystem names follow OSV: npm, PyPI, Maven, Go, crates.io,
        RubyGems, Packagist, NuGet.
Output: {"status": "ok", "results": [...]} or
        {"status": "unavailable", "error": "..."} when OSV cannot be reached, answers
        unexpectedly, or the whole query takes longer than BUDGET seconds.
        {"status": "error", "error": "..."} when OSV rejects the query (bad input).

Only package ecosystem, name and version are sent. No source code leaves the machine.
"""
import json
import sys
import time
import urllib.error
import urllib.request

API = "https://api.osv.dev/v1"
TIMEOUT = 20
BUDGET = 60  # seconds for the whole query; callers should allow more than this
_clock = time.monotonic


class BudgetExceeded(Exception):
    pass


def _post(url, payload, timeout=TIMEOUT):
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def _get(url, timeout=TIMEOUT):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.load(response)


def validate(packages):
    if not isinstance(packages, list):
        raise ValueError("input must be a JSON array")
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            raise ValueError(f"package #{index}: must be a JSON object")
        missing = [k for k in ("ecosystem", "name", "version") if not package.get(k)]
        if missing:
            raise ValueError(f"package #{index}: missing {', '.join(missing)}")
        for key in ("ecosystem", "name", "version"):
            if not isinstance(package[key], str):
                raise ValueError(f"package #{index}: {key} must be a string")


def _fixed_versions(vuln, package):
    fixed = set()
    for affected in vuln.get("affected", []):
        target = affected.get("package", {})
        if target.get("name") != package["name"] or target.get("ecosystem") != package["ecosystem"]:
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed.add(event["fixed"])
    return sorted(fixed)


def _severity(vuln):
    for entry in vuln.get("severity", []):
        if entry.get("score"):
            return entry["score"]
    return vuln.get("database_specific", {}).get("severity")


def query(packages):
    if not packages:
        return {"status": "ok", "results": []}
    queries = [
        {"package": {"ecosystem": p["ecosystem"], "name": p["name"]}, "version": p["version"]}
        for p in packages
    ]
    start = _clock()

    def remaining():
        left = BUDGET - (_clock() - start)
        if left <= 0:
            raise BudgetExceeded(f"time budget of {BUDGET}s exceeded")
        return min(TIMEOUT, left)

    try:
        batch = _post(f"{API}/querybatch", {"queries": queries}, timeout=remaining())
        if len(batch.get("results", [])) != len(packages):
            return {"status": "unavailable", "error": "unexpected response from OSV: result count does not match query count"}
        details = {}
        results = []
        for package, result in zip(packages, batch.get("results", [])):
            vulns = []
            for ref in result.get("vulns", []):
                vid = ref["id"]
                if vid not in details:
                    details[vid] = _get(f"{API}/vulns/{vid}", timeout=remaining())
                detail = details[vid]
                vulns.append({
                    "id": vid,
                    "aliases": detail.get("aliases", []),
                    "summary": detail.get("summary", ""),
                    "severity": _severity(detail),
                    "fixed": _fixed_versions(detail, package),
                })
            results.append({"package": package, "vulns": vulns})
        return {"status": "ok", "results": results}
    except urllib.error.HTTPError as exc:
        if 400 <= exc.code < 500:
            return {"status": "error", "error": f"OSV rejected the query ({exc.code}): check ecosystem names and versions"}
        return {"status": "unavailable", "error": f"OSV returned {exc.code}"}
    except BudgetExceeded as exc:
        return {"status": "unavailable", "error": str(exc)}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return {"status": "unavailable", "error": str(exc)}


def main():
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    try:
        packages = json.load(sys.stdin)
        validate(packages)
    except ValueError as exc:  # includes JSON decode errors
        json.dump({"status": "error", "error": str(exc)}, sys.stdout)
        sys.exit(2)
    json.dump(query(packages), sys.stdout, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
