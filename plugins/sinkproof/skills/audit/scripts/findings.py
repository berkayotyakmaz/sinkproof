#!/usr/bin/env python3
"""Validate audit findings and add stable IDs and rubric severity.

Usage: python findings.py < findings.json > normalized.json

Input is a JSON array of finding objects (templates/finding-format.md).
On invalid input, prints {"error": "..."} and exits with status 2.
"""
import hashlib
import json
import re
import sys

DIMENSIONS = {"SEC", "LOG", "DEP", "ARC", "PRI"}
LEVELS = ("low", "medium", "high")
REQUIRED = ("dimension", "class", "file", "symbol", "impact", "exploitability", "evidence")
STRING_FIELDS = ("dimension", "class", "file", "symbol", "impact", "exploitability")
ABSOLUTE_RE = re.compile(r"^([A-Za-z]:[\\/]|[\\/])")
CLASS_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

# Must match the table in rubric/severity.md (enforced by tests/test_structure.py).
MATRIX = {
    ("high", "high"): "critical",
    ("high", "medium"): "high",
    ("high", "low"): "medium",
    ("medium", "high"): "high",
    ("medium", "medium"): "medium",
    ("medium", "low"): "low",
    ("low", "high"): "low",
    ("low", "medium"): "low",
    ("low", "low"): "low",
}


class FindingError(ValueError):
    pass


def normalize_path(path):
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def finding_id(dimension, cls, path, symbol):
    key = "|".join([dimension, cls, normalize_path(path), symbol or ""])
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:4]
    return f"{dimension}-{cls.upper()}-{digest}"


def severity(impact, exploitability):
    return MATRIX[(impact, exploitability)]


def _validate(index, finding):
    if not isinstance(finding, dict):
        raise FindingError(f"finding #{index}: must be a JSON object, got {type(finding).__name__}")
    missing = [k for k in REQUIRED if not finding.get(k)]
    if missing:
        raise FindingError(f"finding #{index}: missing {', '.join(missing)}")
    for key in STRING_FIELDS:
        if not isinstance(finding[key], str):
            raise FindingError(f"finding #{index}: {key} must be a string, got {finding[key]!r}")
    evidence = finding["evidence"]
    if not isinstance(evidence, list) or not all(isinstance(e, str) and e for e in evidence):
        raise FindingError(f"finding #{index}: evidence must be a non-empty list of strings")
    if ABSOLUTE_RE.match(finding["file"]):
        raise FindingError(f"finding #{index}: file must be relative to the project root, got {finding['file']!r}")
    line = finding.get("line")
    if line is not None and not isinstance(line, int) and not (isinstance(line, str) and line.isdigit()):
        raise FindingError(f"finding #{index}: line must be a single line number, got {line!r}")
    if finding["dimension"] not in DIMENSIONS:
        raise FindingError(f"finding #{index}: unknown dimension {finding['dimension']!r}")
    if not CLASS_RE.match(finding["class"]):
        raise FindingError(f"finding #{index}: class must be kebab-case, got {finding['class']!r}")
    for key in ("impact", "exploitability"):
        if finding[key] not in LEVELS:
            raise FindingError(f"finding #{index}: {key} must be one of {LEVELS}, got {finding[key]!r}")


def _sort_key(finding):
    return (finding["file"], finding.get("line") or 0, finding["class"], finding.get("title", ""))


def normalize(items):
    for index, finding in enumerate(items):
        _validate(index, finding)
    prepared = []
    for finding in items:
        copy = dict(finding)
        copy["file"] = normalize_path(copy["file"])
        if isinstance(copy.get("line"), str):
            copy["line"] = int(copy["line"])
        prepared.append(copy)
    prepared.sort(key=_sort_key)
    seen = {}
    for finding in prepared:
        base = finding_id(finding["dimension"], finding["class"], finding["file"], finding.get("symbol", ""))
        seen[base] = seen.get(base, 0) + 1
        finding["id"] = base if seen[base] == 1 else f"{base}-{seen[base]}"
        finding["severity"] = severity(finding["impact"], finding["exploitability"])
    return prepared


def main():
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    try:
        data = json.load(sys.stdin)
        if not isinstance(data, list):
            raise FindingError("input must be a JSON array")
        json.dump(normalize(data), sys.stdout, indent=2, ensure_ascii=False)
    except (FindingError, json.JSONDecodeError) as exc:
        json.dump({"error": str(exc)}, sys.stdout)
        sys.exit(2)
    except Exception as exc:  # malformed input must never end in a bare traceback
        json.dump({"error": f"unexpected input: {exc!r}"}, sys.stdout)
        sys.exit(2)


if __name__ == "__main__":
    main()
