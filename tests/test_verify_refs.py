import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import verify_refs  # noqa: E402

GOOD = """# IDOR
CWE-639 · OWASP A01:2021 · ASVS V4.2.1

## What it is
Text.
"""

CWE_JSON = json.dumps({"Weaknesses": [{"ID": "639", "Name": "Authorization Bypass Through User-Controlled Key"}]})
TOP10_A01 = "## List of Mapped CWEs\n[CWE-639 Authorization Bypass](x)\n[CWE-6390 Other](y)\n"
ASVS_V4 = "| **4.2.1** | Verify that sensitive data and APIs are protected against IDOR attacks. | ✓ |\n"


def fake_fetch(pages):
    def fetch(url):
        for key, body in pages.items():
            if key in url:
                return body
        raise OSError(f"404 {url}")
    return fetch


PAGES = {"weakness/639": CWE_JSON, "A01_2021": TOP10_A01, "0x12-V4-Access-Control.md": ASVS_V4}


class CheckTests(unittest.TestCase):
    def test_all_references_verified(self):
        result = verify_refs.check(GOOD, fetch=fake_fetch(PAGES))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["cwe_name"], "Authorization Bypass Through User-Controlled Key")
        self.assertEqual(result["owasp"], "mapped")
        self.assertIn("IDOR", result["asvs_text"])

    def test_malformed_reference_line_fails(self):
        result = verify_refs.check("# X\nCWE-639 OWASP A01\n", fetch=fake_fetch(PAGES))
        self.assertFalse(result["ok"])
        self.assertIn("format", result["error"])

    def test_unknown_cwe_fails(self):
        pages = dict(PAGES)
        del pages["weakness/639"]
        result = verify_refs.check(GOOD, fetch=fake_fetch(pages))
        self.assertFalse(result["ok"])
        self.assertIsNone(result["cwe_name"])

    def test_cwe_number_prefix_does_not_count_as_mapped(self):
        text = GOOD.replace("CWE-639", "CWE-63")
        pages = {"weakness/63": CWE_JSON.replace("639", "63"), "A01_2021": TOP10_A01, "0x12-V4": ASVS_V4}
        result = verify_refs.check(text, fetch=fake_fetch(pages))
        self.assertEqual(result["owasp"], "not-mapped")
        self.assertFalse(result["ok"])

    def test_unmapped_owasp_passes_only_with_note(self):
        pages = dict(PAGES, A01_2021="no cwes here")
        self.assertEqual(verify_refs.check(GOOD, fetch=fake_fetch(pages))["owasp"], "not-mapped")
        noted = GOOD + "\nOWASP Top 10 2021 does not map CWE-639 to a category; A01 is the closest fit.\n"
        result = verify_refs.check(noted, fetch=fake_fetch(pages))
        self.assertEqual(result["owasp"], "unofficial-noted")
        self.assertTrue(result["ok"])

    def test_missing_asvs_requirement_fails(self):
        pages = dict(PAGES, **{"0x12-V4-Access-Control.md": "| **4.2.2** | other |"})
        result = verify_refs.check(GOOD, fetch=fake_fetch(pages))
        self.assertFalse(result["ok"])
        self.assertIsNone(result["asvs_text"])

    def test_unknown_category_or_chapter_fails_cleanly(self):
        result = verify_refs.check(GOOD.replace("A01:2021", "A11:2021"), fetch=fake_fetch(PAGES))
        self.assertFalse(result["ok"])
        self.assertIn("A11", result["error"])

    def test_network_error_fails_cleanly(self):
        def broken(url):
            raise OSError("offline")
        result = verify_refs.check(GOOD, fetch=broken)
        self.assertFalse(result["ok"])
        self.assertIn("offline", result["error"])


if __name__ == "__main__":
    unittest.main()
