import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "plugins" / "sinkproof" / "skills" / "audit" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import osv  # noqa: E402

LODASH = {"ecosystem": "npm", "name": "lodash", "version": "4.17.15"}
EXPRESS = {"ecosystem": "npm", "name": "express", "version": "4.21.2"}

DETAIL = {
    "id": "GHSA-p6mc-m468-83gw",
    "aliases": ["CVE-2020-8203"],
    "summary": "Prototype Pollution in lodash",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"}],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "3.7.0"}, {"fixed": "4.17.19"}]}],
        }
    ],
}


class QueryTests(unittest.TestCase):
    def test_ok_result_includes_fixed_versions_and_aliases(self):
        batch = {"results": [{"vulns": [{"id": "GHSA-p6mc-m468-83gw"}]}]}
        with mock.patch.object(osv, "_post", return_value=batch), \
             mock.patch.object(osv, "_get", return_value=DETAIL):
            out = osv.query([LODASH])
        self.assertEqual(out["status"], "ok")
        vuln = out["results"][0]["vulns"][0]
        self.assertEqual(vuln["aliases"], ["CVE-2020-8203"])
        self.assertEqual(vuln["fixed"], ["4.17.19"])
        self.assertTrue(vuln["severity"].startswith("CVSS:3.1"))

    def test_sends_only_name_ecosystem_version(self):
        with mock.patch.object(osv, "_post", return_value={"results": [{}]}) as post:
            osv.query([dict(LODASH, path="package.json")])
        payload = post.call_args[0][1]
        self.assertEqual(
            payload,
            {"queries": [{"package": {"ecosystem": "npm", "name": "lodash"}, "version": "4.17.15"}]},
        )

    def test_fetches_each_vuln_detail_once(self):
        batch = {"results": [{"vulns": [{"id": "X-1"}]}, {"vulns": [{"id": "X-1"}]}]}
        detail = dict(DETAIL, id="X-1")
        with mock.patch.object(osv, "_post", return_value=batch), \
             mock.patch.object(osv, "_get", return_value=detail) as get:
            osv.query([LODASH, EXPRESS])
        self.assertEqual(get.call_count, 1)

    def test_package_without_vulns(self):
        with mock.patch.object(osv, "_post", return_value={"results": [{}]}):
            out = osv.query([EXPRESS])
        self.assertEqual(out["results"][0]["vulns"], [])

    def test_network_failure_returns_unavailable(self):
        with mock.patch.object(osv, "_post", side_effect=urllib.error.URLError("offline")):
            out = osv.query([LODASH])
        self.assertEqual(out["status"], "unavailable")
        self.assertIn("offline", out["error"])

    def test_timeout_returns_unavailable(self):
        with mock.patch.object(osv, "_post", side_effect=TimeoutError("timed out")):
            out = osv.query([LODASH])
        self.assertEqual(out["status"], "unavailable")

    def test_empty_input_makes_no_request(self):
        with mock.patch.object(osv, "_post") as post:
            out = osv.query([])
        post.assert_not_called()
        self.assertEqual(out, {"status": "ok", "results": []})


class ValidateTests(unittest.TestCase):
    def test_rejects_missing_version(self):
        with self.assertRaises(ValueError):
            osv.validate([{"ecosystem": "npm", "name": "lodash"}])


class RobustnessTests(unittest.TestCase):
    def test_result_count_mismatch_is_unavailable_not_ok(self):
        with mock.patch.object(osv, "_post", return_value={"error": "bad"}):
            out = osv.query([LODASH])
        self.assertEqual(out["status"], "unavailable")
        self.assertIn("unexpected", out["error"])

    def test_time_budget_exceeded_is_unavailable(self):
        batch = {"results": [{"vulns": [{"id": f"X-{n}"} for n in range(5)]}]}
        clock = iter([0, 10, 30, 50, 70, 90, 110, 130])
        with mock.patch.object(osv, "_post", return_value=batch),              mock.patch.object(osv, "_get", return_value=DETAIL) as get,              mock.patch.object(osv, "_clock", side_effect=lambda: next(clock)):
            out = osv.query([LODASH])
        self.assertEqual(out["status"], "unavailable")
        self.assertIn("budget", out["error"])
        self.assertLess(get.call_count, 5)

    def test_http_client_error_is_reported_as_error(self):
        err = urllib.error.HTTPError("https://api.osv.dev", 400, "Bad Request", {}, None)
        with mock.patch.object(osv, "_post", side_effect=err):
            out = osv.query([LODASH])
        self.assertEqual(out["status"], "error")
        self.assertIn("400", out["error"])

    def test_validate_rejects_non_object_items(self):
        with self.assertRaises(ValueError):
            osv.validate([3])

    def test_validate_rejects_non_string_fields(self):
        with self.assertRaises(ValueError):
            osv.validate([{"ecosystem": "npm", "name": ["lodash"], "version": "1.0.0"}])


if __name__ == "__main__":
    unittest.main()
