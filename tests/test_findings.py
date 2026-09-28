import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "plugins" / "sinkproof" / "skills" / "audit" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import findings  # noqa: E402


def make(**overrides):
    base = {
        "dimension": "SEC",
        "class": "idor",
        "title": "Order lookup has no ownership check",
        "file": "src/routes/orders.js",
        "line": 12,
        "symbol": "getOrder",
        "impact": "high",
        "exploitability": "high",
        "evidence": ["req.params.id (src/routes/orders.js:10)"],
        "fix": "Scope the query by req.user.id",
    }
    base.update(overrides)
    return base


class IdTests(unittest.TestCase):
    def test_id_format(self):
        fid = findings.finding_id("SEC", "idor", "src/a.js", "getOrder")
        self.assertRegex(fid, r"^SEC-IDOR-[0-9a-f]{4}$")

    def test_multiword_class_is_uppercased(self):
        fid = findings.finding_id("SEC", "sql-injection", "src/a.js", "search")
        self.assertRegex(fid, r"^SEC-SQL-INJECTION-[0-9a-f]{4}$")

    def test_same_inputs_same_id(self):
        a = findings.finding_id("SEC", "idor", "src/a.js", "getOrder")
        b = findings.finding_id("SEC", "idor", "src/a.js", "getOrder")
        self.assertEqual(a, b)

    def test_windows_and_dot_paths_normalize_to_same_id(self):
        plain = findings.finding_id("SEC", "idor", "src/routes/orders.js", "getOrder")
        windows = findings.finding_id("SEC", "idor", "src\\routes\\orders.js", "getOrder")
        dotted = findings.finding_id("SEC", "idor", "./src/routes/orders.js", "getOrder")
        self.assertEqual(plain, windows)
        self.assertEqual(plain, dotted)

    def test_line_number_does_not_affect_id(self):
        a = findings.normalize([make(line=12)])[0]["id"]
        b = findings.normalize([make(line=80)])[0]["id"]
        self.assertEqual(a, b)

    def test_different_symbol_changes_id(self):
        a = findings.finding_id("SEC", "idor", "src/a.js", "getOrder")
        b = findings.finding_id("SEC", "idor", "src/a.js", "getInvoice")
        self.assertNotEqual(a, b)


class NormalizeTests(unittest.TestCase):
    def test_adds_severity_from_matrix(self):
        out = findings.normalize([make(impact="high", exploitability="medium")])
        self.assertEqual(out[0]["severity"], "high")

    def test_matrix_corners(self):
        self.assertEqual(findings.severity("high", "high"), "critical")
        self.assertEqual(findings.severity("low", "high"), "low")
        self.assertEqual(findings.severity("medium", "low"), "low")
        self.assertEqual(len(findings.MATRIX), 9)

    def test_duplicate_base_ids_get_order_independent_suffixes(self):
        first = make(line=10, title="A")
        second = make(line=20, title="B")
        out1 = findings.normalize([first, second])
        out2 = findings.normalize([second, first])
        ids1 = {f["title"]: f["id"] for f in out1}
        ids2 = {f["title"]: f["id"] for f in out2}
        self.assertEqual(ids1, ids2)
        self.assertTrue(ids1["B"].endswith("-2"))
        self.assertNotEqual(ids1["A"], ids1["B"])

    def test_file_path_is_normalized_in_output(self):
        out = findings.normalize([make(file=".\\src\\routes\\orders.js")])
        self.assertEqual(out[0]["file"], "src/routes/orders.js")

    def test_missing_field_raises_with_index(self):
        bad = make()
        del bad["impact"]
        with self.assertRaises(findings.FindingError) as ctx:
            findings.normalize([make(), bad])
        self.assertIn("finding #1", str(ctx.exception))
        self.assertIn("impact", str(ctx.exception))

    def test_invalid_level_raises(self):
        with self.assertRaises(findings.FindingError) as ctx:
            findings.normalize([make(impact="critical")])
        self.assertIn("impact", str(ctx.exception))

    def test_unknown_dimension_raises(self):
        with self.assertRaises(findings.FindingError):
            findings.normalize([make(dimension="XSS")])

    def test_non_kebab_class_raises(self):
        with self.assertRaises(findings.FindingError):
            findings.normalize([make(**{"class": "SQL Injection"})])

    def test_input_is_not_mutated(self):
        original = make(file="./src/a.js")
        findings.normalize([original])
        self.assertEqual(original["file"], "./src/a.js")
        self.assertNotIn("id", original)


class CliTests(unittest.TestCase):
    def run_cli(self, stdin):
        return subprocess.run(
            [sys.executable, str(SCRIPTS / "findings.py")],
            input=stdin, capture_output=True, text=True, encoding="utf-8",
        )

    def test_cli_success(self):
        result = self.run_cli(json.dumps([make()]))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = json.loads(result.stdout)
        self.assertRegex(data[0]["id"], r"^SEC-IDOR-")

    def test_cli_invalid_json_exits_2(self):
        result = self.run_cli("not json")
        self.assertEqual(result.returncode, 2)
        self.assertIn("error", json.loads(result.stdout))

    def test_cli_non_array_exits_2(self):
        result = self.run_cli(json.dumps({"findings": []}))
        self.assertEqual(result.returncode, 2)
        self.assertIn("array", json.loads(result.stdout)["error"])

    def test_cli_handles_non_ascii(self):
        result = self.run_cli(json.dumps([make(title="Sipariş kontrolü yok")], ensure_ascii=False))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)[0]["title"], "Sipariş kontrolü yok")


class RobustnessTests(unittest.TestCase):
    def test_non_object_item_raises_with_index(self):
        with self.assertRaises(findings.FindingError) as ctx:
            findings.normalize([make(), 1])
        self.assertIn("finding #1", str(ctx.exception))

    def test_non_string_field_raises(self):
        with self.assertRaises(findings.FindingError) as ctx:
            findings.normalize([make(dimension=["SEC"])])
        self.assertIn("dimension", str(ctx.exception))

    def test_numeric_string_line_is_coerced(self):
        out = findings.normalize([make(line="14", title="A"), make(line=5, title="B", symbol="other")])
        self.assertEqual({f["title"]: f["line"] for f in out}, {"A": 14, "B": 5})

    def test_line_range_raises(self):
        with self.assertRaises(findings.FindingError) as ctx:
            findings.normalize([make(line="14-16")])
        self.assertIn("line", str(ctx.exception))

    def test_missing_symbol_raises(self):
        bad = make()
        del bad["symbol"]
        with self.assertRaises(findings.FindingError) as ctx:
            findings.normalize([bad])
        self.assertIn("symbol", str(ctx.exception))

    def test_empty_evidence_raises(self):
        with self.assertRaises(findings.FindingError) as ctx:
            findings.normalize([make(evidence=[])])
        self.assertIn("evidence", str(ctx.exception))

    def test_evidence_must_be_list_of_strings(self):
        with self.assertRaises(findings.FindingError):
            findings.normalize([make(evidence="req.params.id (a.js:1)")])

    def test_absolute_paths_are_rejected(self):
        for path in [r"C:\proj\src\a.js", "C:/proj/a.js", "/home/u/proj/a.js", r"\\server\share\a.js"]:
            with self.subTest(path):
                with self.assertRaises(findings.FindingError) as ctx:
                    findings.normalize([make(file=path)])
                self.assertIn("relative", str(ctx.exception))


class CliRobustnessTests(unittest.TestCase):
    def test_cli_malformed_item_exits_2_with_json(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / "findings.py")],
            input="[1]", capture_output=True, text=True, encoding="utf-8",
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("finding #0", json.loads(result.stdout)["error"])


if __name__ == "__main__":
    unittest.main()
