"""Tests for vibecode-scanner. Fixtures only — no live network."""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER = os.path.join(ROOT, "scanner.py")
FIX = os.path.join(ROOT, "tests", "fixtures")

sys.path.insert(0, ROOT)
import scanner as mod


def _scan(*names):
    findings = []
    for n in names:
        path = os.path.join(FIX, n)
        with open(path, encoding="utf-8") as fh:
            findings.extend(mod.scan_code(fh.read(), path))
    return findings


def _rule_ids(findings):
    return {f["rule_id"] for f in findings}


def test_vulnerable_fires_at_least_8_distinct_rules():
    findings = _scan("vulnerable.py", "vulnerable.js")
    assert len(_rule_ids(findings)) >= 8, \
        "expected >=8 distinct rules, got %s" % sorted(_rule_ids(findings))


def test_vulnerable_covers_expected_rules():
    ids = _rule_ids(_scan("vulnerable.py", "vulnerable.js"))
    for rid in ("VC-001", "VC-002", "VC-003", "VC-004", "VC-005",
                "VC-006", "VC-007", "VC-008", "VC-009", "VC-010"):
        assert rid in ids, "missing rule %s" % rid


def test_clean_fixtures_zero_findings():
    assert _scan("clean.py", "clean.js") == []


def test_findings_have_required_shape():
    findings = _scan("vulnerable.py")
    assert findings
    for f in findings:
        for key in ("rule_id", "severity", "title", "file", "line",
                    "detail", "fix"):
            assert key in f, "finding missing %s" % key
        assert f["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert f["rule_id"].startswith("VC-")


def test_garbage_input_never_raises():
    assert mod.scan_code("", "empty.py") == []
    assert mod.scan_code("\x00\x01\x02 binary \xff\xfe junk", "bin.py") == []
    assert mod.scan_code(")))) {{{ not code at all", "junk.py") == []


def test_cli_json_parses(tmp_path):
    out = subprocess.run(
        [sys.executable, SCANNER, FIX, "--json"],
        capture_output=True, text=True, check=False)
    assert out.returncode in (0, 1)
    data = json.loads(out.stdout)
    assert data["files_scanned"] >= 4
    assert isinstance(data["findings"], list)


def test_cli_fail_on_critical(tmp_path):
    vuln = subprocess.run(
        [sys.executable, SCANNER,
         os.path.join(FIX, "vulnerable.py"), "--fail-on", "critical"],
        capture_output=True, text=True, check=False)
    assert vuln.returncode == 1  # VC-001 CRITICAL present
    clean = subprocess.run(
        [sys.executable, SCANNER,
         os.path.join(FIX, "clean.py"), "--fail-on", "critical"],
        capture_output=True, text=True, check=False)
    assert clean.returncode == 0


def test_cli_missing_path_is_usage_error():
    out = subprocess.run(
        [sys.executable, SCANNER, "/does/not/exist"],
        capture_output=True, text=True, check=False)
    assert out.returncode == 2
