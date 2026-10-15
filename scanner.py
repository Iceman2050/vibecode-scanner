#!/usr/bin/env python3
"""vibecode-scanner — "npm audit for AI-generated code."

A standalone, stdlib-only static scanner that hunts the vulnerability
patterns AI coding assistants commonly introduce into generated code:
hardcoded secrets, injection flaws, unsafe deserialization, shell
execution, weak randomness, missing auth, path traversal, XSS sinks and
SSRF sinks.

The scanner READS code — it never executes it. Deterministic, offline,
no network, no dependencies. Never raises on garbage input: unreadable
or binary files are skipped with a warning on stderr.

Usage:
    scanner.py [path] [--json] [--fail-on critical|high|medium|low]

Exit code: 1 if any finding meets the --fail-on severity threshold,
otherwise 0.
"""
import argparse
import json
import os
import re
import sys

VERSION = "0.1.0"

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".php", ".rb", ".go", ".java", ".cs",
}
MAX_FILE_BYTES = 2 * 1024 * 1024  # skip anything bigger; never OOM


def _finding(rule_id, severity, title, path, lineno, line, detail, fix):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "file": path,
        "line": lineno,
        "code": line.strip()[:160],
        "detail": detail,
        "fix": fix,
    }


def _iter_lines(code, rx):
    for m in rx.finditer(code):
        yield code[: m.start()].count("\n") + 1, m


def _nearby(lines, lineno, radius=10):
    lo = max(0, lineno - 1 - radius)
    hi = min(len(lines), lineno + radius)
    return "\n".join(lines[lo:hi])


# ---------------------------------------------------------------- VC-001
# Hardcoded secrets — ported from vibe-audit scanner.py SECRET_PATTERNS
# (the proven high-precision subset). Each sub-pattern keeps its own name
# but all report under rule VC-001.
_SECRET_SUBPATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "CRITICAL"),
    ("GitHub token", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "CRITICAL"),
    ("Stripe secret key", re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{16,}\b"), "CRITICAL"),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"), "CRITICAL"),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9\-_]{20,}\b"), "CRITICAL"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "CRITICAL"),
    ("Database connection string",
     re.compile(r"(?i)(postgres|mysql|mongodb)(\+srv)?://[^: \n'\"<]+:[^@ \n'\"<]+@"), "HIGH"),
    ("Generic API key assignment",
     re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9\-_]{16,}['\"]"), "HIGH"),
    ("Hardcoded password",
     re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]"), "HIGH"),
    ("JWT secret assignment",
     re.compile(r"(?i)(jwt[_-]?secret|secret[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]"), "HIGH"),
]


def _d_hardcoded_secrets(code, path):
    out = []
    for name, rx, sev in _SECRET_SUBPATTERNS:
        for lineno, m in _iter_lines(code, rx):
            line = code.splitlines()[lineno - 1]
            out.append(_finding(
                "VC-001", sev, "Hardcoded secret: %s" % name, path, lineno, line,
                "A %s appears to be hardcoded in source. Anyone with repo access "
                "(including future contributors and AI training pipelines) gets the "
                "credential." % name,
                "Move the secret to an environment variable or secret manager and "
                "rotate it — assume it is already compromised. Fix prompt for your "
                "AI builder: 'Replace this hardcoded secret with an environment "
                "variable; never emit real credentials in generated code.'"))
    return out


# ---------------------------------------------------------------- VC-002
# SQL injection via string building — ported from CODE_PATTERNS.
_SQL_FSTRING_RX = re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE)\b[^;\n]*\{[^}]+\}")
_SQL_CONCAT_RX = re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE)\b[^;\n]*\+\s*\w+")


def _d_sql_injection(code, path):
    out = []
    for lineno, m in _iter_lines(code, _SQL_FSTRING_RX):
        line = code.splitlines()[lineno - 1]
        out.append(_finding(
            "VC-002", "HIGH", "SQL injection risk (interpolated query)", path, lineno, line,
            "Query text is built with interpolated values — attacker input can "
            "break out of the string and run arbitrary SQL.",
            "Use parameterized queries (placeholders) for every value. Fix prompt "
            "for your AI builder: 'Rewrite this query using parameterized "
            "placeholders for every user-supplied value.'"))
    for lineno, m in _iter_lines(code, _SQL_CONCAT_RX):
        line = code.splitlines()[lineno - 1]
        out.append(_finding(
            "VC-002", "HIGH", "SQL injection risk (concatenated query)", path, lineno, line,
            "Query text is concatenated with variables — classic SQL injection "
            "when any part is user-controlled.",
            "Use parameterized queries — never concatenate input into SQL. Fix "
            "prompt for your AI builder: 'Convert this SQL string concatenation "
            "to a parameterized query.'"))
    return out


# ---------------------------------------------------------------- VC-003
# eval/exec on dynamic input — ported from CODE_PATTERNS.
_EVAL_RX = re.compile(r"(?<![\w.])eval\s*\(")
_EXEC_RX = re.compile(r"(?<![\w.])exec\s*\(")


def _d_eval_exec(code, path):
    out = []
    for rx, name in ((_EVAL_RX, "eval"), (_EXEC_RX, "exec")):
        for lineno, m in _iter_lines(code, rx):
            line = code.splitlines()[lineno - 1]
            out.append(_finding(
                "VC-003", "HIGH", "Dynamic code execution (%s)" % name, path, lineno, line,
                "%s() executes arbitrary code — if any argument derives from "
                "user input, this is remote code execution." % name,
                "Remove %s() and use a safe alternative (JSON.parse, ast.literal_eval, "
                "a dispatch dict). Fix prompt for your AI builder: 'Remove %s() and "
                "replace with a safe alternative.'" % (name, name)))
    return out


# ---------------------------------------------------------------- VC-004
# Unsafe deserialization — ported from ADVANCED_CODE_PATTERNS.
_DESER_PATTERNS = [
    ("pickle.loads", re.compile(r"pickle\.loads\s*\("),
     "pickle.loads on untrusted data is remote code execution — pickle can run "
     "arbitrary code during deserialization.",
     "Replace pickle with JSON for untrusted data; never unpickle user input."),
    ("marshal.loads", re.compile(r"marshal\.loads\s*\("),
     "marshal.loads on untrusted data can execute arbitrary code, like pickle.",
     "Replace marshal with JSON for untrusted data."),
    ("yaml.load (unsafe)", re.compile(r"yaml\.load\s*\((?![^)\n]*(?:SafeLoader|safe_load))"),
     "yaml.load without SafeLoader can construct arbitrary Python objects — "
     "remote code execution on untrusted YAML.",
     "Use yaml.safe_load or pass Loader=yaml.SafeLoader explicitly."),
    ("PHP unserialize", re.compile(r"(?<!\w)unserialize\s*\("),
     "PHP unserialize() on user input enables object-injection attacks.",
     "Replace unserialize with json_decode, or pass allowed_classes=false."),
]


def _d_deserialization(code, path):
    out = []
    for name, rx, detail, fix in _DESER_PATTERNS:
        for lineno, m in _iter_lines(code, rx):
            line = code.splitlines()[lineno - 1]
            out.append(_finding(
                "VC-004", "HIGH", "Unsafe deserialization (%s)" % name, path, lineno, line,
                detail,
                "Fix prompt for your AI builder: '%s'" % fix))
    return out


# ---------------------------------------------------------------- VC-005
# Shell execution — ported from ADVANCED_CODE_PATTERNS.
_SHELL_PATTERNS = [
    ("os.system", re.compile(r"os\.system\s*\(\s*(f['\"]|.*\+)"), "HIGH",
     "os.system is called with a formatted/concatenated string — command "
     "injection if any part is user-controlled.",
     "Use subprocess.run with a list of arguments and shell=False."),
    ("os.system", re.compile(r"os\.system\s*\("), "MEDIUM",
     "os.system runs a shell command — audit every argument for user input.",
     "Prefer subprocess.run with an argument list and shell=False."),
    ("shell=True", re.compile(r"shell\s*=\s*True"), "MEDIUM",
     "subprocess is invoked with shell=True — if any part of the command comes "
     "from user input, this is remote code execution.",
     "Drop shell=True and pass the command as a list of arguments."),
    ("child_process.exec", re.compile(r"child_process\.(exec|execSync)\s*\("), "HIGH",
     "child_process.exec runs a shell command — RCE if any argument comes "
     "from user input.",
     "Use execFile/spawn with an argument array; never interpolate user input "
     "into shell strings."),
]


def _d_shell_exec(code, path):
    out = []
    seen = set()
    for name, rx, sev, detail, fix in _SHELL_PATTERNS:
        for lineno, m in _iter_lines(code, rx):
            if (lineno, name) in seen:
                continue
            seen.add((lineno, name))
            line = code.splitlines()[lineno - 1]
            out.append(_finding(
                "VC-005", sev, "Command injection risk (%s)" % name, path, lineno, line,
                detail,
                "Fix prompt for your AI builder: '%s'" % fix))
    return out


# ---------------------------------------------------------------- VC-006
# Insecure randomness for secrets — ported from ADVANCED_CODE_PATTERNS.
_RANDOM_PATTERNS = [
    ("Python random module",
     re.compile(r"(?i)(token|secret|password|key|nonce).{0,40}random\.(random|choice|randint)\s*\(|"
                r"random\.(random|choice|randint)\s*\(\).{0,40}(token|secret|password|key|nonce)"),
     "Python's random module is not a CSPRNG — secrets built from it are "
     "guessable.",
     "Use the secrets module (secrets.token_hex / token_urlsafe)."),
    ("Math.random",
     re.compile(r"(?i)(token|secret|password|key|nonce).{0,40}Math\.random\s*\(\)|"
                r"Math\.random\s*\(\).{0,40}(token|secret|password|key|nonce)"),
     "Math.random() is not cryptographically secure — tokens built from it "
     "are predictable.",
     "Use crypto.getRandomValues / crypto.randomUUID for tokens and secrets."),
]


def _d_weak_random(code, path):
    out = []
    for name, rx, detail, fix in _RANDOM_PATTERNS:
        for lineno, m in _iter_lines(code, rx):
            line = code.splitlines()[lineno - 1]
            out.append(_finding(
                "VC-006", "MEDIUM", "Weak randomness for secrets (%s)" % name,
                path, lineno, line, detail,
                "Fix prompt for your AI builder: '%s'" % fix))
    return out


# ---------------------------------------------------------------- VC-007
# Missing auth on routes (heuristic) — AI builders routinely scaffold routes
# without auth and leave "TODO: add auth" comments.
_ROUTE_RX = re.compile(
    r"@app\.(route|get|post|put|delete|patch)\s*\(|"
    r"(?<![\w.])app\.(get|post|put|delete|use)\s*\(|"
    r"router\.(get|post|put|delete)\s*\(")
_AUTH_HINT_RX = re.compile(
    r"(?i)(login_required|jwt_required|token_required|authenticate|@auth|"
    r"permission|authorize|is_admin|current_user|verify_token|middleware)")
_TODO_AUTH_RX = re.compile(r"(?i)(#|//)\s*(TODO|FIXME)[:\s].{0,40}\bauth")


def _d_missing_auth(code, path):
    out = []
    lines = code.splitlines()
    for lineno, m in _iter_lines(code, _ROUTE_RX):
        ctx = _nearby(lines, lineno, 10)
        if _AUTH_HINT_RX.search(ctx):
            continue
        line = lines[lineno - 1]
        out.append(_finding(
            "VC-007", "MEDIUM", "Route without visible auth check (heuristic)",
            path, lineno, line,
            "This route has no authentication/authorization decorator or check "
            "in its vicinity. AI scaffolding often ships routes open by "
            "default. (Heuristic — verify manually.)",
            "Add an auth decorator/guard (login_required, JWT check, API-key "
            "middleware) and test the route unauthenticated. Fix prompt for "
            "your AI builder: 'Add authentication and authorization checks to "
            "every route; fail closed.'"))
    for lineno, m in _iter_lines(code, _TODO_AUTH_RX):
        line = lines[lineno - 1]
        out.append(_finding(
            "VC-007", "MEDIUM", "Deferred auth (TODO comment)", path, lineno, line,
            "An auth check is explicitly deferred in a comment — shipped TODOs "
            "become open endpoints.",
            "Implement the authentication check before shipping. Fix prompt for "
            "your AI builder: 'Implement the missing authentication check now, "
            "not as a TODO.'"))
    return out


# ---------------------------------------------------------------- VC-008
# Path traversal via unsanitized path building — ported from ADVANCED_CODE_PATTERNS.
_PATH_TRAV_RX = re.compile(
    r"(?i)(open|send_file|createReadStream|readFile|readFileSync)\s*\([^)]*(\+|f['\"]|%s|\.format\()")


def _d_path_traversal(code, path):
    out = []
    for lineno, m in _iter_lines(code, _PATH_TRAV_RX):
        line = code.splitlines()[lineno - 1]
        out.append(_finding(
            "VC-008", "HIGH", "Path traversal risk (file op with built path)",
            path, lineno, line,
            "A file is opened with a path built from concatenation/interpolation "
            "— path traversal can read arbitrary files (e.g. ../../etc/passwd).",
            "Resolve the path against a base directory and reject anything "
            "escaping it; prefer an allow-list of filenames. Fix prompt for "
            "your AI builder: 'Normalize the path and assert it stays inside "
            "the allowed base directory.'"))
    return out


# ---------------------------------------------------------------- VC-009
# XSS via unescaped template interpolation — ported from CODE_PATTERNS +
# ADVANCED_CODE_PATTERNS.
_XSS_PATTERNS = [
    (".innerHTML assignment", re.compile(r"\.innerHTML\s*="), "HIGH",
     "innerHTML with dynamic content enables cross-site scripting.",
     "Use textContent or sanitize with DOMPurify before rendering."),
    ("dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML"), "HIGH",
     "React dangerouslySetInnerHTML renders raw HTML.",
     "Sanitize with DOMPurify first, or refactor to safe JSX."),
    ("document.write", re.compile(r"document\.write\s*\("), "MEDIUM",
     "document.write can inject untrusted markup.",
     "Replace with createElement/textContent."),
    ("template renders request data", re.compile(r"\{\{\s*(request\.|params\.|args\.)"), "HIGH",
     "A template directly renders request data with {{ }} — if autoescaping "
     "is off, this is SSTI/XSS.",
     "Ensure autoescaping is on and never render raw request data."),
    ("render_template_string", re.compile(r"render_template_string\s*\("), "HIGH",
     "render_template_string renders a template built from a string — SSTI "
     "if any part comes from user input.",
     "Use render_template with a static template file."),
]


def _d_xss(code, path):
    out = []
    for name, rx, sev, detail, fix in _XSS_PATTERNS:
        for lineno, m in _iter_lines(code, rx):
            line = code.splitlines()[lineno - 1]
            out.append(_finding(
                "VC-009", sev, "XSS risk (%s)" % name, path, lineno, line,
                detail,
                "Fix prompt for your AI builder: '%s'" % fix))
    return out


# ---------------------------------------------------------------- VC-010
# SSRF via unvalidated URL fetch — ported from ADVANCED_CODE_PATTERNS.
_SSRF_PATTERNS = [
    ("requests with user input",
     re.compile(r"(?i)(requests|httpx)\.(get|post|put|delete|request)\s*\(\s*(f['\"]|request\.|req\.|user_|params)"),
     "The server fetches a URL built from user input — server-side request "
     "forgery: attackers can reach internal services and cloud metadata "
     "(169.254.169.254).",
     "Validate the URL against an allow-list of hosts/schemes and block "
     "private IP ranges before fetching."),
    ("fetch with user input",
     re.compile(r"(?<![\w.])fetch\s*\(\s*(req\.|request\.|params\.|input|url)"),
     "fetch() is called with a user-controlled value — SSRF.",
     "Allow-list the fetch target and reject private IPs."),
]


def _d_ssrf(code, path):
    out = []
    for name, rx, detail, fix in _SSRF_PATTERNS:
        for lineno, m in _iter_lines(code, rx):
            line = code.splitlines()[lineno - 1]
            out.append(_finding(
                "VC-010", "HIGH", "SSRF risk (%s)" % name, path, lineno, line,
                detail,
                "Fix prompt for your AI builder: '%s'" % fix))
    return out


DETECTORS = [
    _d_hardcoded_secrets,
    _d_sql_injection,
    _d_eval_exec,
    _d_deserialization,
    _d_shell_exec,
    _d_weak_random,
    _d_missing_auth,
    _d_path_traversal,
    _d_xss,
    _d_ssrf,
]


def scan_code(code, path):
    """Scan one code string. Never raises — a detector failure yields no
    findings from that detector rather than crashing the run."""
    findings = []
    for detector in DETECTORS:
        try:
            findings.extend(detector(code, path))
        except Exception:
            continue
    findings.sort(key=lambda f: (f["line"], f["rule_id"]))
    return findings


def _read_file(path):
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size > MAX_FILE_BYTES:
        print("warning: skipping oversized file %s" % path, file=sys.stderr)
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def iter_target_files(target):
    if os.path.isfile(target):
        yield target
        return
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs
                   if d not in (".git", "node_modules", "__pycache__", ".venv",
                                "venv", "dist", "build", ".tox")]
        for name in sorted(files):
            _, ext = os.path.splitext(name)
            if ext.lower() in SCAN_EXTENSIONS:
                yield os.path.join(root, name)


def scan_target(target):
    findings = []
    files_scanned = 0
    for path in iter_target_files(target):
        code = _read_file(path)
        if code is None:
            continue
        files_scanned += 1
        findings.extend(scan_code(code, path))
    return files_scanned, findings


def _render_text(files_scanned, findings):
    lines = ["vibecode-scanner v%s — %d file(s) scanned, %d finding(s)"
             % (VERSION, files_scanned, len(findings)), ""]
    if not findings:
        lines.append("No findings. (Heuristics only — not a substitute for review.)")
        return "\n".join(lines)
    by_file = {}
    for f in findings:
        by_file.setdefault(f["file"], []).append(f)
    for path in sorted(by_file):
        lines.append("== %s" % path)
        for f in by_file[path]:
            lines.append("  %s:%d  [%s %s]  %s"
                         % (f["file"], f["line"], f["rule_id"], f["severity"], f["title"]))
            lines.append("      detail: %s" % f["detail"])
            lines.append("      fix: %s" % f["fix"])
        lines.append("")
    return "\n".join(lines).rstrip()


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="scanner.py",
        description="vibecode-scanner: find the vulnerabilities AI coding "
                    "assistants leave behind. Reads code, never executes it.")
    ap.add_argument("path", nargs="?", default=".",
                    help="file or directory to scan (default: current dir)")
    ap.add_argument("--json", action="store_true",
                    help="emit machine-readable JSON")
    ap.add_argument("--fail-on",
                    choices=["critical", "high", "medium", "low"],
                    default=None,
                    help="exit 1 if any finding meets this severity or higher")
    ap.add_argument("--version", action="version", version="vibecode-scanner " + VERSION)
    args = ap.parse_args(argv)

    target = args.path
    if not os.path.exists(target):
        print("error: path does not exist: %s" % target, file=sys.stderr)
        return 2

    files_scanned, findings = scan_target(target)

    if args.json:
        summary = {}
        for f in findings:
            summary[f["severity"]] = summary.get(f["severity"], 0) + 1
        print(json.dumps({
            "scanner": "vibecode-scanner",
            "version": VERSION,
            "files_scanned": files_scanned,
            "summary": summary,
            "findings": findings,
        }, indent=2))
    else:
        print(_render_text(files_scanned, findings))

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on.upper()]
        for f in findings:
            if SEVERITY_ORDER[f["severity"]] >= threshold:
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
