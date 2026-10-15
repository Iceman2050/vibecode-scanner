[![AI Security Score](https://ingeniousai-security-checks.netlify.app/badges/vibecode-scanner.svg)](https://ingeniousai-security-checks.netlify.app/ai-security-badge.html)

# vibecode-scanner

**"npm audit for AI-generated code."**

AI writes code fast. It also writes vulnerabilities fast — hardcoded API keys,
SQL built with f-strings, `eval()` on request input, `pickle.loads()` on
uploads, `os.system()` with concatenation, tokens from `random.choice()`,
routes with no auth, `innerHTML` sinks, server-side fetches of user URLs.
These are the patterns AI coding assistants reproduce most often, because
they learned them from the same Stack Overflow answers we all did.

vibecode-scanner hunts exactly those patterns. Point it at a repo, get
per-file/per-line findings with rule IDs, severities, and a one-line fix —
plus a "fix prompt" you can paste straight back into your AI builder.

- **Zero dependencies** — stdlib only, works on any Python 3.8+
- **Offline** — never touches the network
- **Read-only** — the scanner READS code; it never executes it
- **Deterministic** — same code, same findings, every run
- **Never crashes** — garbage input is skipped, not fatal

Built by [Ingenious AI](https://vibe-audit-efkm.onrender.com). The rule
engine ports proven detectors from our production scanner
[Vibe-Code Audit](https://vibe-audit-efkm.onrender.com).

## Install

```bash
git clone https://github.com/YOUR-USER/vibecode-scanner.git
cd vibecode-scanner
# no install step — it's one file
```

## Usage

```bash
# scan a directory
python3 scanner.py ./my-project

# scan one file, machine-readable output
python3 scanner.py app.py --json

# fail CI when a CRITICAL finding appears
python3 scanner.py ./src --fail-on critical
```

Example output:

```
vibecode-scanner v0.1.0 — 12 file(s) scanned, 3 finding(s)

== ./app.py
  ./app.py:14  [VC-001 CRITICAL]  Hardcoded secret: OpenAI API key
      detail: A OpenAI API key appears to be hardcoded in source. ...
      fix: Move the secret to an environment variable or secret manager ...
```

## Rules

| Rule | Severity | What it catches |
|------|----------|-----------------|
| VC-001 | CRITICAL/HIGH | Hardcoded secrets: AWS keys, GitHub/Stripe/OpenAI/Anthropic tokens, private keys, DB connection strings, passwords, JWT secrets |
| VC-002 | HIGH | SQL injection via f-string/format/concatenation |
| VC-003 | HIGH | `eval()` / `exec()` on dynamic input |
| VC-004 | HIGH | Unsafe deserialization: `pickle.loads`, `marshal.loads`, unsafe `yaml.load`, PHP `unserialize` |
| VC-005 | HIGH/MEDIUM | Command injection: `os.system` with formatting, `shell=True`, `child_process.exec` |
| VC-006 | MEDIUM | Weak randomness for secrets (`random.*`, `Math.random` near token/secret/key) |
| VC-007 | MEDIUM | Route without a visible auth check (heuristic) + deferred-auth TODO comments |
| VC-008 | HIGH | Path traversal via concatenated/interpolated file paths |
| VC-009 | HIGH/MEDIUM | XSS sinks: `innerHTML`, `dangerouslySetInnerHTML`, `document.write`, unescaped template interpolation, `render_template_string` |
| VC-010 | HIGH | SSRF: server-side fetches built from user input |

Each finding includes a **fix prompt** — a sentence you can paste into
ChatGPT/Claude/Copilot to get the vulnerability fixed correctly.

## Honest limitations

- These are **heuristics, not proofs**. VC-007 (missing auth) is explicitly
  a heuristic — always verify manually.
- A clean scan does **not** mean secure code. This is a first pass, not a
  replacement for code review or a penetration test.
- Regex-based: heavily obfuscated or metaprogrammed code can slip past.
- Secrets detection favors precision on known token shapes; novel formats
  may be missed.

## Contributing

PRs welcome — especially new high-precision detectors with a vulnerable
fixture and a clean fixture (see `tests/fixtures/`). Every detector must
fire on the vulnerable fixture and stay silent on the clean one.

## License

MIT — see [LICENSE](LICENSE).
