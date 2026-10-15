# Push instructions — your one tap

The repo is fully built and tested locally. Creating the GitHub repo is an
account action, so it's yours:

## Option A — GitHub CLI (one command)

```bash
cd ~/workspace/oss/vibecode-scanner
gh repo create vibecode-scanner --public --source=. --remote=origin \
  --description="npm audit for AI-generated code — finds the vulnerabilities AI coding assistants leave behind"
git add -A
git commit -m "vibecode-scanner 0.1.0 — 10 detectors, stdlib only"
git push -u origin main
```

## Option B — web UI

1. Go to https://github.com/new — name it `vibecode-scanner`, public,
   no README (we have one).
2. Then:
```bash
cd ~/workspace/oss/vibecode-scanner
git init -b main
git add -A
git commit -m "vibecode-scanner 0.1.0 — 10 detectors, stdlib only"
git remote add origin https://github.com/YOUR-USER/vibecode-scanner.git
git push -u origin main
```

## After pushing — replace YOUR-USER in README.md

The README links `https://github.com/YOUR-USER/vibecode-scanner.git`.
Update it to your real username, commit, push.

## Then fire the traffic taps (in order)

1. **Show HN** — "Show HN: vibecode-scanner — npm audit for AI-generated code"
   (morning US time; pre-flight the HN rules first).
2. **r/SideProject + r/homelab** — Tuesday/Wednesday, launch-style post.
3. **dev.to** — "I scanned 10 AI-generated repos, here's what I found"
   (only publish real numbers you actually measured).
4. **TLDR / Changelog News** — submit the repo link.
5. **awesome lists** — PR to awesome-security / awesome-python-security
   style lists (read their CONTRIBUTING first).
