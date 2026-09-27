#!/usr/bin/env bash
# Build the encrypted public build and deploy it to GitHub Pages.
# The passphrase never leaves /home/oioi/Work/zts/.publish-passphrase (mode 0600).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

REPO="${ZTS_PUBLISH_REPO:-OIuch/fleet-map}"
BRANCH="${ZTS_PUBLISH_BRANCH:-main}"

fail() { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

command -v node  >/dev/null || fail "node not found"
command -v git  >/dev/null || fail "git not found"
command -v gh   >/dev/null || fail "gh not found"

[ -f ../zts-map.html ]      || fail "missing ../zts-map.html (run fetch-zts.js first)"
[ -f ../.publish-passphrase ] || fail "missing ../.publish-passphrase"

mode="$(stat -c '%a' ../.publish-passphrase)"
[ "$mode" = "600" ] || { chmod 600 ../.publish-passphrase; printf 'tightened passphrase mode to 0600\n'; }

printf '\n[1/4] building encrypted artifacts\n'
node build-lock.js

printf '\n[2/4] verifying no plaintext leaks\n'
node -e '
const fs = require("fs");
const h = fs.readFileSync("zts-map.html", "utf8");
const m = h.match(/const ZTS_BLOB = "([A-Za-z0-9+/=]+)";/);
if (!m) { console.error("no ciphertext blob found"); process.exit(1); }
const s = h.indexOf("\"" + m[1] + "\"") + 1, e = s + m[1].length;
const leaks = [];
const add = (re, label) => {
  const r = new RegExp(re.source, "g"); let x;
  while ((x = r.exec(h)) !== null) {
    if (!(x.index >= s && x.index + x[0].length <= e)) leaks.push(label + ": " + x[0]);
  }
};
if (/const DATA = \{/.test(h)) leaks.push("plaintext DATA literal");
if (!/function boot\(/.test(h)) leaks.push("missing boot() wrapper");
if (!/id="lock"/.test(h)) leaks.push("missing lock screen");
add(/drogomir|arcelormittal/i, "upstream host");
add(/GPS[1-9][0-9]{5}/, "GPS token");
add(/cookie|Authorization/i, "credential keyword");
if (leaks.length) { console.error("LEAKS:\n  " + leaks.join("\n  ")); process.exit(1); }
console.log("clean: " + m[1].length + " ciphertext chars, all fleet data encrypted");
'

printf '\n[3/4] committing %s\n' "$REPO"
git rev-parse --git-dir >/dev/null 2>&1 || fail "publish/ is not a git repo (init and set remote first)"
git add -- index.html zts-map.html build-lock.js publish.sh .gitignore
git -c core.hooksPath=/dev/null commit -q -m "chore: encrypted ZTS map build ($(date -u +%Y-%m-%dT%H:%MZ))" --allow-empty

printf '\n[4/4] pushing to %s (%s)\n' "$REPO" "$BRANCH"
git push -q origin "HEAD:$BRANCH"

printf '\nDeployed: https://%s.io/\n' "$(gh repo view "$REPO" --json homepage -q .homepage 2>/dev/null || echo "OIuch.github.io")"
printf 'Passphrase: stored locally at ../.publish-passphrase (not printed, not committed)\n'
