# axios Supply-Chain Attack — Scanner & Remediation

**Incident date:** 2026-03-30
**Severity:** Critical — Remote Access Trojan (RAT) dropper

## What happened

The npm account of axios's primary maintainer (`jasonsaayman`) was hijacked using a stolen long-lived npm access token. The attacker published two malicious axios versions to npm that inject a new dependency — `plain-crypto-js@4.2.1` — whose sole purpose is to execute a `postinstall` hook that drops a cross-platform RAT on macOS, Windows, and Linux.

Because the token bypassed GitHub entirely, no CI/CD pipelines, branch protections, or code review gates were triggered.

## Affected versions

| Package           | Affected | Safe downgrade  |
| ----------------- | -------- | --------------- |
| `axios`           | `1.14.1` | `1.14.0`        |
| `axios`           | `0.30.4` | `0.30.3`        |
| `plain-crypto-js` | `4.2.1`  | Remove entirely |

## Indicators of Compromise (IOC)

| Indicator                                 | Type         | Notes                                         |
| ----------------------------------------- | ------------ | --------------------------------------------- |
| `plain-crypto-js@4.2.1` in `node_modules` | File         | RAT dropper — never a legitimate dependency   |
| `/tmp/ld.py`                              | File (Linux) | On-disk artifact left by executed RAT dropper |
| `sfrclak[.]com:8000`                      | C2 domain    | Command-and-control server                    |
| `142.11.206.73`                           | C2 IP        | Block outbound immediately if found           |

## Quick manual check

```bash
# Check if an affected axios version is installed
npm list axios 2>/dev/null | grep -E "axios@(1\.14\.1|0\.30\.4)$"

# Check for the malicious dependency
ls node_modules/plain-crypto-js 2>/dev/null && echo "POTENTIALLY AFFECTED"

# Linux only — check for RAT artifact
ls -la /tmp/ld.py 2>/dev/null && echo "COMPROMISED"
```

## Automated scanning

This repo contains two scanner scripts that walk every Node.js project under `$HOME`, check for affected versions, auto-inject `overrides.axios`, and print step-by-step remediation instructions.

### macOS / Linux

```bash
./axios-scan.sh
```

Requires: `bash`, `npm`, `jq` (optional but strongly recommended — without it, declared-version detection for projects without `node_modules` falls back to regex parsing which may miss non-standard dependency fields, and `overrides` auto-injection is disabled entirely).

### Windows (PowerShell)

```powershell
# Run as Administrator for automatic firewall blocking
pwsh -ExecutionPolicy Bypass -File .\axios-scan.ps1
```

### Dependencies

1. `jq`:
   1. macOS: Install via `brew install jq`
   2. Windows: Install via `winget install --id=jqlang.jq -e`

### What the scripts do

1. Check for active TCP connections to the C2 IP (`142.11.206.73`)
2. Check for `/tmp/ld.py` on Linux (RAT artifact)
3. Recursively find all `package.json` files under `$HOME` (excluding `node_modules`)
4. For each project: detect affected axios via `npm list` and/or direct `node_modules` inspection
5. Check for `plain-crypto-js` in `node_modules`
6. For each affected project: print mitigation steps and inject `overrides.axios` into `package.json` (requires `jq`); on Windows only (PowerShell script, requires Administrator): auto-block the C2 IP via Windows Firewall

## Manual remediation

For each affected project:

```bash
# 1. Downgrade to safe version
npm install axios@1.14.0        # or 0.30.3 for the 0.x branch

# 2. Remove the malicious package
rm -rf node_modules/plain-crypto-js

# 3. Reinstall without running postinstall hooks
npm install --ignore-scripts
```

Pin axios to prevent transitive re-pull. Add to `package.json`:

```json
"overrides": {
  "axios": "1.14.0"
}
```

## If you were affected — rotate credentials immediately

Any system that installed `axios@1.14.1` or `axios@0.30.4` should be treated as fully compromised. Rotate **all** of the following without delay:

- SSH keys (`~/.ssh/`) — revoke and regenerate
- Git tokens — GitHub / GitLab / Bitbucket PATs
- npm tokens — `.npmrc`, Artifactory, Nexus
- Cloud credentials — AWS IAM keys, Azure service principals, GCP service accounts
- Database passwords — Postgres, MySQL, MongoDB, Redis, etc.
- CI/CD secrets — GitHub Actions, GitLab CI variables, Azure DevOps variable groups
- `.env` files — all API keys, secrets, and connection strings
- Container registry credentials — Docker Hub, GitHub Container Registry, etc.
- Anything in shell history (`~/.bash_history`, `~/.zsh_history`, PowerShell history)

Block the C2 domain and IP at your firewall/DNS level:

```text
sfrclak.com        → block outbound DNS + HTTP/HTTPS
142.11.206.73      → block all outbound traffic
```

## References

- [The Hacker News — Axios Supply Chain Attack](https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html)
- [StepSecurity — axios Compromised on npm](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)
- [Snyk — axios npm Package Compromised](https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/)
- [Wiz Blog — axios npm Compromised](https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack)
- [Socket.dev — axios package compromised](https://socket.dev/blog/axios-npm-package-compromised)
- [aikido.dev — axios npm compromised, maintainer hijacked](https://www.aikido.dev/blog/axios-npm-compromised-maintainer-hijacked-rat)
- [github.com - axios PR for compromised packages](https://github.com/axios/axios/issues/10604)
- [Windows Report - Axios Hack Bypasses GitHub Protections](https://windowsreport.com/axios-hack-bypasses-github-protections-and-installs-hidden-malware-on-systems/)
