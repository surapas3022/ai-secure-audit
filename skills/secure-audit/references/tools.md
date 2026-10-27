# Tools

Licenses checked on GitHub on 2026-10-27. Check the LICENSE file again for the exact version before pinning it in
`profiles/`.

## How a tool gets in

1. **Open source under an OSI-approved license**, and allowed to be downloaded or bundled by the kit.
2. **Basic tier only:** a single binary for Windows, macOS and Linux. No Docker, Homebrew, Python or Java.
3. **Basic tier only:** reads local files only and sends no traffic.
4. Pinned by version and checksum, so the same commit gives the same `findings.json`.

## Basic tier: default for everyone

| Tool | License | Phase | Note |
|---|---|---|---|
| gitleaks | MIT | 2, 4 | scan git history too; a deleted secret is still exposed |
| osv-scanner | Apache-2.0 | 2, 4 | reads lockfiles; offline databases, so the dependency list is never sent to osv.dev |
| trivy `config` | Apache-2.0 | 4 | Dockerfile/IaC misconfiguration; dependencies are left to osv-scanner to avoid duplicates |
| opengrep (planned) | LGPL-2.1 | 4, 5 | uses only this kit's rules in `rules/`, never Semgrep Registry rules |

## Advanced tier: developers, needs Docker or a Linux host

| Tool | License | Phase | Where it may run |
|---|---|---|---|
| hadolint | GPL-3.0 | 4 | offline |
| checkov or KICS | Apache-2.0 | 4 | offline |
| syft | Apache-2.0 | 2 | offline (SBOM) |
| trivy `image` | Apache-2.0 | 4 | offline |
| lynis, docker-bench-security | GPL-3.0, Apache-2.0 | 4 | on the user's own server |
| testssl.sh | GPL-2.0 | 4 | targets in `.audit/targets.yml`; default options on prod |
| naabu | MIT | 2 | targets only; slow rate on prod |
| OWASP ZAP | Apache-2.0 | 4, 5 | baseline or API scan `-S` on prod; full scan on dev only |
| nuclei | MIT | 4 | targets only; dev unless the template set is passive |
| schemathesis | MIT | 5 | dev only (sends many requests) |
| MobSF | GPL-3.0 | 4 | offline static analysis |

Phase 5 cross-user tests use the project's own test framework (vitest, jest, pytest…). No extra tool needed.

## Not used

| Tool | Reason |
|---|---|
| Semgrep Registry rules | Semgrep Rules License v1.0, not open source |
| nmap | Nmap Public Source License, not OSI-approved, limits bundling. Users may run their own copy; the kit does not ship it |
| CodeQL | CLI not open source; free only for open-source code |
| trufflehog `--verify` | sends found keys to the provider's API to test them; gitleaks is enough |
