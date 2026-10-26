# ai-secure-audit

> Status: early development (v0 — not usable yet). Planned first release: v0.1, December 2026.

A free, open-source security audit kit for web apps, APIs, mobile (Flutter) apps and small self-hosted infrastructure.
It is built for developers who ship fast — including those who write code with AI — and want to check their own
systems against recognised standards before users or clients find the problems.

## How it works

The findings come from established open-source scanners, not from an AI's opinion, so the same code gives the same
result every run.

```
scripts/audit.sh <profile>      runs pinned versions of the scanners with pinned rules (no AI needed)
        |
        v
findings.json                   merged, stably sorted results from the tools
        |
        v
AI skill (optional)             picks the profile for your stack, explains each finding and how to fix it,
                                and lists what the tools cannot check (for a human to review)
```

- The AI never adds or removes findings; its explanations are kept in a separate section of the report.
- Tools and rule sets are pinned, so a rerun on the same commit produces an identical `findings.json`.
- Scanners that send traffic (DAST, port and TLS scans) only run against hosts listed in your own `config/targets.yml`.

## Planned coverage

| Layer | Tools | Standard |
|---|---|---|
| Secrets (including git history) | gitleaks | — |
| Dependencies | osv-scanner, trivy | — |
| Source code | semgrep / opengrep + custom rules | OWASP Top 10, CWE |
| Dockerfile, Compose, CI config | hadolint, trivy config, checkov | CIS Docker Benchmark |
| Container images | trivy | — |
| Linux host | lynis | CIS |
| Network and TLS | nmap, testssl.sh | Mozilla TLS guidelines |
| Running web app / API | OWASP ZAP, nuclei | OWASP ASVS, OWASP API Security Top 10 |
| Flutter mobile app | MobSF, semgrep | OWASP MASVS |

## What it does not do

- It does not certify anything. A report states which standard and level were self-assessed, on which date and commit.
- Automated tools cannot fully check business logic or whether one user can reach another user's data;
  the report lists these for manual review.

## Privacy

`scripts/audit.sh` runs locally and sends nothing anywhere. The optional AI skill sends parts of the scanned code
and findings to the AI provider you use. Get permission before running it on code you do not own.

## Use only on systems you are allowed to test

Scan your own code and systems, or systems you have written permission to test.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
