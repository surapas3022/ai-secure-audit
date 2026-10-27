# Audit scope and rules of engagement

> Copy to `<project>/.audit/scope.md`. Everything marked `TODO(confirm)` needs the owner's approval.

| Field | Value |
|---|---|
| Project | |
| Repository / commit | |
| Date | |
| Owner (approves this file) | |
| Standard and level | e.g. OWASP ASVS 5.0.0 L1 · MASVS v2.1.0 MAS-L1 |
| Results stored at | e.g. a private repo `reports/<project>/<date>.md`, never this repo |

## In scope

- Code: (paths)
- Environments and targets: see `.audit/targets.yml`

## Out of scope

- Third-party services (payment, push, external APIs): never scanned
- (anything else)

## Allowed techniques

| Environment | Allowed |
|---|---|
| local / dev | everything in the chosen profile, including active scans |
| prod | passive only: see `secure-audit/references/live-safety.md` |

## Stop conditions

- API error rate or latency rises noticeably → stop and wait
- Any sign that data has already leaked → stop and tell the owner at once
- (others)

## Contacts

- Who runs the test:
- Who to call if something breaks:

## Data handling

- Personal data and secrets are redacted from reports and screenshots.
- Raw scanner output stays on the local machine and is deleted after the report is written (or: kept at ...).

Approved by: ______________________  Date: __________
