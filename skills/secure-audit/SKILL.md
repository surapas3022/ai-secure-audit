---
name: secure-audit
description: >-
  Runs a security audit of the user's own codebase or self-hosted system phase
  by phase (scope and rules of engagement, discovery, threat model, automated
  scan, manual review, triage, report, retest) and hands each phase to the
  matching skill. Use when the user asks to audit or security-check their app,
  API, Flutter app or Docker Compose deployment, asks whether their app is
  secure, or wants to retest after fixing findings.
---

# Secure audit

Coordinates one audit from scope to retest. It does not decide findings; each phase has its own skill or reference.

## Before anything

1. **Scope.** Look for `.audit/scope.md` in the audited project. If it is missing, draft it from
   [assets/scope.template.md](assets/scope.template.md) by reading the repo (services, routes, compose files, where it
   is deployed). Mark every guess `TODO(confirm)` and stop until the user approves the scope.
2. **Targets.** Read `.audit/targets.yml` (format: [config/targets.example.yml](../../config/targets.example.yml)).
   A host that is not listed is never contacted. If the file is missing, only offline checks are allowed.
3. **Production.** If any target has `env: prod`, read [references/live-safety.md](references/live-safety.md) and go
   through its checklist with the user before sending any traffic.

## Phases

| # | Phase | AI does | Person does | Go to |
|---|---|---|---|---|
| 1 | Scope / ROE | Drafts scope and ROE from the repo | Approves; decides whether prod may be touched | [assets/scope.template.md](assets/scope.template.md) |
| 2 | Discovery | Lists routes, dependencies, services, ports and where secrets live → `.audit/inventory.md` | Adds assets outside the repo (DNS, buckets, old servers) | [references/phases.md](references/phases.md) |
| 3 | Threat model | Drafts DFD and STRIDE threats | Confirms the DFD matches reality; adds business threats | [threat-model](../threat-model/SKILL.md) |
| 4 | Automated scan | Runs `npx ai-secure-audit scan` | Nothing, as long as versions are pinned | [compose-hardening](../compose-hardening/SKILL.md) for compose |
| 5 | Manual review | Finds candidates in risk order; writes cross-user tests | Judges business logic | [references/phases.md](references/phases.md), [authz-review](../authz-review/SKILL.md) |
| 6 | Triage | Dedupes, checks each finding against the code, proposes severity | Confirms or rejects; adjusts severity | [finding-triage](../finding-triage/SKILL.md) |
| 7 | Report | Drafts the report | Reviews and signs | [audit-report](../audit-report/SKILL.md) |
| 8 | Fix + retest | Writes fixes as separate commits; reruns the same checks on the fixed commit | Reviews and merges fixes | [references/phases.md](references/phases.md) |

Which tools run depends on the tier in [references/tools.md](references/tools.md). The **basic** tier is the default
and the only tier for users who are not developers: it is offline, needs no Docker, and runs on Windows, macOS and
Linux. Use the **advanced** tier only when the user asks for it and the scope allows it.

Run the basic check with `npx ai-secure-audit` (until it is on npm: `node <kit>/bin/ai-secure-audit.js <project>`).
It writes `.audit/out/findings.json` and `.audit/out/report.md`.

## Hard rules

- Never contact a host outside `.audit/targets.yml`, or anything in its `exclude:` list.
- On `env: prod`: no active scan, fuzzing, brute force, authenticated crawl, or load test.
- Run scanners through the CLI and `profiles/`; do not make up scanner flags.
- Every finding has evidence ([finding-triage](../finding-triage/SKILL.md)). No evidence, no finding.
- Redact personal data, tokens and secrets before anything goes into a report or leaves the machine.
- Write results only to the location named in `scope.md`.
- If you see signs that data has **already leaked** (not only that a weakness exists), stop and tell the user at once.
  Breach notification deadlines may have started (for example, 72 hours under Thailand's PDPA section 37(4)).

## Done when

- [ ] `scope.md` approved, with date and commit
- [ ] every phase is either done or listed in the report as not done
- [ ] every finding has evidence and a status (Open, Fixed, Retested, Accepted, False positive)
- [ ] the report states what automation could not check ([references/claim-wording.md](references/claim-wording.md))
