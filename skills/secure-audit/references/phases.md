# Phases in detail

The eight phases combine NIST SP 800-115 (Planning → Discovery → Attack → Reporting) with OWASP WSTG's testing across
the SDLC. Neither standard uses exactly these eight steps.

## 1. Scope / rules of engagement

Output: `.audit/scope.md`. NIST SP 800-115 §6.5 says every assessment needs a plan "regardless of the scope, level of
intrusiveness, or party performing the test", including audits of your own system. The plan answers: what is in
scope, who may test, when, how sensitive data is handled, and what happens if something breaks.

## 2. Discovery

Output: `.audit/inventory.md` with:

- entry points: HTTP routes (method, path, auth required?), webhooks, queues, cron jobs, mobile deep links
- dependencies: lockfiles found and which tool scans each
- services: compose services, published ports, networks, images
- secrets: where configuration is read from (`.env`, secret files, CI variables); never copy the values
- outside the repo: domains, buckets, third-party APIs (third parties are never scanned)

## 4. Automated scan

The profile decides which tools run. The tools and rule sets are pinned, so rerunning on the same commit produces the
same `findings.json`. Scanners have high false-positive rates (NIST SP 800-115 §4); phase 6 deals with that.

## 5. Manual review, in risk order

Start with what does the most damage if it breaks. This order is a choice, not a standard.

| # | Area | Look at | Standard |
|---|---|---|---|
| 1 | Authentication | login, password reset, MFA, rate limits, password hashing | ASVS 5.0 V6, API2:2023 |
| 2 | Session / token | token lifetime, rotation, revoke on logout, JWT alg check, cookie flags, where mobile stores tokens | ASVS V7, V9, V10; MASVS-STORAGE, MASVS-AUTH |
| 3 | Authorization | object ownership (BOLA/IDOR), function-level guards, property-level (mass assignment) | ASVS V8; API1, API3, API5; CWE-639, CWE-862 → [authz-review](../../authz-review/SKILL.md) |
| 4 | Input / injection | SQL/NoSQL/command injection, XSS (`v-html`, `dangerouslySetInnerHTML`), SSRF | ASVS V1; A05:2025; API7 |
| 5 | Business logic | skipping steps, reusing coupons, race conditions on balances | ASVS V2; API6; WSTG BUSL |
| 6 | Data protection / crypto | sensitive data in logs or responses, key management, TLS | ASVS V11, V12, V14 |
| 7 | Configuration | CORS, security headers, debug mode, secrets in images, published ports | ASVS V13; A02:2025; API8 → [compose-hardening](../../compose-hardening/SKILL.md) |
| 8 | Integrations | webhook signature and replay, file upload, outbound API calls | ASVS V4, V5; API10 |
| 9 | LLM features | prompt injection, model output that gets executed, over-privileged agents, no spending cap | OWASP Top 10 for LLM 2025 |

Automation cannot settle areas 3 and 5. WSTG says business logic flaws "cannot be detected by a vulnerability
scanner", and ASVS 5.0 says tools are "unable entirely to verify" access control. The AI proposes candidates and
tests here; a person judges.

## 8. Fix and retest

- One fix per commit, referencing the finding ID.
- Retest = the same profile, the same tool versions and the same cross-user tests, run on the fixed commit.
- Status moves Open → Fixed (code changed) → Retested (check passes, with date and commit).
- NIST SP 800-115 §6, 7.2 and 8.3 call for further testing to confirm the fix worked.
