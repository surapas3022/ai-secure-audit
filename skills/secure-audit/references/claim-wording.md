# What a report may claim

OWASP does not certify anyone. ASVS and MASVS are verification standards that support "self-assessed against" claims.
OWASP Top 10 is an awareness list, so you cannot "pass" it.

## Allowed

> Self-assessed against OWASP ASVS 5.0.0 Level 1 on 2026-11-15, commit `a1b2c3d`.
> Automated checks: gitleaks 8.x, osv-scanner 2.x, trivy 0.x (exact versions in the appendix).
> No open findings rated critical or high. Not covered: see "Limitations".

- Always give the standard, version, level or profile, date and commit.
- Cite requirements with their version, e.g. `v5.0.0-1.2.5`; numbering changes between versions.
- For mobile, MASVS v2 uses MAS profiles (MAS-L1, MAS-L2, MAS-R), not the old L1/L2 levels.

## Not allowed

- "Certified", "ISO compliant", "OWASP approved"
- "Passes OWASP Top 10" or "covers the OWASP Top 10"
- "No vulnerabilities" or "secure", with no scope

## Limitations section (always present)

State which of these were not done or only partly done:

- cross-user authorization testing, and for how many endpoints
- business logic review
- dynamic testing, and on which environment
- areas excluded by scope
