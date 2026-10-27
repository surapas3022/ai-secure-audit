---
name: finding-triage
description: >-
  Turns raw scanner output and review candidates into verified findings:
  deduplicates, checks each one against the code, marks false positives,
  assigns tool and contextual severity, and tags CWE, ASVS and OWASP API or
  MASVS references in a fixed schema. Use after running security scanners
  (gitleaks, osv-scanner, trivy, semgrep, hadolint, ZAP and similar), when
  the user pastes scanner output, asks which findings are real, or asks how
  severe a finding is.
---

# Finding triage

NIST SP 800-115 warns that scanners produce many false positives, and that checking by hand is more accurate than
comparing two tools (§4, §7.3). This skill does that checking. It does not create findings.

## Procedure

1. **Collect** every input: `.audit/out/findings.json` from `npx ai-secure-audit`, raw tool output, and candidates from manual
   review. Note each tool's name and version.
2. **Deduplicate.** The same rule at the same location is one finding. The same root cause at several locations is
   one finding with several locations. Record what was merged.
3. **Verify each one** by opening the `file:line` or reproducing the request:
   - `confirmed`: the code or response shows the problem
   - `false-positive`: say why (test fixture, dead code, value is not a secret, dependency path not reachable)
   - `needs-human`: you cannot tell from the code (business intent, production config)
4. **Severity.** Keep the tool's severity as it is. Add a contextual severity using Likelihood × Impact
   ([references/severity.md](references/severity.md)). Say which one came from the tool and which from judgement.
5. **Tag** CWE, ASVS (with version, e.g. `v5.0.0-8.2.1`), and OWASP API (`API1:2023`) or MASVS (`MASVS-STORAGE-1`)
   where they apply.
6. **Write** each finding in the schema [assets/finding.schema.json](assets/finding.schema.json), then hand the list
   to a person to confirm or reject.

## Rules

- Never add a finding that no tool, test or `file:line` supports.
- Never drop a finding silently. False positives stay in the list with their reason.
- Redact secrets in evidence: show the first 4 characters and the location, never the full value.
- A secret that was ever committed is `confirmed` even if it was deleted later; it stays in git history. The fix is
  to rotate it.
