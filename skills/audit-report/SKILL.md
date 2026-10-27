---
name: audit-report
description: >-
  Writes a security audit report from triaged findings, in one of two forms:
  "simple" (top five problems in plain language with step-by-step fixes, for
  people who build with AI or are not security specialists) or "full" (every
  finding, scope, method, tool versions, standard claims and limitations, for
  clients and reviewers). Use when the user asks for an audit or security
  report, a summary of findings, or a deliverable for a client.
---

# Audit report

## Input

Findings from [finding-triage](../finding-triage/SKILL.md) that a person has confirmed, plus `.audit/scope.md`. If
findings are still `needs-human`, list them as open questions; do not decide them here.

## Pick the form

| Form | Reader | Template |
|---|---|---|
| `simple` | the builder; may not be a developer | [assets/report-simple.template.md](assets/report-simple.template.md) |
| `full` | a client, reviewer, or the audit record | [assets/report-full.template.md](assets/report-full.template.md) |

## Rules

- Claims follow [secure-audit/references/claim-wording.md](../secure-audit/references/claim-wording.md): standard,
  version, level, date, commit. Never "certified" or "secure".
- The Limitations section is always present, even in `simple`.
- Keep the AI's explanations apart from the findings. Findings carry evidence; explanations are labelled as
  explanation.
- No personal data, tokens or full secrets anywhere in the report.
- Write the report to the location in `scope.md`, never into this kit's repository.
