# Skills

Agent skills (the `SKILL.md` format read by Claude Code and other agents) that guide an AI through an audit.
They organise the work and explain the results. The findings themselves come from the scanners in
the `npx ai-secure-audit` CLI ([docs/cli.md](../docs/cli.md)) and from tests and code locations a person can check.

| Skill | Use when | Audit phase | Status |
|---|---|---|---|
| [secure-audit](secure-audit/SKILL.md) | Starting, running or retesting an audit; routes to the skills below | 1, 2, 4, 8 | draft |
| [threat-model](threat-model/SKILL.md) | Drawing a data flow diagram and listing threats (STRIDE) | 3 | draft |
| [authz-review](authz-review/SKILL.md) | Looking for IDOR/BOLA, missing guards, mass assignment; writing cross-user tests | 5 | draft |
| [compose-hardening](compose-hardening/SKILL.md) | Checking or writing a Docker Compose deployment | 4, 5 | draft |
| [finding-triage](finding-triage/SKILL.md) | Turning raw scanner output into verified, deduplicated findings | 6 | draft |
| [audit-report](audit-report/SKILL.md) | Writing the report (simple or full) | 7 | draft |

"draft" means the skill has not yet been tested on a real audit.

## Rules every skill follows

1. **Evidence only.** Every finding points to scanner output, a `file:line`, or a test result. A skill never invents,
   drops, or silently merges a finding.
2. **A person decides.** People approve scope, confirm or reject findings, mark ASVS requirements pass/fail, and sign
   the report. The AI drafts and checks.
3. **Nothing project-specific inside a skill.** Data about the audited project lives in that project's `.audit/` folder.
   Results go wherever the scope file says, never into this repository.
4. **No traffic to unlisted hosts.** Only hosts in the project's `.audit/targets.yml` may be contacted, and
   production hosts get passive checks only.
5. **Each skill works alone.** `secure-audit` only routes; `authz-review` or `compose-hardening` can be used while
   building, without a full audit.

## Inside one skill

```text
<skill>/
  SKILL.md            rules and procedure, always read
  references/         read only when the step needs it
    stacks/<stack>.md read only for the stack that was detected
  assets/             templates copied into the audited project
  scripts/            deterministic checks (same input, same output)
```

## Files in the audited project

```text
<project>/.audit/
  scope.md            scope and rules of engagement (from secure-audit/assets/scope.template.md)
  targets.yml         hosts that may be contacted (from config/targets.example.yml)
  inventory.md        phase 2 output
  threat-model.md     phase 3 output (from threat-model/assets/threat-model.template.md)
```

Commit these only if the project is private. Scan results and reports never go in the audited repo unless
`scope.md` says so.

## Install

Planned: `npx ai-secure-audit init` copies the skills into the project for each AI assistant it finds
(`.claude/skills/` for Claude Code, `.agents/skills/` for Codex and Antigravity; see [docs/cli.md](../docs/cli.md)).

Until then, for Claude Code, link each skill into your personal skills folder:

```bash
for d in skills/*/; do ln -s "$PWD/$d" ~/.claude/skills/"$(basename "$d")"; done
```
