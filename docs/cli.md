# CLI design: `npx ai-secure-audit`

Status: `scan`, `retest` and `tools` work from a clone (`node bin/ai-secure-audit.js`). Not published to npm yet.
`init`, `mcp` and `--advanced` are not implemented.

## Who runs it

Mostly an AI coding assistant (Claude Code, Codex, Cursor, Antigravity and similar), working for someone who builds
apps with AI and will never read a terminal themselves. All of these assistants can run shell commands, so the CLI
is the one interface that works everywhere without setup. Skills and MCP are optional extras on top.

The user only has to say something like:

> Run `npx ai-secure-audit` in this project, explain the results in simple words, and help me fix the most serious
> ones first.

## Requirements

- Node.js 18 or later, and git if the project is a git repository. Nothing else: no Docker, Homebrew, Python or Java
  for the basic check.
- Windows, macOS and Linux (x64 and arm64).
- **No runtime npm dependencies.** A security tool should not bring a dependency tree of its own. Node's built-in
  modules (`fetch`, `crypto`, `child_process`, `zlib`) are enough.

## Commands

| Command | Does | Network |
|---|---|---|
| `npx ai-secure-audit` | same as `scan` | downloads tools on first run only |
| `scan [path]` | basic check of the project folder (default `.`) | downloads public vulnerability databases; never uploads code |
| `scan --advanced` | adds the advanced tools; needs Docker | only to hosts in `.audit/targets.yml` |
| `retest` | reruns with the same tool versions and compares with the last `findings.json` | as `scan` |
| `init` | installs the skills for the AI assistants it finds, and adds a short note to `AGENTS.md` / `CLAUDE.md` | none |
| `mcp` | runs a stdio MCP server with `scan` and `get_findings` tools (later) | as `scan` |
| `tools` | lists tool versions, licenses and cache location | none |

Options: `--json` (print machine-readable output only), `--fail-on <critical|high|medium>` (for CI).

## Tools

- Pinned in `tools.lock.json`: version, download URL and SHA-256 for each platform.
- Downloaded on first use to the user cache (`~/.cache/ai-secure-audit/` or `%LOCALAPPDATA%\ai-secure-audit\`).
- A checksum mismatch stops the run. The CLI never falls back to a version that is not pinned.
- Basic tier: gitleaks, osv-scanner (offline databases), trivy `config`. opengrep joins once `rules/` has rules.
- Maintainers update versions in `scripts/update-lock.mjs` and run `npm run update-lock`.
  See [skills/secure-audit/references/tools.md](../skills/secure-audit/references/tools.md).

## Output

Written to `.audit/out/` in the scanned project. The CLI writes `.audit/out/.gitignore` containing `*`, so results are
never committed by accident.

| File | For |
|---|---|
| `findings.json` | machines and AI; stable sort, so the same commit gives the same bytes |
| `report.md` | the simple report: top problems in plain language |
| `raw/<tool>.json` | each tool's original output |

Secrets are redacted in every file: gitleaks runs with `--redact`, and the matched text, author and email are never
copied into `findings.json` or `report.md`.

`findings.json` has no timestamps, so two runs on the same commit with the same vulnerability databases give
byte-identical files.

## What it prints

A short summary, then a fixed block addressed to the AI assistant that ran it:

```text
ai-secure-audit 0.1.0 · basic check · commit a1b2c3d
3 critical · 2 high · 5 medium · 11 low     report: .audit/out/report.md

For the AI assistant reading this:
- Findings are in .audit/out/findings.json. Do not add, remove or re-rate findings.
- Explain them to the user in plain language, most serious first.
- Ask before changing code. Fix one finding at a time; run `npx ai-secure-audit retest` after.
- A leaked secret must be rotated at the provider. Deleting it from the code is not enough.
- Not checked: whether one user can reach another user's data, and business rules. Say so.
- For deeper review, see the skills: npx ai-secure-audit init
```

The block is how the kit's rules reach assistants that have no skills installed.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | scan finished; nothing at or above `--fail-on` (default: never fail) |
| 1 | scan finished; findings at or above `--fail-on` |
| 2 | scan could not run, or a tool failed (the report says which; results are incomplete) |

## `init`: where skills go

The SKILL.md format is shared, but each assistant reads a different folder. `init` writes project-level copies only,
so nothing global changes:

| Assistant | Folder |
|---|---|
| Claude Code | `.claude/skills/` |
| Codex, Antigravity, others that follow `.agents/` | `.agents/skills/` |
| Cursor | to be confirmed at implementation time |

Paths are checked against each assistant's official docs when `init` is written, not taken from this table.
