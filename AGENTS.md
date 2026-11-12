# Instructions for AI assistants

## Running this tool on a user's project

Use this section when someone points you at this repository and asks you to check their app.

1. In the user's project folder, run `npx ai-secure-audit`. It needs Node.js 18 or later and git. It downloads a pinned scanner on first use and does not upload the code.
2. Read `.audit/out/findings.json`. The same content for people is in `.audit/out/report.md`.
3. Explain the findings in plain language, most serious first, in the user's language.
4. Ask before changing code. Fix one finding at a time, then run `npx ai-secure-audit retest`.

### Rules

- Findings come only from the tool. Do not add, remove or re-rate them. Your own observations go in a separate section and do not count as findings.
- Never print or repeat a key's value, even when you can read the file.
- Use each finding's `fix` field. A key that is in git or was deployed must be rotated at the provider first: deleting it from the code is not enough. A finding marked `not_committed` can be moved out of the code without rotating, unless the key was shared or pasted somewhere else.
- Findings of type `code` come from pattern rules and can be wrong. Read the code at the location. If a limit or check exists where the rule cannot see it (another file, the reverse proxy), tell the user, but do not remove the finding.
- `retest` keeps a key from git history as `still open` even after it is rotated, because the tool cannot know it was cancelled. Tell the user this.
- Ask before rewriting git history.
- Say what was not checked: whether one user can reach another user's data, business rules, database rules, the live server, and Docker or config files. "0 problems" does not mean the app is safe.
- Exit code 2 means a tool did not run. Tell the user the check is incomplete.
- Only check code the user owns or has permission to test. If you are sending code to an AI provider and the code belongs to someone else, ask first.

### Commands

| Command | Use |
|---|---|
| `npx ai-secure-audit [path]` | Check a project folder (default: current folder) |
| `npx ai-secure-audit retest [path]` | Check again and compare with the last result |
| `npx ai-secure-audit --json` | Print `findings.json` to stdout |
| `npx ai-secure-audit --fail-on high` | Exit 1 if a finding is at or above that level (for CI) |
| `npx ai-secure-audit tools` | List pinned tool versions |

`init`, `mcp` and `--advanced` are not available yet.

### If the user wants to learn

Point them to [`learn/`](learn/README.en.md) (English) or [`learn/README.md`](learn/README.md) (Thai). It explains what to check first, why, and how to fix it.

## Changing this repository

Follow [`CLAUDE.md`](CLAUDE.md). It applies to every AI assistant working on this code.
