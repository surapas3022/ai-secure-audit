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
- Use each finding's `fix` field. A key that is in git or was deployed must be rotated at the provider first: deleting it from the code is not enough. A finding marked `not_committed` can be moved out of the code without rotating, unless the key was shared or pasted somewhere else. From 0.0.14 a file that is tracked and identical to HEAD is never marked `not_committed`, even when it was moved with `git mv`; before that, such a key was wrongly marked, so check older results.
- Findings of type `code` come from pattern rules and can be wrong. Read the code at the location. If a limit or check exists where the rule cannot see it (another file, the reverse proxy), tell the user, but do not remove the finding.
- `retest` keeps a key from git history as `still open` even after it is rotated, because the tool cannot know it was cancelled. Tell the user this.
- Ask before rewriting git history.
- Say what was not checked: whether one user can reach another user's data, business rules, how sign-in, sign-up and password reset work, database rules, the live server, and Docker Compose files (Dockerfiles are checked from 0.0.10; Compose files are not). "0 problems" does not mean the app is safe.
- `findings.json` has a `coverage.gaps` list: languages with no code rules, how few code rules ran for the languages that have some (and common mistakes none of them look for, such as SQL built from user input or XSS), files the code rules never read (folders named test or tests, *.min.js), files the code checker could not read or read only in part, lockfiles from ecosystems not tested yet, and Docker Compose files (not read by trivy). Tell the user each one; "0 findings" does not cover them. For a language with no code rules you may offer to review it with [`docs/ai-review-prompt.md`](docs/ai-review-prompt.md); keep what you find in a separate section, not as findings.
- `findings.json` has a `notices` list about the check's own results, not about the app (from 0.0.11: a Dockerfile that would copy `.audit/` into the image). Tell the user, and ask before editing `.dockerignore` or the Dockerfile. Notices are not findings and have no severity.
- From 0.0.13 `--report simple` also writes `report-simple.md`: one item per problem (several advisories for the same library are merged into one item), in plain words, grouped by how soon to act. It is a shorter view of the same `findings.json`, not new findings. Offer it when the user does not know security words. It was tested on macOS and Linux, not Windows, and not yet with readers who do not know security.
- `live <host>` checks the TLS of one live host. Only run it for a host the user has listed in `targets.yml`, never to "see if it works" on someone else's site. Never add `--allow-prod` unless the user says in this conversation to check production. Never edit `targets.yml` to make a refused host pass. A result says nothing about the app itself, only its TLS. `--ports` checks a fixed list of risky ports by connecting and closing (nothing is sent): tell the user that "not found open" can also mean blocked by a firewall or not reachable from where it ran, and that it only speaks for the network it ran from. If it finds a database or Docker port open to the internet, tell the user plainly and first, and that data may already have been read. With `--zap` it also runs ZAP's passive baseline in Docker. That finds header and cookie mistakes only: never tell the user a clean ZAP baseline means there is no XSS, injection or access-control problem. Never run ZAP's active scan or full scan yourself against anything. With `--ports`, never tell the user a port is "open to the internet" from this check alone: it connects from the computer that ran it, and on a `localhost` or private address an open port shows only that something is listening. Quote the evidence line.
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
