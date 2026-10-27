# ai-secure-audit

> Status: early development. The basic check runs from a clone; it is not on npm yet. Planned first release: v0.1,
> December 2026.

A free, open-source security check for apps built with AI. If you make apps with Claude Code, Codex, Cursor or
Antigravity but security is not your field, ask your AI assistant to run it on your project:

> Run `npx ai-secure-audit` in this project, explain the results in simple words, and help me fix the most serious
> ones first.

Developers can also use it for web apps, APIs, Flutter apps and small self-hosted servers, and check them against
recognised standards before users or clients find the problems.

## How it works

The findings come from established open-source scanners, not from an AI's opinion, so the same code gives the same
result every run.

```
npx ai-secure-audit             runs pinned versions of the scanners with pinned rules (no AI needed)
        |
        v
.audit/out/findings.json        merged, stably sorted results from the tools
        |
        v
your AI assistant               explains each finding and how to fix it, and lists what the tools cannot check;
                                skills (npx ai-secure-audit init) add a guided full audit
```

- The AI never adds or removes findings; its explanations are kept in a separate section of the report.
- Tools and rule sets are pinned, so a rerun on the same commit produces an identical `findings.json`.
- Scanners that send traffic (DAST, port and TLS scans) only run against hosts listed in the audited project's
  `.audit/targets.yml` (see [`config/targets.example.yml`](config/targets.example.yml)).

## Try it now (from a clone)

Needs Node.js 18 or later and git. Nothing else.

```bash
git clone https://github.com/surapas3022/ai-secure-audit.git
node ai-secure-audit/bin/ai-secure-audit.js /path/to/your/project
```

To see what it finds without scanning a real project, build the fake demo app first (every key in it is random
and fake):

```bash
node ai-secure-audit/examples/vulnerable-app/setup.mjs /tmp/demo-app
node ai-secure-audit/bin/ai-secure-audit.js /tmp/demo-app
```

Or ask your AI assistant: *"Run `node <path-to>/ai-secure-audit/bin/ai-secure-audit.js` on this project, explain the
results in simple words, and help me fix the most serious ones first."*

Results go to `.audit/out/` in your project (`report.md` for people, `findings.json` for tools and AI). That folder
ignores itself in git, so results are not committed by accident.

## Repository layout

```
bin/, src/    the CLI: see docs/cli.md
tools.lock.json  pinned tool versions and SHA-256 checksums for every platform
test/         unit tests (npm test)
profiles/     pinned tool and rule sets per stack (planned)
rules/        this kit's own opengrep rules (planned)
config/       example files to copy into the audited project
skills/       AI skills, one folder per audit phase: see skills/README.md
docs/         design notes
```

## Planned coverage

### Basic check: works right after `git clone`

Checks are released one at a time, each after passing its own tests. The version in brackets is when each one is
switched on.

For anyone who builds apps with AI and wants to check their own project. You do not need Docker, Homebrew, Python
or Java. The tools are single files for Windows, macOS and Linux, downloaded at pinned versions and checked against
SHA-256 checksums. The check reads only your project folder and never uploads your code.

| Checks | Tool | License |
|---|---|---|
| Passwords, API keys and tokens in the code or git history (v0.1) | gitleaks | MIT |
| Libraries with known vulnerabilities (v0.2) | osv-scanner (offline database) | Apache-2.0 |
| Dockerfile and config mistakes (v0.3) | trivy config | Apache-2.0 |
| Code mistakes AI-generated apps often make (see below), planned | opengrep + this kit's own rules | LGPL-2.1 (rules: Apache-2.0) |

Common mistakes the kit's own rules look for: secret keys in frontend code or `NEXT_PUBLIC_*` variables, Supabase
`service_role` key outside the server, tables without row-level security, Firebase rules that allow everything,
API routes without an auth check, permission checks done only in the browser, committed `.env` files, CORS `*`,
and stack traces returned to users.

### Advanced check: for developers, needs Docker

| Layer | Tools | License | Standard |
|---|---|---|---|
| Dockerfile, Compose, CI config | hadolint, checkov, this kit's Compose rules | GPL-3.0, Apache-2.0 | CIS Docker Benchmark |
| Container images, SBOM | trivy image, syft | Apache-2.0 | — |
| Linux host | lynis | GPL-3.0 | CIS |
| TLS | testssl.sh | GPL-2.0 | Mozilla TLS guidelines |
| Running web app / API | OWASP ZAP, nuclei | Apache-2.0, MIT | OWASP ASVS, OWASP API Security Top 10 |
| Flutter mobile app | MobSF, opengrep | GPL-3.0, LGPL-2.1 | OWASP MASVS |

Every tool sends traffic only to hosts listed in `.audit/targets.yml`, and production hosts get passive checks only.

### Not used, and why

| Tool | Reason |
|---|---|
| Semgrep Registry rules | Under the Semgrep Rules License, which is not open source. The kit writes its own rules for opengrep. |
| nmap | Under the Nmap Public Source License, which is not OSI-approved and limits bundling. naabu (MIT) covers port checks. |
| CodeQL | The CLI is not open source and is free only for open-source code. |

## What it does not do

- It does not certify anything. A report states which standard and level were self-assessed, on which date and commit.
- Automated tools cannot fully check business logic or whether one user can reach another user's data;
  the report lists these for manual review.

## Privacy

The scan runs locally. The basic check downloads the pinned tools (first run only) and the public vulnerability
databases, then compares against them on your machine. It never uploads your code or your list of dependencies. The optional AI skill sends parts of the scanned code
and findings to the AI provider you use. Get permission before running it on code you do not own.

## Use only on systems you are allowed to test

Scan your own code and systems, or systems you have written permission to test.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
