# CLI design: `npx ai-secure-audit`

Status: `scan`, `retest` and `tools` work from a clone (`node bin/ai-secure-audit.js`) and from npm 0.0.1. Version 0.0.3 adds osv-scanner. Version 0.0.4 also marks a key taken out of a file that still exists as `(git history only)`, not only a key in a deleted file. Version 0.0.5 adds opengrep with the first rule of this kit. Version 0.0.6 adds rules for NestJS and for vote routes, and runs on Alpine Linux. Version 0.0.7 says in the report which languages and lockfiles were not checked or not tested. Version 0.0.8 points those languages to [the AI review prompt](ai-review-prompt.md). Version 0.0.9 adds a rule for session checks done on a plain object. Version 0.0.10 adds trivy config for Dockerfiles and other config files, and names Docker Compose files as not checked (trivy does not read them). v0.1 is not released yet.
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
- Windows, macOS and Linux (x64 and arm64, glibc or musl/Alpine).
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

Options: `--report simple` (also write `report-simple.md`, a short to-do list in plain words: what is wrong, where, what to do; several advisories for one library become one item. Tested on macOS and Linux, not Windows), `--json` (print machine-readable output only), `--fail-on <critical|high|medium>` (for CI).

## Tools

- Pinned in `tools.lock.json`: version, download URL and SHA-256 for each platform.
- Downloaded on first use to the user cache (`~/.cache/ai-secure-audit/` or `%LOCALAPPDATA%\ai-secure-audit\`).
- A checksum mismatch stops the run. The CLI never falls back to a version that is not pinned.
- Basic tier today: gitleaks, osv-scanner and opengrep. Other tools are added one at a time, each after passing its own tests
  (see Planned coverage in the README).
- osv-scanner reads lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `pubspec.lock`, `requirements.txt`
  and others) and checks them against an offline copy of the public OSV database. The first run downloads the
  database for each ecosystem it finds (npm was about 210 MB in November 2026) to the user cache; the list of libraries never
  leaves the machine. `node_modules/` and files a `.gitignore` names are skipped (even committed ones). Libraries are
  only checked from a lockfile (or `requirements.txt`, `go.mod`, `pom.xml`). The report says "Libraries not checked", at
  the top and under what was not checked, when a manifest that lists libraries (`package.json`, `composer.json`,
  `Gemfile`, `Cargo.toml`, `pyproject.toml`, `Pipfile`, `pubspec.yaml`, `*.csproj`, `build.gradle`, `mix.exs`) has no
  lockfile, and when a lockfile is there but osv-scanner read no library from it. A lockfile at the top of an npm, pnpm or
  Cargo workspace covers its members. Known limit: in a hand-made `package-lock.json` without `resolved` fields,
  osv-scanner 2.7.0 lists the libraries but matches no advisory, and this is not detected.
- In a git repository gitleaks runs twice, over the commits and over the current files, so a key that is not committed
  yet is still found. Files git ignores are left out, except build output (`dist/`, `build/`, `.next/static/`,
  `.output/public/`, `.svelte-kit/output/client/`), because that is what gets deployed. Files over 20 MB are skipped.
- opengrep runs only this kit's own rules from `rules/` (one `.yml` per rule, with a test file of the same name beside
  it; `opengrep scan --test rules/` runs them). Rules from the Semgrep Registry are not used: their license is not open
  source. Files git ignores are scanned too, except installed and generated code (`node_modules/`, `dist/`, `build/`,
  `.next/`, `.nuxt/`, `.output/`, `.svelte-kit/`, `coverage/`, `vendor/`). opengrep publishes no checksums file, so the
  lock takes the SHA-256 GitHub records for each release asset. On Linux without glibc (Alpine) the CLI uses the lock
  entries `linux-*-musl`: opengrep's musllinux build, and the same static files as glibc Linux for the other tools.
- First rule, `express-route-no-rate-limit` (medium): an Express route whose path looks like sign-in, sign-up, join,
  reset or a code check, in a file with no limiter package loaded and no limit named in the route. It cannot see a
  limiter set up in another file or at a proxy, so the report asks to check the code before changing it.
- `nestjs-route-no-throttle` (medium, 0.0.6): the same for NestJS: `@Post('login')` and similar, or `@Post()` in a
  controller whose path is `login`, with no `@Throttle` or `ThrottlerGuard` on the route or class. Dropped when any
  file registers `ThrottlerGuard` for the whole app (`APP_GUARD` or `useGlobalGuards`): a rule marked
  `internal: true` records that, and a rule with `suppressed-by: <id>` is dropped when it matched. Internal rules are
  never shown.
- `express-vote-route-no-identity` (medium, 0.0.6): a vote, like or rating route whose handler never looks at who is
  calling (no session, token, cookie, user, IP) and has no limit. Vote routes that need a token from a join step are
  not matched; that join step is what `express-route-no-rate-limit` checks.
- `express-session-lookup-plain-object` (high, 0.0.9): a session, token or admin check that looks up a value from the
  request (cookie, header, query, body, or a home-made `cookies(req)` parser) in a plain object, such as
  `if (db.adminSessions[cookie])`. Every plain object has `constructor`, `toString` and `__proto__`, so a request with
  one of those names passes. Not matched when the token is hashed first, upper-cased, checked with `Object.hasOwn`, or
  the store is a `Map` or `Object.create(null)`. Only a lookup tested directly (in an `if`, a ternary, `!` or `in`)
  and stores named like sessions, tokens, admins or keys; a lookup stored in a variable and tested later is missed.
- **What was not checked.** The CLI counts source files by extension and lists lockfiles (skipping installed and
  generated folders), then writes `coverage` into `findings.json`: each language with its file count and whether this
  kit has code rules for it (taken from the `languages:` of the rule files), and each lockfile with whether its
  ecosystem has been tested with known answers. Gaps go into the report under "What this check could not see" and
  into the instructions printed for the AI, so "0 findings" for a PHP or Go project is not read as "checked".
  Docker Compose files (`compose.yaml`, `docker-compose.yml` and variants such as `docker-compose.prod.yml`) are
  listed in `coverage.compose` and named as a gap, because trivy reads Dockerfiles but has no Compose scanner: a
  Compose file with `privileged: true` or a mounted `docker.sock` gives no finding at all.
  Lockfiles tested with known answers: `package-lock.json` (npm), `composer.lock` (PHP), `go.mod` (Go), `Cargo.lock`
  (Rust), `Gemfile.lock` (Ruby), `packages.lock.json` (NuGet), `requirements.txt` (Python). Code rules: JavaScript and
  TypeScript only (Express, NestJS); `.vue` and `.svelte` files are not read by them.
- Maintainers update versions in `scripts/update-lock.mjs` and run `npm run update-lock`.

## Output

Written to `.audit/out/` in the scanned project. The CLI writes `.audit/out/.gitignore` containing `*`, so results are
never committed by accident.

| File | For |
|---|---|
| `findings.json` | machines and AI; stable sort, so the same commit gives the same bytes |
| `report.md` | the simple report: top problems in plain language |
| `raw/<tool>.json` | each tool's original output (gitleaks: `raw/gitleaks-history.json` and `raw/gitleaks-files.json`; osv-scanner: `raw/osv-scanner.json`) |

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
- Use each finding's fix field. A key that is in git or was deployed must be rotated at the provider: deleting it from the code is not enough.
- A finding marked not_committed can be moved out of the code without rotating, unless the key was shared or pasted somewhere else.
- Not checked: whether one user can reach another user's data, and business rules. Say so.
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

## GitHub Action

Run the same check on every push. Save this as `.github/workflows/audit.yml`:

```yaml
name: security check
on: [push, pull_request]
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0   # gitleaks reads git history
      - uses: surapas3022/ai-secure-audit@v0
        with:
          fail-on: high
```

Inputs: `path` (default `.`), `fail-on` (`critical`, `high`, `medium`, `low`; default `high`), `version` (npm version of this tool; default is pinned to the release the tag points to). The job fails when a finding is at or above `fail-on`. The report is uploaded as the `ai-secure-audit-report` artifact. Tested on a GitHub-hosted Linux runner only.

## live: check the TLS of one host

Create `targets.yml` next to where you run the command. List only hosts you own or may test, and keep the file out of git:

```yaml
targets:
  - host: dev.example.com
    scheme: https     # https (default) or http
    env: dev          # dev (default) or prod
```

```bash
npx ai-secure-audit live dev.example.com
```

(The same example ships in the package as `config/targets.example.yml`.)

**Status: first release of `live` (0.0.13).** Tried on servers on the same machine (a deliberately weak TLS server and a deliberately weak web server, results compared with what was expected beforehand) and on a GitHub-hosted Linux runner. **Not tried on a real remote site**, not on Windows, not with a real https site under `--zap`, and the "no Docker" path is only unit-tested. Treat the first runs on your own site as a trial and compare with another tool (for example SSL Labs for TLS).

`live` talks to a real server, so it is a separate command from `scan` and it is strict:

- It checks **one** host and port at a time, and only if it is in `targets.yml`. Anything else is refused before any connection is made: a host that is not listed, a sub-domain or parent of a listed host, a URL, a path, a wildcard, an address range. A line in `targets.yml` that cannot be read is an error, never skipped.
- A host marked `env: prod` also needs `--allow-prod`, every time. Add it only when the owner has said to check production.
- It uses [testssl.sh](https://github.com/testssl/testssl.sh) (GPL-2.0), pinned by a hash of the whole folder (`live_tools` in `tools.lock.json`). It needs `bash` and `openssl`, and takes about 2 minutes per host. There is no build for Windows (use WSL) or Alpine (no bash by default): the report then says the check did not run, and the exit code is 2.
- Results go to `.audit/out/live/<host>-<port>/` (`report.md`, `findings.json`, the raw `testssl.json`).

What becomes a finding: old SSL/TLS versions that are offered, weak cipher groups, an untrusted, mismatched, expired or weakly signed certificate, missing HSTS, and known TLS weaknesses (Heartbleed, ROBOT, POODLE and similar). testssl lists about 170 lines for one host; the rest stay in the raw file. A test testssl could not run (for example RC4 when the local OpenSSL has none) is listed under "Tests that could not run", never shown as a pass.

Not checked by the TLS part: the app itself, HTTP security headers other than HSTS, cookies, other hosts and ports.

### `--zap`: the web check

```bash
npx ai-secure-audit live dev.example.com --zap
```

Adds the [OWASP ZAP](https://github.com/zaproxy/zaproxy) (Apache-2.0) **baseline** check, run in Docker from an image pinned by digest (`live_tools.zap`). It needs Docker; without it the report says the web check did not run and the exit code is 2. The first run downloads the image (about 1 GB).

- It uses the same `targets.yml` gate as the TLS check. `targets.yml` takes `scheme: https` (default) or `scheme: http` per host. A plain-http host has no TLS, so the TLS part is shown as skipped and `--zap` is required.
- It is **passive**: ZAP spiders the site for about a minute with ordinary GET requests and reads every response. This tool never runs ZAP's active scan, full scan or API scan.
- A server on this machine is reached from the container as `host.docker.internal`. On Linux that name points at the Docker bridge, so a local dev server must listen on all interfaces (`0.0.0.0`), not only `127.0.0.1`; stop it when the check is done.
- Findings are header, cookie and information-leak mistakes: missing CSP, X-Frame-Options, X-Content-Type-Options; cookies without HttpOnly or SameSite; server and framework versions in headers; forms without an anti-CSRF token; scripts from other sites without an integrity hash; known-vulnerable JavaScript libraries; error messages that show internals. One finding per ZAP alert, with the first three places.
- A finding that rests on a banner the server sends about itself (for example "Apache 2.2 with known holes") is labelled that way and capped at medium, because the banner can be wrong.
- **What a clean result does not mean:** the baseline does not find XSS, injection, broken login or access control. On the weak test server it found 10 header and cookie problems and **0** of the cross-site scripting that a plain `curl` showed was there. Every report says this.
