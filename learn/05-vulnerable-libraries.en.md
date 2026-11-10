# Item 5: Libraries with known holes

[ภาษาไทย](05-vulnerable-libraries.md) | **English**

[Back to the checking order](README.en.md)

## Words used here

- **Library or package**: code someone else wrote that your app uses, such as `express` for a web server or `lodash` for working with data.
- **Dependency**: a library your app needs. Without it the app does not run.
- **Dependency of a dependency**: a library that one of your libraries uses in turn. You never installed it yourself, but it is in your app. Installing 3 libraries can bring in dozens.
- **npm**: the tool that installs JavaScript and Node.js libraries.
- **`package.json`**: the list of libraries your app wants. It can name a range of versions, such as `^1.2.5`.
- **`^` before a version**: the [npm docs][npmjson] call it "Compatible with version". For example `^1.0.4` accepts newer minor releases with the same first number.
- **Lockfile**: the file that records the exact version of every library installed, including dependencies of dependencies. npm uses `package-lock.json`, pnpm uses `pnpm-lock.yaml`, yarn uses `yarn.lock`.
- **Published vulnerability (advisory)**: a notice saying which versions of a library have a weakness and which version fixes it.
- **CVE**: a worldwide ID for one vulnerability, such as `CVE-2021-44906`. Every site that talks about that vulnerability uses the same ID.
- **GHSA**: the ID of an advisory in GitHub's database, such as `GHSA-xvch-5gv4-984h`. One vulnerability often has both a CVE and a GHSA.
- **CVSS**: a severity score from 0 to 10. Higher is worse.
- **OSV**: an open source vulnerability database that gathers advisories from many sources in one place, including GitHub's database.
- **Finding**: one problem reported by the tool.

## Why this matters

When a library vulnerability is published, everyone learns how to attack it at the same time. An attacker only has to find apps still on that version. The [OWASP Top 10:2025][owasp] lists "A03:2025 - Software Supply Chain Failures" as the third biggest risk for web apps, and that category covers problems from the libraries an app pulls in.

The good news: most of these are fixed by updating to the fixed version. You do not have to change your own code.

## How old libraries get into an app

1. **The AI writes version numbers from memory.** The AI knows libraries from the data it learned from. If it writes `package.json` by hand instead of running `npm install`, it can pick an old version with a published hole.
2. **Starting from a template or an old project.** The lockfile keeps the old versions, so every install gives the same old versions.
3. **Nothing went wrong, time just passed.** On the day you installed, nobody knew about the hole. Next month someone finds and publishes it, and the version you use becomes vulnerable. So check again from time to time, not just once.
4. **It comes in as a dependency of a dependency.** You updated the libraries you installed, but something they pull in can still be old.

## Try it on an example first

You need Node.js. These commands make a test folder that pins two libraries to old versions. `--package-lock-only` writes only the lockfile and does not install the code, and `--ignore-scripts` runs no library scripts, so no old code ever runs.

```bash
git clone https://github.com/surapas3022/ai-secure-audit.git
mkdir demo-libs && cd demo-libs
npm init -y
npm install minimist@1.2.5 lodash@4.17.20 --save-exact --package-lock-only --ignore-scripts
node ../ai-secure-audit/bin/ai-secure-audit.js .
```

The first run is slower because it downloads the tools and the vulnerability database (about 210 MB for npm). On 10 November 2026 it printed this line:

```text
1 critical · 2 high · 2 medium · 0 low
```

If you get more, nothing is wrong: someone has found more holes in these old versions. The database grows every day.

Open `.audit/out/report.md`. The first item is `minimist 1.2.5: Prototype Pollution in minimist` with the fix `Upgrade minimist to 1.2.6 or later`. That matches [GitHub's advisory][ghminimist], which says versions before 1.2.6 are vulnerable and 1.2.6 is patched.

Now fix it:

```bash
npm install minimist@latest lodash@latest --save-exact --package-lock-only --ignore-scripts
node ../ai-secure-audit/bin/ai-secure-audit.js retest
```

You should get `0 critical · 0 high · 0 medium · 0 low`.

## Check your own project

Open a terminal in the project folder and run:

```bash
npx ai-secure-audit
```

Or tell your AI assistant:

> Run `npx ai-secure-audit` in this project, explain the results in simple words, and help me fix the most serious ones first. Do not add or remove findings.

The tool reads every lockfile in the project and compares it with a copy of the OSV database stored on your machine. Your list of libraries is not sent anywhere. That is different from `npm audit`: the [npm docs][npmaudit] say it submits a description of your project's dependencies to the registry to get a report. Both work; just know where your data goes.

A lockfile is required. If the project only has `package.json`, run `npm install` first. Otherwise you get 0 findings even when there are problems.

## How to read the results

Each finding tells you 4 things. The first three are in `report.md`; the advisory IDs and scores are in `.audit/out/findings.json`.

| Part | Example | Meaning |
|---|---|---|
| Title | `lodash 4.17.20: Command Injection in lodash` | which library, which version, what kind of hole |
| Location | `package-lock.json` | which lockfile |
| Fix | `Upgrade lodash to 4.17.21 or later` | the version that fixes it |
| Advisory IDs (`findings.json`) | `Advisories: CVE-2021-23337, GHSA-35jh-r3h4-6jhm` | search these for details, such as [GitHub's advisory][ghlodash] |

The level comes from the CVSS score, using the [table from FIRST][cvss], which maintains the standard. The actual score is in `severity.tool` in `findings.json`, for example `CVSS 7.2`.

| Score | Level in the report |
|---|---|
| 9.0 – 10.0 | critical |
| 7.0 – 8.9 | high |
| 4.0 – 6.9 | medium |
| 0.1 – 3.9 | low |

An advisory with no score is reported as medium, with `severity.tool` set to `unrated`.

A hole in a library does not always mean your app can be attacked. Sometimes the hole is in a function your app never calls. But finding out takes a deep read of the code. Updating is faster and more certain.

## Fix in this order

1. **Update to the version the report gives**, and let the lockfile change with it.

   ```bash
   npm install lodash@4.17.21
   ```

2. **If the first number changes, test the app before using it.** For example from `0.21.1` to `1.15.2`. A new first number often means the way you use the library changed. Ask the AI to read that library's changelog and update the code, then try the app for real.
3. **If the problem is a dependency of a dependency**, update the library you installed first; its newer release usually pulls in the fixed version. If the problem stays, the [npm docs][npmoverrides] describe `overrides` in `package.json` for forcing the version of a dependency of a dependency, for example one with a known security issue.

   ```json
   {
     "overrides": {
       "minimist": "1.2.8"
     }
   }
   ```

   Then run `npm install` again. Overrides only work in the top-level `package.json` of the project.
4. **If the report says there is no fixed version yet**, check whether your app uses the affected part. If it does, look for another library that does the same job.
5. **Check again.**

   ```bash
   npx ai-secure-audit retest
   ```

6. **Deploy again.** The running server keeps the old versions until you put the new build up.

## Stop it before it happens

- **Check before every deploy.** New holes are published every day. An app that passed last month may not pass today.
- **Have the AI install with a command, not by typing version numbers.** Tell it: "Install libraries with `npm install` to get the latest version. Do not write version numbers into `package.json` yourself."
- **Turn on Dependabot on GitHub.** [Dependabot alerts][dependabot] warn you when a library in your project gets a new hole, and [Dependabot security updates][dependabotupdates] open a pull request that updates it to the lowest fixed version. You review it and merge.
- **Always commit the lockfile.** The [npm docs][npmlock] say the lockfile lets later installs produce the same tree. Without it, the server you deploy to may get different versions from the ones you checked.

## What this check cannot see

- Projects with no lockfile (only `package.json`)
- Libraries loaded from a CDN with `<script src="https://...">` in a page, because they are not in the lockfile
- Library code copied straight into your project
- Holes nobody has published yet
- Whether your app actually calls the vulnerable part
- System programs on the server or in a Docker image (that is item 6)
- `node_modules/` and files git ignores are skipped, because the lockfile already lists everything

## Sources

Accessed 10 November 2026

- [OWASP Top 10:2025][owasp]
- [FIRST: CVSS v3.1 Specification][cvss] §5 Qualitative Severity Rating Scale
- [OSV: A distributed vulnerability database for Open Source][osv]
- [osv-scanner: Supported languages and lockfiles][osvlockfiles]
- [npm Docs: package-lock.json][npmlock]
- [npm Docs: package.json][npmjson]
- [npm Docs: package.json overrides][npmoverrides]
- [npm Docs: npm audit][npmaudit]
- [GitHub Docs: About Dependabot alerts][dependabot]
- [GitHub Docs: Dependabot security updates][dependabotupdates]
- [GitHub Advisory: Prototype Pollution in minimist (GHSA-xvch-5gv4-984h)][ghminimist]
- [GitHub Advisory: Command Injection in lodash (GHSA-35jh-r3h4-6jhm)][ghlodash]

[owasp]: https://top10.owasp.org/2025/
[cvss]: https://www.first.org/cvss/v3.1/specification-document
[osv]: https://osv.dev/
[osvlockfiles]: https://google.github.io/osv-scanner/supported-languages-and-lockfiles/
[npmlock]: https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json
[npmjson]: https://docs.npmjs.com/cli/v10/configuring-npm/package-json
[npmoverrides]: https://docs.npmjs.com/cli/v10/configuring-npm/package-json#overrides
[npmaudit]: https://docs.npmjs.com/cli/v10/commands/npm-audit
[dependabot]: https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts
[dependabotupdates]: https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-security-updates
[ghminimist]: https://github.com/advisories/GHSA-xvch-5gv4-984h
[ghlodash]: https://github.com/advisories/GHSA-35jh-r3h4-6jhm
