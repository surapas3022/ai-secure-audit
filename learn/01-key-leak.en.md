# Item 1: Leaked keys

[ภาษาไทย](01-key-leak.md) | **English**

[Back to the check order](README.en.md)

## Terms

- **Key or secret**: a code your app uses to prove who it is to another service, such as a payment key, a database password or an AI token. Whoever has it can use that service as you
- **Provider**: the company that issued the key, such as Stripe, Supabase or OpenAI
- **Rotate a key**: cancel the old key on the provider's website and create a new one, so the old one stops working
- **git**: the system that records every change to your code
- **Commit**: one saved change in git
- **Push**: sending your commits from your machine up to GitHub
- **Pre-commit hook**: a command git runs by itself before every commit. If it fails, the commit does not happen
- **Git history**: all past commits. Something deleted from the latest files can still be read here
- **`.gitignore`**: the list of things git should not keep
- **`.env`**: a file of app settings on your machine. It often holds keys and should not go into git
- **Environment variable**: a value the app reads from the machine it runs on, so the key is not written in the code
- **Frontend**: code that runs in the visitor's browser. Anyone can read it
- **Backend or server**: code that runs on your machine. Visitors cannot see it
- **Build**: the step that turns your code into the files that go live, usually in `dist/`, `build/` or `.next/static/`
- **Deploy**: putting the app on a server for other people to use
- **Finding**: one problem reported by the tool

## Why start here

A key does not need to be broken into. Whoever finds it can use it. The [CWE-798][cwe] entry calls this hard-coded credentials. The tool can check for it in a few minutes, which makes it a good first step.

## How keys leak

1. **Written straight into the code.** AI often does this when you hand it a key and say "make it work"
2. **Committed, then deleted.** The latest file no longer has the key, but git history does, and anyone with a copy of the repository can read it
3. **`.env` left out of `.gitignore`.** The whole file goes into git at the next commit
4. **Put in a variable that is sent to the frontend.** The [Vite docs][vite] say variables starting with `VITE_` end up in browser code after the build and should not hold keys. The [Next.js docs][next] say `NEXT_PUBLIC_` variables are written into the files sent to the browser at build time. Your source file can look clean while the key sits in the build output

## Try it on the demo app first

You need Node.js and git. These commands create a fake app with fake keys generated when the script runs, so nothing real is affected. On Windows, change `/tmp/demo-app` to any empty folder.

```bash
git clone https://github.com/surapas3022/ai-secure-audit.git
node ai-secure-audit/examples/vulnerable-app/setup.mjs /tmp/demo-app
node ai-secure-audit/bin/ai-secure-audit.js /tmp/demo-app
```

You should see this line:

```text
0 critical · 2 high · 0 medium · 0 low
```

Open `/tmp/demo-app/.audit/out/report.md` to see two problems. The first is a key in `src/web/config.js`. The second is a `.env` marked `(git history only)`: the file was deleted, but the key is still in the history.

## Check your own project

Open a terminal in your project folder and run:

```bash
npx ai-secure-audit
```

Or tell your AI assistant:

> Run `npx ai-secure-audit` in this project, explain the results in simple words for someone who knows nothing about security, and help me fix one item at a time, starting with the most serious. Do not add or remove findings.

The tool runs on your machine and does not upload your code. If an AI reads the results, what it reads goes to that AI provider. Results are in `.audit/out/report.md`, and that folder stays out of git.

### Check only the .env file with git (nothing to install)

For a quick answer to "was `.env` ever committed?", run this in the project folder:

```bash
git log --all --full-history --oneline -- .env
```

- `--all` looks at every branch, not just the one you are on.
- `--full-history` stops git from simplifying the history. When you look at one file, [git normally drops some
  commits][gitlog] (see History Simplification), such as commits on branches that were merged.
- `-- .env` limits the output to that file.

No output means the `.env` at the top of the project was never committed. Any line means it was, even if the file has
since been deleted. Follow "Fix in this order" below, starting with rotating the key.

On the demo app above (`cd /tmp/demo-app` first) you get two commits. The commit ids differ every time the app is
created.

```text
14e74b2 Remove .env
e9c271f Add payments
```

The lower commit is when `.env` was committed, the upper one when it was deleted. The file is gone, but the key is
still in the lower commit.

This command only sees a file named `.env` at the top of the project. If you have `.env` in subfolders, or names like
`.env.local` or `.env.production`, use this instead (the [`:(glob)` form][pathspec] makes `**` mean any folder):

```bash
git log --all --full-history --oneline -- ':(glob)**/.env*'
```

This also lists `.env.example`, which is normally a template with no real values.

Limits: both commands go by file name only. A key written in another file, such as `src/web/config.js` in the demo
app, is not found. Do not use `git log -p` to view the contents and paste them into a chat or an AI: that sends the
key out another way. Use `npx ai-secure-audit`, which checks every file and never prints key values.

## Reading the results

| What the report shows | Meaning | Do you need to rotate the key? |
|---|---|---|
| `(not committed yet)` | In a file, not in git yet | If you never shared or pasted it anywhere, moving it out of the code is enough |
| No label, with a commit number | In a file and in git | Yes |
| `(git history only)` | Deleted from the files, still in the history | Yes |
| `(build output)` | In the files that go live | Yes, if it was ever deployed |

A `(build output)` item at medium level says it may be a false alarm, because minified code can look like a key. Check the value before deciding.

## Fix in this order

1. **Rotate the key first**, on the provider's website. [GitHub's guide][github] says the first step is to revoke or rotate the secret, and warns that removing history alone is not enough because old commits may survive in other people's copies
2. **Take the key out of the code** and have the backend read it from an environment variable
3. **If the key is used in the frontend, move that work to the backend.** The page calls your backend, and your backend calls the provider. Renaming the variable does not fix anything if frontend code still uses the key
4. **Add `.env` to `.gitignore`.** If it was committed before, also stop tracking it, because the [git docs][gitignore] say `.gitignore` does not affect files git already tracks

   ```bash
   git rm --cached .env
   ```

5. **Build again.** If the problem is in build output, old files keep the key until you build over them
6. **Check again**

   ```bash
   npx ai-secure-audit retest
   ```

If the key was ever in git, `retest` still shows `still open` after you rotate it, because the old key is still in the history and the tool cannot know it was cancelled. [GitHub's guide][github] says rotating may be enough and rewriting history may not be warranted. Once rotated, you can treat this item as done. Keep your own note of when you rotated it.

## Block keys before they are pushed

The section above fixes a key after it leaks. This one stops it from leaking again. Set up two layers: one on your machine and one on GitHub.

### Layer 1: a pre-commit hook on your machine

Let [gitleaks][gitleaks] check every commit before it is made. If it finds a key, the commit does not happen, so the key never enters the git history.

1. Install [pre-commit][precommit] once per machine (it needs Python). On a Mac with Homebrew you can use `brew install pre-commit` instead.

   ```bash
   pipx install pre-commit
   ```

2. Create `.pre-commit-config.yaml` in the top folder of your project (`v8.30.1` is the same version `npx ai-secure-audit` uses).

   ```yaml
   repos:
     - repo: https://github.com/gitleaks/gitleaks
       rev: v8.30.1
       hooks:
         - id: gitleaks
   ```

3. Turn it on for the project.

   ```bash
   pre-commit install
   ```

Good to know

- The hook only runs on machines where `pre-commit install` was run. Teammates and new machines must run it too.
- It can be skipped with `SKIP=gitleaks git commit ...` or `git commit --no-verify`. If an AI makes commits for you, tell it never to skip the hook.
- It does not check commits made before you installed it. Check those with `npx ai-secure-audit`.

### Layer 2: Push Protection on GitHub

GitHub checks your push. If it finds a key in a format it knows, it refuses the push, so the key never reaches GitHub ([GitHub's docs][pushabout]).

- **For your account**: on by default, and it stops you pushing keys to public repositories. Check it at your profile picture → Settings → Code security → "Push protection for yourself" ([how to check][pushusers]).
- **For a repository**: go to the repository → Settings → Advanced Security (under Security and quality) → enable Secret Protection, then click Enable next to Push protection ([how to enable][pushrepo]). This protects every push to that repository, not only yours. It is free for public repositories. Private repositories need GitHub Secret Protection, which is paid ([GitHub's docs][ghas]).

If a push is blocked, remove the key from that commit, then push again ([GitHub's steps][pushcli]). If an AI does this for you, tell it not to bypass the block.

Good to know

- It only catches keys in formats GitHub knows ([the list][patterns]).
- Anyone with write access can bypass the block by choosing a reason such as "It's used in tests".
- It does not help repositories hosted elsewhere, such as GitLab, and it does not remove keys that were already pushed. For those, follow the section above.

The two layers cover different moments. The hook catches a key before it enters the git history. Push Protection catches it at push time, even on a machine without the hook.

## Some keys are meant to be public

If the tool or an AI warns about one of these, check the key type first.

| Service | OK in the frontend | Never in the frontend |
|---|---|---|
| [Stripe][stripe] | Publishable key (`pk_...`) | Secret key (`sk_...`) and restricted key (`rk_...`) |
| [Supabase][supabase] | Publishable key (`sb_publishable_...`) or the older `anon` key | Secret key (`sb_secret_...`) or the older `service_role` key |
| [Firebase][firebase] | API keys for Firebase services | Gemini Developer API key |

"OK" does not mean safe by itself. The [Firebase docs][firebase] warn that you still need Security Rules to protect your data. That is item 3 in the [check order](README.en.md).

## What this check cannot see

- Keys in a format that [gitleaks][gitleaks] rules do not know. The tool looks for known patterns, so it can miss some
- Keys sent in chat, pasted into documents, or already on a deployed server
- Files larger than 20 MB
- The folders `node_modules/`, `vendor/` and `coverage/`
- Files git ignores, except build output, because they stay on your machine

## Sources

Accessed 9 November 2026

- [CWE-798: Use of Hard-coded Credentials][cwe]
- [GitHub Docs: Removing sensitive data from a repository][github]
- [Git: gitignore][gitignore]
- [Vite: Env Variables and Modes][vite]
- [Next.js: How to use environment variables][next]
- [Stripe: API keys][stripe]
- [Supabase: API keys][supabase]
- [Firebase: Learn about using and managing API keys][firebase]
- [gitleaks][gitleaks]
- [pre-commit][precommit]
- [GitHub Docs: About push protection][pushabout]
- [GitHub Docs: Push protection for users][pushusers]
- [GitHub Docs: Enabling push protection for your repository][pushrepo]
- [GitHub Docs: Working with push protection from the command line][pushcli]
- [GitHub Docs: Supported secret scanning patterns][patterns]
- [GitHub Docs: About GitHub Advanced Security][ghas]
- [Git: git-log][gitlog], History Simplification
- [Git: gitglossary — pathspec][pathspec]

[cwe]: https://cwe.mitre.org/data/definitions/798.html
[github]: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository
[gitignore]: https://git-scm.com/docs/gitignore
[vite]: https://vite.dev/guide/env-and-mode
[next]: https://nextjs.org/docs/app/guides/environment-variables
[stripe]: https://docs.stripe.com/keys
[supabase]: https://supabase.com/docs/guides/api/api-keys
[firebase]: https://firebase.google.com/docs/projects/api-keys
[gitleaks]: https://github.com/gitleaks/gitleaks
[precommit]: https://pre-commit.com/
[pushabout]: https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection
[pushusers]: https://docs.github.com/en/code-security/secret-scanning/working-with-secret-scanning-and-push-protection/push-protection-for-users
[pushrepo]: https://docs.github.com/en/code-security/secret-scanning/enabling-secret-scanning-features/enabling-push-protection-for-your-repository
[pushcli]: https://docs.github.com/en/code-security/secret-scanning/working-with-secret-scanning-and-push-protection/working-with-push-protection-from-the-command-line
[patterns]: https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns
[ghas]: https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security
[gitlog]: https://git-scm.com/docs/git-log#_history_simplification
[pathspec]: https://git-scm.com/docs/gitglossary#Documentation/gitglossary.txt-aiddefpathspecapathspec
