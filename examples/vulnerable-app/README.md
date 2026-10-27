# Vulnerable demo app

A script that builds a small fake app with security mistakes, so you can see what the check finds without
scanning a real project.

```bash
node examples/vulnerable-app/setup.mjs /tmp/demo-app
node bin/ai-secure-audit.js /tmp/demo-app
```

Every key is random and fake, created when the script runs. The repository itself contains no keys.

## Mistakes in the app

| Added in | Mistake | Found by | Since |
|---|---|---|---|
| commit 2, deleted in commit 3 | `.env` with a payment key committed to git; deleting the file later does not remove it from history | gitleaks | v0.1 |
| commit 4 | a secret in a `NEXT_PUBLIC_*` variable, which the frontend build sends to every visitor | gitleaks | v0.1 |

More mistakes are added as each new check is released.
