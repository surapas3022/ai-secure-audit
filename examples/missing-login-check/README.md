# Example: an API that does not check the login

A tiny team-notes API for the lesson [learn/04-missing-login-check.en.md](../../learn/04-missing-login-check.en.md)
([ภาษาไทย](../../learn/04-missing-login-check.md)). One route has no login check, the admin route trusts a role
the web page sends, and the login check passes for the token `constructor`.

```bash
node examples/missing-login-check/server.mjs           # the mistakes
node examples/missing-login-check/server.mjs --fixed   # deny by default, role from the session, a Map
```

- No dependencies. Needs Node.js 18 or later.
- Listens on `127.0.0.1:4200` only (change with `PORT=`). Data is in memory and is reset on restart.
- Tokens for the two users, alice (member) and boss (admin), are random each time and printed at start.
- All names, emails and notes are made up.
