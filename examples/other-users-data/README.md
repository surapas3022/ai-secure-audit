# Example: seeing other people's data

A tiny shop API for the lesson [learn/02-other-users-data.en.md](../../learn/02-other-users-data.en.md)
([ภาษาไทย](../../learn/02-other-users-data.md)). It checks who you are, but not whether the order is yours.

```bash
node examples/other-users-data/server.mjs           # the mistake
node examples/other-users-data/server.mjs --fixed   # checks the owner on every request
```

- No dependencies. Needs Node.js 18 or later.
- Listens on `127.0.0.1:4100` only (change with `PORT=`). Data is in memory and is reset on restart.
- Tokens for the two users, alice and bob, are random each time and printed at start.
- All names, addresses and phone numbers are made up.
