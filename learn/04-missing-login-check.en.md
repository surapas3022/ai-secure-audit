# Item 4: An API with no login check, or a check only in the web page

[ภาษาไทย](04-missing-login-check.md) | **English**

[Back to the checking order](README.en.md)

## Words used here

- **Authentication**: the system checks who you are, for example by logging in with an email and password.
- **Authorization**: the system checks whether you may do this, for example whether you may open the admin page.
- **API**: the way a web page or mobile app asks the backend for data. `GET /api/notes` means "give me the list of notes".
- **Route or endpoint**: one API, a method (`GET`, `POST`, ...) together with an address, such as `GET /api/notes/export`.
- **Request**: one call sent to an API.
- **Header**: information sent along with a request besides its content, such as the token that says who you are.
- **Token or session**: what the system gives you after you log in. It is sent with every request to say who you are, and the backend keeps a record of which token belongs to whom.
- **Cookie**: a small piece of data kept in the browser and sent with every request automatically. Often used to hold the token.
- **Frontend**: code that runs in the user's browser. Anyone can read and change it.
- **Backend or server**: code that runs on your machine. Users cannot see it.
- **Role**: the user's level, such as a regular member or an admin.
- **Middleware**: code that runs before every route, or before several of them, for work that repeats, such as checking whether the user has logged in.
- **Deny by default**: every route needs a login unless it is opened on purpose for people who are not logged in.
- **401 / 403**: API response codes. 401 means not logged in; 403 means logged in but not allowed.
- **DevTools**: the browser's built-in tools. Open with F12, or right-click and choose Inspect.

## What the problem is

The web page looks locked: if you are not logged in it sends you to the login page, and if you are not an admin you do not see the admin menu. But that blocking happens in the **web page**, and the **API** behind it does not check, or checks only part of the way. Anyone who calls the API directly with `curl` or DevTools skips the web page entirely.

In item 2 the app knows who you are but does not check whether the data is yours. This item is worse: the app does not check who you are at all, or believes you are an admin because the web page says so.

[CWE-306][cwe306] describes the problem as a system that does not authenticate anyone before a function that needs to know who the user is. [CWE-602][cwe602] describes a server that relies on the web page to enforce a protection that exists to protect the server itself.

## Why it is item 4

- [OWASP Top 10:2025][owasp], in "A01:2025 Broken Access Control" (ranked first), lists these directly: acting as a user without being logged in, gaining admin rights you should not have, an API with no access control for `POST`, `PUT` and `DELETE`, and changing a cookie or a hidden field to raise your privileges.
- [OWASP API Security Top 10 2023][api5], in "API5:2023 Broken Function Level Authorization", says admin functions are the main target and tells you to ask whether a regular user can call admin endpoints.
- Apps built with AI hit this often, because we ask for one page at a time: "make an admin page", "add a download button". The AI can make the page hide the button, but a route added later may never get a check.

It comes after item 2 because it is about as easy to find by trying, and the tool already catches part of it.

## Common forms

1. **A route added later has no check**, such as an "export CSV" or "download" button added afterwards. In Express, a route written above the `app.use(checkLogin)` line never goes through the check. The [Express documentation][express] says middleware loaded first runs first, and once a route has answered, middleware loaded after it never runs.
2. **The check is only in the web page.** The page hides the admin menu or redirects to the login page, but the API answers anyone.
3. **The role the web page sends is trusted**, for example the page keeps `role: "admin"` in the browser and sends it with requests, or uses a cookie `isAdmin=true`. Users can change these values themselves.
4. **Reading is checked, changing and deleting are not.** `GET` checks, but `POST`, `PUT` and `DELETE` on the same route do not.
5. **A check that a special word passes**, for example sessions kept in a plain JavaScript object and checked with `if (!sessions[token])`. A plain object already has names such as `constructor`. [MDN][mdn] says an object has a prototype, so it contains default keys that could collide with your own. Sending the token `constructor` passes the check without knowing any real token.

## Try it on the example first

You need Node.js and `curl`. The example is a team-notes API with the mistakes in this lesson. It runs only on your machine, the data is made up, and the tokens are random each time it starts. On Windows, run it in Git Bash.

In the first terminal:

```bash
git clone https://github.com/surapas3022/ai-secure-audit.git
node ai-secure-audit/examples/missing-login-check/server.mjs
```

You will see the tokens for alice, a regular member, and boss, an admin.

In a second terminal, first try without logging in:

```bash
curl http://127.0.0.1:4200/api/notes
curl http://127.0.0.1:4200/api/notes/export
```

The first gives `log in first`, as it should. The second gives every note as CSV without a login, because the export route was added later and nobody gave it a check (form 1).

Now send the token `constructor`:

```bash
curl -H "Authorization: Bearer constructor" http://127.0.0.1:4200/api/notes
curl -H "Authorization: Bearer constructor" http://127.0.0.1:4200/api/me
```

You get every note, and `/api/me` says your name is `Object`, because the app keeps sessions in a plain object (form 5).

Last, act as alice (put alice's token in place of `PASTE_TOKEN`):

```bash
TOKEN=PASTE_TOKEN
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:4200/api/admin/users
curl -H "Authorization: Bearer $TOKEN" -H "X-Role: admin" http://127.0.0.1:4200/api/admin/users
```

The first gives `admins only`, which looks safe. The second only adds the header `X-Role: admin` and gets everyone's names and emails, because the API trusts the role the web page sends (form 3).

Stop the server (Ctrl+C) and start the fixed version:

```bash
node ai-secure-audit/examples/missing-login-check/server.mjs --fixed
```

Put alice's new token in and run every command again. The export without a login and the `constructor` token both get `log in first`, and alice with `X-Role: admin` gets `admins only`. The code that differs is in `examples/missing-login-check/server.mjs`, on the lines marked `MISTAKE` and `FIXED`.

Run the tool on the example too:

```bash
node ai-secure-audit/bin/ai-secure-audit.js scan ai-secure-audit/examples/missing-login-check
```

The summary shows `1 high`. Open the `report.md` file at the path it prints: it points at the line in `server.mjs` that reads `if (!sessions[t])` as a session check on a plain object (version 0.0.9 and later). It says nothing about the export route or `X-Role`: a person has to try those.

## Why the tool catches only part of it

The tool does not know which routes are meant to be open to everyone, such as the home page or the sign-up page, and which need a login. That is a rule of your app. What it can catch is code that is wrong in any app, such as a session check on a plain object, so `npx ai-secure-audit` warns about that, and every report says that the rest of access control was not checked.

## Check your own app

Only test apps you own or have permission to test. Getting into someone else's system without permission may be illegal.

1. **List every API.** Ask an AI to go through the code (prompt below). Do not rely only on what the web page calls: a route without a button is still open.
2. **Open DevTools, Network tab, and use the app as usual**, once as an admin and once as a regular user. [Chrome's documentation][devtools] says this tab records all network activity (open DevTools first, then reload the page).
3. **Right-click a request and choose Copy as cURL.** Paste it in a terminal and try the table below. To try without a login, delete the `-H 'Cookie: ...'` or `-H 'Authorization: ...'` line.

| Try | You should get |
|---|---|
| Not logged in, call every API that is not meant for everyone | 401 for all of them, including exports, downloads and uploaded files |
| A regular account calls the admin APIs you noted in the admin run | 403 |
| A regular account changes the role or `isAdmin` value in the browser (DevTools, Application tab) or in the request | No effect: the system uses the role kept on the server |
| Change the method, such as `GET` to `DELETE` or `PUT` | 401 or 403 as well, if you are not allowed |
| Send the token or cookie `constructor`, `toString` or `__proto__` | 401 |
| Log out, then use the old token | 401 |

If you do not want to go through everything yourself, let an AI make the list first, but still try the table, because the AI can misread code.

> Make a table of every route in this project. For each, say whether it needs a login, whether it needs an admin, on which line that is checked, and where the role comes from (the server, or a value the web page sends). Point out any route with no check, or with a check only in the web page. Do not change anything yet.

## How to fix it

The one rule: **the backend checks every request itself, and denies by default.** The [OWASP Authorization Cheat Sheet][authz] says never to rely on checks in the web page. They may make the app nicer to use, but must never decide who gets in, because they are easy to bypass. The real check belongs on the server.

1. **Check the login in one place before every route, and open only the routes meant for everyone.** A route added later stays closed until someone opens it on purpose. [OWASP API5:2023][api5] recommends the same: deny all access by default, then grant it to specific roles.

   ```js
   // Every route needs a login, except the ones listed here.
   // sessions is a Map from token to user; req.cookies needs the cookie-parser package.
   const PUBLIC = new Set(['GET /', 'POST /api/login', 'POST /api/signup']);
   app.use((req, res, next) => {
     if (PUBLIC.has(`${req.method} ${req.path}`)) return next();
     const user = sessions.get(req.cookies.session);
     if (!user) return res.status(401).json({ error: 'log in first' });
     req.user = user;
     next();
   });
   // Routes go below this line, never above it.
   ```

2. **Take the role from the session on the server, not from the web page**, for example `if (req.user.role !== 'admin') return res.status(403)...`. Remove code that reads the role from a header, a cookie or data the web page sends.
3. **Keep sessions in a `Map` or a database, not a plain object.** [MDN][mdn] says a `Map` holds only the keys put into it, so it is safe with keys that users send. If you must use an object, make it with `Object.create(null)`.
4. **Check every method of the same route.** The middleware in step 1 covers them all.
5. **The web page may keep hiding buttons**, as a convenience, not as protection.
6. **Try the table again.**

## Prevent it next time

- **Tell the AI when you ask for the app**, for example: "Every API needs a login except the login and sign-up pages. Admin pages check the role on the backend from the session, never from a value the web page sends." AI follows rules it is given better than rules it has to guess.
- **Ask the AI for a test that calls every route without logging in**, expecting 401 everywhere except the routes meant to be open, and calls the admin APIs with a regular account, expecting 403. When a new route is added, the test warns if its check was forgotten. [The same cheat sheet][authz] also recommends tests for authorization.
- **Run `npx ai-secure-audit` before every release.** It catches a session check that a special word passes (version 0.0.9 and later).

## Related topics

- If the API checks the login but changing an id shows someone else's data, that is item 2, [Seeing or changing other people's data](02-other-users-data.en.md).
- If the web page talks to the database directly, as with Supabase or Firebase, the check has to be in the database rules. That is item 3 in the [checking order](README.en.md).
- A login route that allows unlimited password guesses: `npx ai-secure-audit` warns about it (version 0.0.5 and later, Express and NestJS).

## Limits of this kind of check

- You can only try the routes you know about, so let an AI go through the code, and remember that a route written and forgotten is still open.
- Apps with several roles, such as staff, manager and admin, need every pair tried, not only regular user and admin.
- The tool catches session checks on plain objects only in JavaScript/TypeScript in the Express style, and only when the store's name looks like sessions, tokens or admins.
- Passing once does not mean passing for good. The next new route may be forgotten again, so keep a test.

## Sources

Accessed 16 November 2026.

- [OWASP Top 10:2025 — A01:2025 Broken Access Control][owasp]
- [OWASP API Security Top 10 2023 — API5:2023 Broken Function Level Authorization][api5]
- [OWASP Cheat Sheet: Authorization][authz]
- [CWE-306: Missing Authentication for Critical Function][cwe306]
- [CWE-602: Client-Side Enforcement of Server-Side Security][cwe602]
- [Express: Writing middleware][express]
- [MDN: Map (section Objects vs. maps)][mdn]
- [Chrome DevTools: Inspect network activity][devtools]

[owasp]: https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/
[api5]: https://api-security.owasp.org/editions/2023/en/0xa5-broken-function-level-authorization
[authz]: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
[cwe306]: https://cwe.mitre.org/data/definitions/306.html
[cwe602]: https://cwe.mitre.org/data/definitions/602.html
[express]: https://expressjs.com/en/guide/writing-middleware.html
[mdn]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Map
[devtools]: https://developer.chrome.com/docs/devtools/network
