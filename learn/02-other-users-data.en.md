# Item 2: Seeing or changing other people's data

[ภาษาไทย](02-other-users-data.md) | **English**

[Back to the checking order](README.en.md)

## Words used here

- **Authentication**: the system checks who you are, for example by logging in with an email and password.
- **Authorization**: the system checks whether you may do this to this piece of data, for example whether you may open this order.
- **Record**: one row of data in the database, such as one order or one person's profile.
- **id**: the number or code of each record, such as order `2`.
- **API**: the way the web page or mobile app asks the backend for data. `GET /api/orders/2` means "give me order 2".
- **Request**: one call to the API.
- **Token or session**: what the system gives you after you log in. It is sent with every request to say who you are.
- **Frontend**: code that runs in the user's browser. Anyone can read and change it.
- **Backend or server**: code that runs on your machine. Users cannot see it.
- **Owner**: the user a record belongs to.
- **BOLA / IDOR**: names for the problem in this lesson. BOLA stands for Broken Object Level Authorization and IDOR for Insecure Direct Object Reference. Both mean: change an id, reach someone else's data.
- **DevTools**: the browser's built-in tools. Open them with F12, or right-click and choose Inspect.

## What the problem is

The app checks that you are **logged in**, but not that the data you ask for is **yours**. You open your own order at `/api/orders/1`, change it to `/api/orders/2`, and see someone else's name, address and phone number. Some apps also let you edit or delete it.

No skill is needed, just a different number. [CWE-639][cwe] describes it as authorization that does not stop one user from reaching another user's data by changing the value that identifies the data.

## Why it is item 2

- The [OWASP Top 10:2025][owasp] puts "A01:2025 Broken Access Control" first among web app risks, and gives this exact example: viewing or editing someone else's account by sending its id.
- The [OWASP API Security Top 10 2023][api1] puts "API1:2023 Broken Object Level Authorization" first among API problems.
- Apps built with AI hit it often. We ask for "a page to see orders"; the AI makes it work, but if we never say "only your own", it often does not check.

It comes after item 1 because a tool cannot check it. A person has to try.

## Common shapes

1. **Changing the number in the link or the API**: `/orders/1` to `/orders/2`.
2. **The API trusts a userId sent by the page**, for example `GET /api/profile?userId=15` changed to 16, even though the backend already knows from the token who you are.
3. **The list sends everyone's data and lets the page filter it.** The screen shows only yours, but everything reached the browser. DevTools shows it.
4. **Viewing is limited to your own, but editing or deleting is not**, because the check was added to the view API and forgotten in edit and delete.
5. **Uploaded files**, such as receipts or ID card photos, open from a direct link with no owner check.

## Try it on an example first

You need Node.js and `curl`. The example is a fake shop with the mistake from this lesson. It runs only on your machine, all data is made up, and the tokens are new every time it starts. On Windows, use Git Bash.

In a first terminal:

```bash
git clone https://github.com/surapas3022/ai-secure-audit.git
node ai-secure-audit/examples/other-users-data/server.mjs
```

It prints tokens for alice and bob. alice owns orders 1 and 3; bob owns 2 and 4.

In a second terminal, act as alice (replace `paste-token` with alice's token):

```bash
TOKEN=paste-token
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:4100/api/orders/1
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:4100/api/orders/2
```

The first command returns alice's own order, as expected. The second returns bob's order, with his address and phone number, although alice is not the owner. Now change bob's address and look at the list:

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"address":"changed by alice"}' http://127.0.0.1:4100/api/orders/2
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:4100/api/orders
```

The change works, and the list has all 4 orders from both people. Without a token you get `log in first`. So this app **does authentication** but **does not check authorization**.

Stop the server (Ctrl+C) and start the fixed version:

```bash
node ai-secure-audit/examples/other-users-data/server.mjs --fixed
```

Tokens are new. Put alice's new token in and run the same commands. Order 2 now gives `order not found`, the edit fails, and the list has only alice's 2 orders. The difference is in `examples/other-users-data/server.mjs`, on the lines that mention `FIXED`.

## Why a tool cannot catch all of it

A tool does not know who order 2 belongs to. That is a rule of your business, not a fixed code pattern. That is why every `npx ai-secure-audit` report says this was not checked. What works is a person trying with two accounts.

## Check your own app

Only test apps you own or have permission to test. Opening data in someone else's system without permission may be against the law.

1. **Make two accounts**, A and B. Use two different browsers, or a normal window and a private window.
2. **With account A, create every kind of data the app has**: orders, profile, uploaded files.
3. **Open the Network tab in DevTools and use the app normally.** The [Chrome docs][devtools] say this panel logs all network activity (open DevTools first, then reload the page). Note which requests carry a record id: in the link, in `?id=`, or in the data sent.
4. **Try those links or requests as account B.** Paste the link into B's browser, or right-click the request, choose Copy as cURL, and swap in B's token.
5. **Try every action, not just viewing.**

| Try | Should get |
|---|---|
| B opens A's data | nothing (for example 404) |
| B edits A's data | cannot edit |
| B deletes A's data | cannot delete |
| B opens a list page | the data in Network has only B's records |
| B opens a file A uploaded | cannot open |
| Logged out, open the same link | asked to log in |
| Change a `userId` the page sends to A's | the system ignores it and uses whoever is logged in |

If you do not want to do it all by hand, have the AI read the code first, but still test with two accounts every time, because the AI can miss things.

> Go through every API in this project that takes an id from the web page: view, edit, delete, lists and files. For each one, say whether it checks that the record belongs to the logged-in user, and on which line. List the ones that do not check first. Do not fix anything yet.

## How to fix it

One rule: **the backend checks that the record belongs to the logged-in user, on every request.** The [OWASP IDOR cheat sheet][idor] says to check access for every object a user asks for, every time it is accessed.

1. **Take who is asking from the token, not from what the page sends.** Remove any `userId` the API accepts from the page and use the user from the token instead.
2. **Put the owner in the lookup itself**, instead of looking up by id alone.

   ```js
   // Mistake: finds the order by id only
   db.query('SELECT * FROM orders WHERE id = ?', [req.params.id]);

   // Fixed: the order must also belong to the logged-in user
   db.query('SELECT * FROM orders WHERE id = ? AND owner_id = ?', [req.params.id, req.user.id]);
   ```

   If nothing is found, answer as if the record does not exist, for example with 404. The [same cheat sheet][idor] suggests giving the same answer whether the record is missing or not yours, so outsiders cannot tell that the number exists.
3. **Do it in every API that touches the record**: view, edit, delete, download, export, and lists, which must be filtered on the backend instead of sending everything and filtering in the page.
4. **Deny by default.** The [OWASP authorization cheat sheet][authz] says an app should deny access by default and never rely on checks in the frontend.
5. **Long random ids help, but are not enough.** [OWASP API1:2023][api1] recommends random, hard-to-guess ids, but the [IDOR cheat sheet][idor] stresses that access checks are still essential, because ids leak, for example in shared links.
6. **Test with two accounts again**, using the table above.

## Stop it before it happens

- **Tell the AI when you ask for the feature**, for example: "Users can view, edit and delete only their own data. Check it on the backend in every API." The AI follows rules it is told better than rules it has to guess.
- **Ask the AI to write a test with two accounts**: B tries to open, edit and delete A's data and must fail. When the code changes later, the test warns you if the check disappears.
- **Keep the check in one place**, such as one lookup function that always adds the owner condition, instead of checks scattered everywhere and forgotten in one spot.

## Related items

- If the web page talks to the database directly, as with Supabase or Firebase, the owner check has to live in the database rules. That is item 3 in the [checking order](README.en.md).
- If an API does not even check that you are logged in, or checks only in the page, that is item 4.

## Limits of this kind of check

- You can only try the requests you see. An API the page never calls but that is still open will be missed; have the AI read the code too.
- Apps with several roles, such as staff and managers, need every pair tested, not just two accounts of the same role.
- Passing today does not mean passing forever. The next code change can drop the check, which is why a test matters.

## Sources

Accessed 10 November 2026

- [OWASP Top 10:2025 — A01:2025 Broken Access Control][owasp]
- [OWASP API Security Top 10 2023 — API1:2023 Broken Object Level Authorization][api1]
- [OWASP Cheat Sheet: Insecure Direct Object Reference Prevention][idor]
- [OWASP Cheat Sheet: Authorization][authz]
- [CWE-639: Authorization Bypass Through User-Controlled Key][cwe]
- [Chrome DevTools: Inspect network activity][devtools]

[owasp]: https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/
[api1]: https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization
[idor]: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
[authz]: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
[cwe]: https://cwe.mitre.org/data/definitions/639.html
[devtools]: https://developer.chrome.com/docs/devtools/network
