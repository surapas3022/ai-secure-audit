# Authorization checks

Standards: ASVS 5.0 V8 · OWASP API Security Top 10 2023 API1, API3, API5 · CWE-639, CWE-862, CWE-915.

| Check | Fails when | Typical evidence | Map to |
|---|---|---|---|
| Object ownership | the handler loads a record by id from the request and never compares its owner or tenant with the caller | `findById(params.id)` with no `userId` / `tenantId` condition | API1, CWE-639 |
| List filtering | a list endpoint returns every row, or filters only by a query parameter the client controls | `?userId=` taken from the query instead of the token | API1, CWE-639 |
| Function-level guard | an admin or staff route has no role or permission check on the server | a route without a guard decorator or middleware that its siblings have | API5, CWE-862 |
| Property allowlist | the request body is written straight to the model, so the client can set `role`, `balance`, `ownerId`, `isVerified` | spreading `req.body` into an update; a DTO without an allowlist | API3, CWE-915 |
| Response filtering | the response includes fields the caller should not see (password hash, other users' email) | returning the whole entity | API3 |
| Database rules | row-level security is off, or rules allow every read or write | Supabase table without RLS; Firebase `allow read, write: if true` | API1 |
| Identity source | the user id comes from the body, query or header instead of the verified token | `body.userId` used for the ownership check | API1 |

## Cross-user test pattern

```text
given  user A owns resource R
when   user B requests  GET / PATCH / DELETE  R
then   expect 403 or 404, and R is unchanged

when   a normal user calls an admin route      → expect 403
when   user B sends { "role": "admin" } in a profile update → role is unchanged
```
