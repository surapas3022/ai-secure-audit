---
name: authz-review
description: >-
  Reviews code for broken access control: object-level authorization
  (IDOR/BOLA, CWE-639), missing function-level guards on admin routes
  (CWE-862), property-level problems such as mass assignment, and open
  Supabase RLS or Firebase security rules; then writes cross-user tests that
  prove or disprove each candidate. Use when reviewing endpoints that take an
  id, adding protected routes, or when the user mentions IDOR, BOLA,
  ownership checks, "can user A see user B's data", RLS or Firebase rules.
---

# Authorization review

Scanners rarely find these problems, because a scanner cannot tell whose data a record is. This skill reads the code,
proposes candidates, and turns each one into a test that a person can run and check.

## Procedure

1. **Detect the stack** and read only the matching file in [references/stacks/](references/stacks/). If none matches,
   use [references/checks.md](references/checks.md) alone.
2. **List the endpoints** that read or change user-owned data or admin-only data. Reuse `.audit/inventory.md` if it
   exists. For each one record: method, path, `file:line` of the handler, and whether authentication is required.
3. **Check each endpoint** against [references/checks.md](references/checks.md): object ownership, function-level guard,
   property allowlist, and list filtering.
4. **Record candidates**, not findings: `file:line`, which check failed, and why you think so.
5. **Write cross-user tests** in the project's own test framework: create user A and user B (and an admin if relevant),
   then have B call A's resources. A test that gets data or a 2xx where it should get 403/404 confirms the candidate.
6. **Run the tests locally or on dev only.** Never on prod.
7. **Hand over** to [finding-triage](../finding-triage/SKILL.md): confirmed candidates take the failing test as evidence.
   Candidates you could not test stay "needs a person".

## Rules

- A candidate is only a finding once a test fails or a person confirms it from the code.
- Hiding a button in the UI is not authorization. Check the server.
- A check in the controller, a guard, or the database (RLS) all count. Find where it actually happens before calling
  something missing.
- Keep the tests in the project afterwards. They are the retest for phase 8.
