# Learn in order: what to check first in an app built with AI

[ภาษาไทย](README.md) | **English**

For people who build apps with AI and have never studied security. Read in order and fix one item at a time. Each topic has its own file. Item 1 is written; the others will be added one file at a time.

Not reading? Ask your AI assistant instead:

> Run `npx ai-secure-audit` in this project, explain the results in simple words, and help me fix the most serious ones first. Do not add or remove findings.

| Order | Topic | Why it is here | How to check today |
|---|---|---|---|
| 1 | [Leaked keys](01-key-leak.en.md) | Anyone who finds a key can use it at once, with no skill, and it can cost real money | `npx ai-secure-audit` |
| 2 | Seeing or changing other people's data | In some apps, changing a number in the URL shows someone else's data | A person checks; tools cannot catch all of it |
| 3 | Database rules left open (Supabase, Firebase) | Outsiders can read the database without going through your website | A person checks; the tool does not cover this yet |
| 4 | API with no login check, or a check only in the frontend | Calling the API directly skips the check | A person checks; the tool does not cover this yet |
| 5 | Libraries with known holes | The attack is often already published, but most fixes are just an update | The tool does not cover this yet |
| 6 | Unsafe Docker or server settings | Makes the damage spread further; only matters if you run your own server | The tool does not cover this yet |

This order is this project's judgement for beginners, based on how much damage each problem does and how easy it is to attack. It is not a ranking from a standard. The usual reference is the [OWASP Top 10:2025][owasp], which ranks risks for web apps overall: broken access control (our item 2) is first, security misconfiguration second, and software supply chain failures third.

The order shows where to start. It does not mean later items do not matter.

A result of "0 problems" does not mean the app is safe. It only means the tool found nothing among the things it can check.

[owasp]: https://top10.owasp.org/2025/
