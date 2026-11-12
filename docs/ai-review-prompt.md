# Review with your AI assistant

Use this when the check cannot cover your project: the report says a language has no code rules yet (for example
PHP, Go, Python, `.vue` files), or you want the things no scanner can judge, such as whether one user can open
another user's data.

The scanners in `npx ai-secure-audit` give the same result every run. This prompt does not: an AI reads the code, and
two runs can find different things. Treat what it reports as leads to check, not as findings, and run it again
after fixing.

How to use it: clone or open the project on your computer, start an AI assistant that can read local files (Claude
Code, Cursor, Codex) in that folder, and paste the prompt below. It works for any language. It asks for answers in plain Thai; change that word to your
language if you like.

```text
Review this web project for security problems before I let other people use it.

Project location: the current folder (the project is cloned on this computer).
Work only from the files and git history in this folder.
- If I give you a GitHub URL instead, clone it into a new empty folder first
  (public repositories only), then work from that folder.
- If the repository is private and not cloned, or you cannot read the folder,
  stop and tell me. Do not guess from a URL.

Check these 6 things one by one:

1. Secrets: Are there keys, passwords or tokens in the code, in committed files,
   or anywhere in git history? Run `git log --all --oneline -- .env` and scan
   the history for other secret files too.
2. Owner-only pages: Can someone who is not logged in, or who only knows the
   link, open admin pages, settings pages, or anything that deletes data?
3. Other people's data: If I change an ID or code in a link or request, can I
   see or edit someone else's data?
4. Trusting the browser: Are scores, prices, permissions or usage limits
   calculated or checked only in the browser instead of on the server?
5. Typed-in text: Is user-typed text shown back on a page without being
   escaped or filtered?
6. Unlimited repeats: Can someone spam a form, vote, sign-up or code request
   over and over without a limit?

Answer format:
- For each item write PASS / FAIL / CANNOT CHECK, with the file and line number.
- For each FAIL, explain in plain Thai what another person could do, then how
  to fix it.
- Order the items from most serious to least serious.
- For each item, say how much of the code you actually read (all of it, or a
  sample). Do not claim full coverage if you only checked some files.
- At the end, list what cannot be checked from code alone (server settings,
  live environment variables, cloud console settings).

Rules:
- Do not change code, delete files, or rewrite git history until I tell you to.
- Never print the value of any key or password you find. Say only which file
  and line it is in.
- If you find a secret in a public repository, tell me to rotate (replace) it
  first. Removing it from the repository is not enough.
- Do not send test requests to a website that is running live. Check only the
  code and the local copy.
- Do not upload my code or any secret to an outside service.
```

ภาษาไทย: ใช้เมื่อรายงานบอกว่าภาษาในโปรเจกต์ยังไม่มีกฎตรวจโค้ด หรืออยากให้ตรวจเรื่องที่เครื่องมือตัดสินไม่ได้ เช่น
เปลี่ยนเลขในลิงก์แล้วเห็นข้อมูลคนอื่นไหม เปิด AI ที่อ่านไฟล์ในเครื่องได้ในโฟลเดอร์โปรเจกต์ แล้ววางพรอมต์ด้านบน
AI จะตอบเป็นภาษาไทย ผลจาก AI รันแต่ละครั้งไม่เหมือนกัน ให้ถือเป็นจุดที่ต้องไปเช็กต่อ ไม่ใช่ผลตรวจที่ยืนยันแล้ว
