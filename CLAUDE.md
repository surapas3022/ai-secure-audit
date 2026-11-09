# Working on this repository

## Small steps, one tool per release

- Build in small pieces that each work on their own. Split large tasks.
- Enable and release **one scanner (or one rule) at a time**, and only after it passes its own tests: fixture test,
  a real project, and the other operating systems.
- During the 100-day challenge (8 Nov 2026 – 15 Feb 2027) the real project is a weekly app in the private repo
  `lab/apps/`, not a live product. A scanner may be prepared in the private `lab/` ahead of the clip date.
  It moves here only after that app run and the other-OS test. Posting dates stay on the content plan.
- Do not widen the scope of a change beyond what was asked without asking first.

## Rules that never change

- Every lesson in `learn/` has a Thai file (`name.md`) and an English file (`name.en.md`), with a language switch on top.
- Findings come only from the pinned tools; never invent, drop or re-rate them in code or docs.
- No runtime npm dependencies.
- No real scan results, reports or vulnerability details in this repository (they belong in the private repo).
- Commit messages end with the content. No trailers.
