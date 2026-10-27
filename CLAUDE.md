# Working on this repository

## Small steps, one tool per release

- Build in small pieces that each work on their own. Split large tasks.
- Enable and release **one scanner (or one rule) at a time**, and only after it passes its own tests: fixture test,
  a real project, and the other operating systems.
- Do not widen the scope of a change beyond what was asked without asking first.

## Rules that never change

- Findings come only from the pinned tools; never invent, drop or re-rate them in code or docs.
- No runtime npm dependencies.
- No real scan results, reports or vulnerability details in this repository (they belong in the private repo).
- Commit messages end with the content. No trailers.
