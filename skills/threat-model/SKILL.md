---
name: threat-model
description: >-
  Builds a lightweight threat model for an app or service: a data flow
  diagram with trust boundaries, STRIDE threats for each boundary crossing,
  and a decision for each threat. Use when the user asks for a threat model,
  a data flow diagram, "what could go wrong" with a design, or during phase 3
  of an audit.
---

# Threat model

Follows OWASP's four questions (from the Threat Modeling Manifesto). It is sized for one person and about an hour.
No single process is the industry standard; this one is a short recipe.

## Procedure

1. **What are we working on?** Read the repo (compose files, routes, clients, external API calls) and draw a data
   flow diagram in Mermaid in `.audit/threat-model.md`, using
   [assets/threat-model.template.md](assets/threat-model.template.md). Include external entities, processes, data
   stores and the data flows between them. Mark the trust boundaries: internet ↔ proxy, proxy ↔ app, app ↔ database,
   app ↔ third party.
2. **What can go wrong?** For each flow that crosses a boundary, go through STRIDE
   ([references/stride.md](references/stride.md)). Write concrete threats for this app, not generic ones.
3. **What are we going to do about it?** For each threat choose Mitigate, Eliminate, Transfer or Accept, and say where
   the control is (file, config, or "missing").
4. **Did we do a good enough job?** List what needs a person: whether the diagram matches production, and business
   threats the code cannot show (money, coupons, admin powers).

## Rules

- Mark everything inferred from code but not confirmed as `TODO(confirm)`.
- A threat is not a finding. Threats with a "missing" control become candidates for phase 5 manual review; they enter
  the report only after triage.
- If the app handles a lot of personal data, add LINDDUN privacy threats (OWASP Threat Modeling Cheat Sheet).
