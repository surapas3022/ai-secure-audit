# Threat model: <project>

Date: · Commit: · Reviewed by:

## 1. Data flow diagram

```mermaid
flowchart LR
  user([User / browser]) -->|HTTPS| proxy[Reverse proxy]
  subgraph app [App zone]
    api[API]
  end
  subgraph data [Data zone]
    db[(Database)]
  end
  proxy -->|HTTP| api
  api -->|SQL| db
  api -->|HTTPS| ext([Third-party API])
```

Trust boundaries: internet ↔ proxy · proxy ↔ app · app ↔ data · app ↔ third party

## 2. Threats

| ID | Flow | STRIDE | Threat | Decision | Control (where) |
|---|---|---|---|---|---|
| T-01 | user → proxy | S | | Mitigate | |

## 3. Needs a person

- [ ] Does the diagram match production?
- [ ] Business threats not visible in code:
