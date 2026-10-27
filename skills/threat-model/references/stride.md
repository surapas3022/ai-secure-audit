# STRIDE

From the OWASP Threat Modeling Cheat Sheet.

| Letter | Breaks | Ask at each boundary crossing | Example |
|---|---|---|---|
| **S**poofing | Authentication | Can someone pretend to be this caller? | stolen access token reused |
| **T**ampering | Integrity | Can the data be changed on the way or at rest? | price edited in the request |
| **R**epudiation | Accountability | Can we prove who did it? | no audit log for transfers |
| **I**nformation disclosure | Confidentiality | Can someone read what they should not? | `GET /orders/123` returns someone else's order |
| **D**enial of service | Availability | Can someone stop it working? | login flood locks accounts |
| **E**levation of privilege | Authorization | Can someone gain rights they should not have? | editing the `role` claim in a JWT |

Decisions: **Mitigate** (add a control), **Eliminate** (remove the feature or flow), **Transfer** (someone else carries
the risk, e.g. a payment provider), **Accept** (written down, with a reason and an owner).
