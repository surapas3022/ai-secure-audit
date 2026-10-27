# Severity

## Tool severity

Keep whatever the tool reports. If it is a CVSS score, say which kind:

- CVSS v4.0 names: **CVSS-B** (Base only), CVSS-BT, CVSS-BE, **CVSS-BTE** (Base + Threat + Environmental)
- Scale: None 0.0 · Low 0.1–3.9 · Medium 4.0–6.9 · High 7.0–8.9 · Critical 9.0–10.0
- The Base score is how severe the flaw is in general, not the risk to this system. Dependency scanners usually report
  CVSS-B.

## Contextual severity: OWASP Risk Rating

`Risk = Likelihood × Impact`, each scored 0–9: 0 to <3 = LOW, 3 to <6 = MEDIUM, 6–9 = HIGH.

| Impact \ Likelihood | LOW | MEDIUM | HIGH |
|---|---|---|---|
| **HIGH** | Medium | High | Critical |
| **MEDIUM** | Low | Medium | High |
| **LOW** | Note | Low | Medium |

Use business impact when it is known (money, personal data, downtime) instead of technical impact.

Questions that move likelihood: Is it reachable from the internet? Does it need login? Is there a public exploit?
Is the vulnerable code path actually called?
