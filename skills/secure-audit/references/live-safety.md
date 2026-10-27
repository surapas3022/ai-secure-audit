# Testing a live system safely

Read this before any target with `env: prod`. Not legal advice.

## Passive vs active

NIST SP 800-115 §2.3: any test that interacts with a system can cause "unexpected system halts and other denial of
service conditions"; §6.3 says techniques likely to cause DoS belong on non-production systems.

| Generally acceptable on prod (once the ROE is written) | dev / staging only |
|---|---|
| testssl.sh with default options (not `--each-cipher`) | ZAP full scan; ZAP API scan without `-S` |
| nmap of your own IP with `-T2` or a low `--max-rate` | authenticated crawling that submits forms |
| ZAP baseline with a short spider (`-m`) | fuzzing |
| ZAP API scan with `-S` (safe mode) | brute-forcing logins |
| anything that reads only code, config or dependencies | load or stress tests |

Even ZAP baseline spiders follow links. A GET link that changes data (`/logout`, `/delete?id=`) will be clicked.

## Checklist before touching production

- [ ] `.audit/scope.md` has targets, exclude list, time window, allowed and forbidden techniques, stop conditions,
      contacts and data handling
- [ ] every target is confirmed to be ours; no third parties (payment, push, external APIs)
- [ ] the cloud provider's testing policy has been read for this round (e.g. AWS penetration testing policy)
- [ ] a fresh snapshot and database dump exist, and a restore has worked at least once
- [ ] logs and CPU/RAM/error rate are being watched during the test
- [ ] rate limits are set in the tools, not left to the server
- [ ] the people affected have been told; the window is a low-traffic time
- [ ] everyone knows who decides what to do if real data turns out to have leaked
- [ ] reports and screenshots contain no personal data or secrets, and are stored somewhere safe

## Law (Thailand, summary of unofficial translations)

- Computer Crime Act B.E. 2550 (amended 2560): s.5/s.7 unauthorised access to systems or data, s.9 damaging data,
  s.10 hindering a system. Scanning a system you do not own without written permission falls squarely here.
- s.13 concerns distributing a program "created specifically for" committing those offences. The kit refuses
  unlisted targets and states "authorised use only" for this reason. Ask a lawyer how far that protects you.
- PDPA B.E. 2562: s.22 collect only what is necessary (prove access with row counts or field names, not values);
  s.37(1) keep scan results secure; s.37(4) notify the regulator within 72 hours of becoming aware of a breach.
