# Compose checklist

Sources: Docker docs (port publishing, packet filtering, networks, Compose spec), OWASP Docker Security Cheat Sheet
(RULE #n), NIST SP 800-190, CIS Docker Benchmark section numbers as used by Docker Bench for Security (CIS v1.6.0).
Numbers may differ in CIS 1.9.0.

## Ports and networks

| ID | Check | Fails when | Reference |
|---|---|---|---|
| CMP-001 | Ports bound to a specific host IP | `ports: ["5432:5432"]` with no host IP binds every interface, IPv4 and IPv6 | Docker docs; CIS 5.14 |
| CMP-002 | Only the reverse proxy publishes ports in prod | any other service has `ports:` | OWASP RULE #5a |
| CMP-003 | Databases and caches publish nothing | postgres / mysql / redis / mongo has `ports:` | NIST 800-190 §4.3.3 |
| CMP-004 | Data zone is isolated | DB is on the default network or shares a network with the proxy; data network lacks `internal: true` | NIST 800-190 §4.3.3, §4.4.2 |
| CMP-005 | No host networking | `network_mode: host` | OWASP RULE #5 |

## Images

| ID | Check | Fails when | Reference |
|---|---|---|---|
| CMP-010 | Image pinned by digest | no `@sha256:`, or tag is `latest` | Docker docs (tags are mutable); NIST 800-190 §4.2.2 |

## Secrets

| ID | Check | Fails when | Reference |
|---|---|---|---|
| CMP-020 | No default passwords | `${…:-value}` on a key whose name contains PASSWORD, SECRET, TOKEN or KEY | Compose interpolation; use `${VAR:?message}` |
| CMP-021 | No secrets in `command:` | e.g. `--requirepass ${REDIS_PASSWORD}` | visible in container config |
| CMP-022 | Env files not committed | `.env` or `secrets/*` not in `.gitignore` | NIST 800-190 §4.1.4 |

## Container privileges

| ID | Check | Fails when | Reference |
|---|---|---|---|
| CMP-030 | Not root | no `user:` and image runs as root (own images) | OWASP RULE #2; CIS 4.1 |
| CMP-031 | Read-only root filesystem | no `read_only: true` (own images) | OWASP RULE #8; CIS 5.13 |
| CMP-032 | Capabilities dropped | no `cap_drop: [ALL]` (own images) | OWASP RULE #3; CIS 5.4 |
| CMP-033 | No new privileges | no `security_opt: [no-new-privileges:true]` | OWASP RULE #4; CIS 5.26 |
| CMP-034 | Not privileged | `privileged: true` | OWASP RULE #3; CIS 5.5 |
| CMP-035 | Docker socket not mounted | `/var/run/docker.sock` in `volumes`, even `:ro` | OWASP RULE #1; CIS 5.32 |
| CMP-036 | Resource limits | no `mem_limit` / `pids_limit` | OWASP RULE #7; CIS 5.11, 5.29 |
| CMP-037 | Health check | a depended-on service has no `healthcheck:` | CIS 5.27 |

## Host (single VPS)

| ID | Check | Fails when | Reference |
|---|---|---|---|
| HST-001 | Cloud firewall limits SSH | port 22 open to every IP (IPv4 and IPv6 are set separately) | provider docs |
| HST-002 | SSH keys only | `PasswordAuthentication` or `KbdInteractiveAuthentication` not `no` (both default `yes`) | sshd_config |
| HST-003 | Security updates | unattended-upgrades off, or no plan for reboots (auto reboot defaults to off) | Ubuntu docs |
| HST-004 | Host audit | lynis `audit system` not run | — |
