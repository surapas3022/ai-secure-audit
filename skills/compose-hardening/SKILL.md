---
name: compose-hardening
description: >-
  Checks or writes a Docker Compose deployment for a single host against a
  security checklist: published ports and host IP binding, network zones
  with internal networks, image pinning by digest, secrets and default
  passwords, non-root and read-only containers, capabilities, resource
  limits, Docker socket mounts, plus the host firewall and SSH. Use when
  reviewing or writing docker-compose files or Dockerfiles, deploying to a
  VPS, or when the user asks whether their Docker setup is safe.
---

# Compose hardening

Written for Docker Compose on one Linux VPS behind a reverse proxy. hadolint, trivy config and checkov check
Dockerfiles, but they do not check Compose files, so this checklist fills that gap.

## Procedure

1. Run `docker compose config` to get the resolved file (merges overrides and env). Do not print the result if it
   contains real secret values. Read the original files instead and note that env was not resolved.
2. Go through [references/checklist.md](references/checklist.md) service by service. Each failed item records the
   service, the key, the rule ID and the reference.
3. Draw the network zones (public / app / data) and check that only the reverse proxy is in the public zone.
4. For Dockerfiles referenced by `build:`, run hadolint and trivy config (from the profile), not your own rules.
5. When **writing** compose rather than reviewing it, apply the same checklist as defaults.

## Rules

- `ufw deny` does not prove a port is closed. Docker's published ports bypass ufw. Confirm from outside the host
  (nmap of your own public IP, listed in `.audit/targets.yml`) or with the cloud firewall.
- A finding about a password default (`${VAR:-secret}`) is confirmed even if production sets the variable. The
  default is in git.
