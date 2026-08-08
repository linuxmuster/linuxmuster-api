# Release Notes – linuxmuster-api 7.4

**Package version:** 7.4.1 – 7.4.8

---

## Overview

Version 7.4 turns linuxmuster-api into the real integration point for
operations that used to be handled by shell-outs from the webui or the CLI:
LINBO remote control, password management and management-group membership
are now exposed as proper, role- and school-scoped HTTP endpoints backed by
`linuxmuster-tools`. Background sophomorix jobs also gained completion
notifications, and several school-scoping and rate-limiting bugs were fixed
along the way.

---

## LINBO endpoints

- Raw `start.conf` write/delete endpoints.
- Host state and boot logs over HTTP: `POST /linbo/hosts/scan`,
  `POST /linbo/wol`, `GET /linbo/hosts/image-status`,
  `GET`/`DELETE /linbo/boot-logs[/{filename}]` (closes #29, thanks
  @TomlDev). `scan_hosts` now probes hosts concurrently via `asyncio`
  instead of blocking the event loop.
- New dedicated `/linbo/sync` router: `POST /linbo/sync/run`,
  `GET /linbo/sync/sessions`, `GET /linbo/sync/sessions/{hostname}/log`,
  `GET /linbo/sync/hosts/{hostname}/status` — open to school-administrators
  scoped to their own school, unrestricted for global-administrators
  (closes #32, thanks @TomlDev).

---

## Password management

- Domain-wide password-policy and password-constraints endpoints, scoped by
  role (school-admin vs global-admin); new/current passwords are checked
  against the configured policy on set.
- `POST /v1/users/{user}/set-random-first-password`; omitting `password` in
  `set-first-password` now resets to the existing first password instead of
  requiring a new one; current-password changes now go through
  `LMNUser.set_actual_password()`.

---

## Groups

- New endpoints for `lmngroups`, including custom fields.
- Management-group membership now goes through `GroupManager` (batch,
  proper error reporting) instead of `LMNMgmtGroup` (per-member loop, only
  warning on an unknown user), scoped via `@require_school`.

---

## Background jobs

- `sophomorix-check` now runs as a background job like `sophomorix-apply`
  already did, polled via
  `GET /listmanagement/sophomorix-jobs/status/{pid}` (also fixes `-jj`'s
  JSON output being written to stderr and never captured).
- Configurable webhook notification when a background sophomorix job
  completes: HMAC-SHA256-signed POST, timestamp mixed into the signature to
  prevent replay, silent no-op without a configured `callback_url`.

---

## Hardening

- School-scoping fixes across several endpoints: required `school` for
  global-administrators, school-administrators restricted to their own
  school (closes #22, #23, #24, #26).
- Local requests (webui on the same host) exempted from the rate limiter.
- Test infrastructure: `make test` seeds `pytests/credentials.py` from the
  sample file on a clean checkout (closes #28, #30, thanks @TomlDev).

---

Author: Arnaud Kientz
Co-Author: Claude
