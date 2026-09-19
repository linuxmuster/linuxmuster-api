# 🚀 Release Notes – linuxmuster-api 7.4

**Package version:** 7.4.1 – 7.4.13

---

## 📋 Overview

Version 7.4 turns linuxmuster-api into the real integration point for
operations that used to be handled by shell-outs from the webui or the CLI:
LINBO remote control, LINBO image and `start.conf` management, password
management and management-group membership are now exposed as proper, role-
and school-scoped HTTP endpoints backed by `linuxmuster-tools`. Background
sophomorix jobs gained completion notifications, host keys can be narrowed to
a list of endpoints, and a long series of school-scoping bugs was fixed along
the way.

---

## 🖥️ LINBO endpoints

- Raw `start.conf` write/delete endpoints. The `startconfs` and `configs`
  routes no longer take a `school` parameter: `group_id` addresses one
  server-wide set of files and the parameter was only validated, never used.
- Host state and boot logs over HTTP: `POST /linbo/hosts/scan`,
  `POST /linbo/wol`, `GET /linbo/hosts/image-status`,
  `GET`/`DELETE /linbo/boot-logs[/{filename}]` (closes #29, thanks
  @TomlDev). `scan_hosts` now probes hosts concurrently via `asyncio`
  instead of blocking the event loop, and no longer returns `lastSeen` —
  the field held the time of the scan itself, not a last-seen date.
- New dedicated `/linbo/sync` router: `POST /linbo/sync/run`,
  `GET /linbo/sync/sessions`, `GET /linbo/sync/sessions/{hostname}/log`,
  `GET /linbo/sync/hosts/{hostname}/status` — open to school-administrators
  scoped to their own school, unrestricted for global-administrators
  (closes #32, thanks @TomlDev).
- Image management routed: 9 endpoints under `/v1/linbo/images` (list,
  backups, delete, delete diff, delete backup, restore backup, rename,
  duplicate, extras). Images could until now be uploaded and downloaded via
  the API but never managed. An unknown group is resolved to 404 instead of a
  silent 200; an image with an unreadable `.info` is reported 409 instead of
  crashing on `AttributeError`. This picks up PR #33 from @TomlDev, closed
  without merging and reimplemented directly.
- New endpoint listing the LINBO groups (closes #35), and one returning the
  last LINBO status of a given device.
- Three routes for a group's VDI config, read, written and deleted at
  `/v1/linbo/startconfs/{group_id}/vdi` — not to be confused with an image's
  `.vdi` sidecar (closes #38, reported by @TomlDev).
- The `start.conf` backups the server already keeps are exposed: list,
  restore and delete under `/v1/linbo/startconfs/{group_id}/backups`. A
  restore backs the current file up before overwriting it (closes #39,
  reported by @TomlDev).
- `GET /v1/linbo/iso` downloads `linbo.iso`, `GET /v1/linbo/examples` lists
  the example configs shipped with the server and `/v1/linbo/examples/{name}`
  returns one of them (see #39).
- School-administrators now reach the LINBO routes, which were global-admin
  only while the Schulkonsole has always granted them the same access. Routes
  acting on machines (wol, boot logs) are filtered to the school of the
  caller through `devices.csv`; the ones reading `/srv/linbo` address a flat,
  server-wide set of files and each dangerous endpoint says so in its
  description. Per-school LINBO files are the real fix and are planned
  separately. Only `/server-info` stays global-admin only (closes #37,
  reported by @TomlDev).

---

## 🔑 Password management

- Domain-wide password-policy and password-constraints endpoints, scoped by
  role (school-admin vs global-admin); new/current passwords are checked
  against the configured policy on set.
- `POST /v1/users/{user}/set-random-first-password`; omitting `password` in
  `set-first-password` now resets to the existing first password instead of
  requiring a new one; current-password changes now go through
  `LMNUser.set_actual_password()`.

---

## 👥 Groups, printers and roles

- New endpoints for `lmngroups`, including custom fields.
- Management-group membership now goes through `GroupManager` (batch,
  proper error reporting) instead of `LMNMgmtGroup` (per-member loop, only
  warning on an unknown user), scoped via `@require_school`.
- `PATCH /v1/printers/{printer}` was rewriting attributes a partial patch
  never sent: a patch adding a member also unhid the printer, made it
  joinable and reset its school to `default-school`. Only the attributes
  actually sent are written now.
- Removing the last member of a printer answered 500 (empty value refused by
  `setattr`) and an unknown name answered 500 (`None` used as a DN). Both are
  handled: the member list can be cleared, and an unknown name is refused
  with a 404 naming it, the whole patch being rejected. An exam account is
  refused with a 400 saying so, instead of a "not found" for an account which
  does exist.
- Printer members are applied through one targeted LDAP modify, so adding
  users and groups in the same operation no longer loses one of the two
  (reported by @ebert). The caller's school is passed to the writer
  (multischool).
- `GET /v1/roles/{role}` is scoped to the caller's school: a
  school-administrator can no longer read the users of another school, and an
  empty `school` parameter no longer widens the query to every school. Global
  roles, which are read unfiltered, are restricted to global-administrators
  (reported by the edulution-ui team).
- `GET /v1/devices/roles` lists the computer roles configured in
  `sophomorix.ini`'s `[computerrole.*]` sections, until now hardcoded
  client-side (merge of PR #34, @TomlDev).
- `cn` added to the user list (merge of PR #40, @JanHolger).

---

## ⏳ Background jobs

- `sophomorix-check` now runs as a background job like `sophomorix-apply`
  already did, polled via
  `GET /listmanagement/sophomorix-jobs/status/{pid}` (also fixes `-jj`'s
  JSON output being written to stderr and never captured).
- Configurable webhook notification when a background sophomorix job
  completes: HMAC-SHA256-signed POST, timestamp mixed into the signature to
  prevent replay, silent no-op without a configured `callback_url`.

---

## 🔒 Security and hardening

- A host key can be restricted to a list of endpoints with a new optional
  `scope` in its `host_keys` entry. Without one, nothing changes: the key
  keeps reaching the whole API with the LDAP role of its user. A scope only
  ever narrows, the role is still checked behind it. Entries read
  `"<METHOD> <path>"` and are matched against the path as it appears on the
  wire, without the `/v1` prefix, with `*` for one path segment and `**` for
  the rest of the path. An entry matching no route of the API is logged as a
  warning at startup and never allows anything.
- The rate limit of `GET /v1/auth/` is configurable through a new
  `rate_limit` section (requests, window, whitelist) instead of being fixed
  at 5 requests per 60 s. The counter stays per client address, which a
  front-end signing all its users in from one address would spend on the
  first few of them: such an address can now be whitelisted. Setting
  `requests` to 0 or less disables the limiter. Callers on the host itself
  are still never counted (closes #41, reported by @Pasemesan).
- School-scoping fixes across several endpoints: required `school` for
  global-administrators, school-administrators restricted to their own
  school (closes #22, #23, #24, #26). Both
  `/v1/listmanagement/{school}/{mgmtlist}` routes are scoped to the caller's
  school as well — a school-administrator could read and, above all,
  overwrite the management CSV of another school. `require_school()` now
  treats an empty school as absent and derives it from the caller's token.
- `check_user_header()`, `check_host_header()` and `BasicAuthChecker`
  (`GET /v1/auth/`) catch `linuxmusterTools.common.LdapNotProvisionedError`
  and return a 503 "linuxmuster is not provisioned yet" instead of a raw 500
  or a misleading 400 "Malformated username" on a fresh install where Samba
  hasn't been provisioned yet.
- Local requests (webui on the same host) exempted from the rate limiter.

---

## 📦 Packaging and tests

- postinst: the deprecated venv migration is dropped, and a new
  `linuxmuster-venv` dpkg trigger reinstalls the API requirements when
  `linuxmuster-tools7` rebuilds the shared venv after a Python upgrade.
- `make test` seeds `pytests/credentials.py` from the sample file on a clean
  checkout (closes #28, #30, thanks @TomlDev). New `pytests/test_header.py`
  and `pytests/test_basic_auth.py`, mocking the LDAP layer directly (no
  `TestClient` needed).

---

## ⚠️ Upgrade notes

- `POST /linbo/hosts/scan` no longer returns a `lastSeen` field. Tracking
  last reachability is up to the caller.
- The `startconfs` and `configs` routes no longer accept a `school`
  parameter.
- Existing host keys keep working unchanged: the new `scope` is optional, and
  an absent one means the previous behaviour.

---

Author: Arnaud Kientz
Co-Author: Claude
