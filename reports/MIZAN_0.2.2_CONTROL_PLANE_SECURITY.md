# Mīzān 0.2.2 — Control-Plane Security Review

**Scope:** Phase 2 of the 0.2.2 mission - `mizan.server` reviewed as an API
that could be exposed to other systems.

---

## 1. Authentication

### Before

The server issued and accepted the tokens of `mizan.tokens.make_token()` - a
JWT-*shaped* value with a **hard-coded signature** (`mizan-signature`). The
signature was never verified: the server looked the token up in a table. So the
"signature" bought nothing, and every deployment that copied the helper shipped
predictable credentials. `make_token("root", "admin")` was a valid credential
anywhere.

### After

- `mizan.server.DevAuth` issues **opaque random tokens**
  (`secrets.token_urlsafe(32)`) - not JWTs, not predictable.
- Only the **hash** of a token is stored (`sha256`); the plain token is
  returned once and never written down.
- **There is no default credential.** The users are injected explicitly:
  `MIZAN_SERVER_USERS=alice=secret,root=secret:admin`. With the variable
  unset, the server has no users and every protected endpoint answers `401`.
- A token in the environment is never printed: the CLI and the reports print
  `masked()` values only.
- The module docstring says plainly that this is a **development** mechanism,
  not a production identity provider. No attempt is made to look like one.

### Residual risk (documented, not fixed)

`DevAuth` has no expiry, no rotation and no revocation beyond restarting the
process. That is acceptable for a development control plane and **not**
acceptable in production. The limitation is stated in the module docstring and
here.

## 2. Request validation

### Before

Pydantic's default is to **ignore** unknown fields. A client could send
`owner_id`, `status` or `findings` and the server would quietly drop them. A
dropped field is a near miss: the API looks strict while it is not.

### After

All request models derive from `StrictModel`, which sets
`ConfigDict(extra="forbid")`:

- `POST /scans` rejects `owner_id`, `status`, `findings` and anything else
  with `422`.
- `POST /scans/{id}/findings` rejects unknown fields, and its `law`,
  `title` and `severity` have patterns and length limits.
- The body size is capped by the server (`MAX_BODY_BYTES`).

A test asserts that the rejected request created **nothing at all**, and that a
valid request produces a scan that belongs to the caller.

## 3. Authorization

The ownership boundary is tested end to end:

| Case | Expected |
|---|---|
| alice reads her own scan | 200 |
| bob reads alice's scan | **404** (not 403: the existence is not the caller's business) |
| bob reads alice's findings | 404 / empty |
| bob retrieves alice's bundle | 404 |
| bob submits a finding to alice's scan | 404 |
| a caller changes the ownership | impossible: there is no ownership field |
| an unauthenticated caller | 401 |

The bundle endpoint now serves the **real** bundle from disk (`replay.json`),
scoped to the owner. It used to answer `501` while the documentation implied it
worked.

## 4. Target restrictions and SSRF

The server makes the requests, so an unrestricted target turns it into a proxy
for internal services. `validate_target()` now checks:

| Check | Example that is refused |
|---|---|
| the scheme | `file:///etc/passwd` |
| the host | `http://169.254.169.254/latest/meta-data/` |
| credentials in the URL | `http://user:pass@127.0.0.1:8000/x` |
| the port | when `MIZAN_ALLOWED_TARGET_PORTS` is set |
| a malformed URL | `not-a-url` |

The default allow-list is `127.0.0.1,localhost` - **local only**. The tests
never touch a cloud metadata service, a private network or an external host.

## 5. Truthful behaviour

The scan endpoint **queues a record and returns `201`** - it does not run a
scan. That was implicit before; it is now stated in the docstring and in the
API description: the control plane records the request and the *engine* runs the
scan (through `mizan twin`, the CLI). The bundle endpoint serves real files.

There is no simulated worker and no faked success: a queued scan says `queued`,
and the findings of a scan only appear when a scan really ran.

## 6. What is still missing

| Gap | Status |
|---|---|
| the scan endpoint does not execute a scan | **known limitation**, documented - the engine runs it from the CLI |
| no rate limiting | not implemented |
| no audit log of the control plane's own actions | not implemented |
| no TLS | the server is meant to sit behind a proxy that terminates TLS |
| `DevAuth` has no expiry or rotation | documented; it is a development mechanism |

## 7. Summary

| Area | Before | After |
|---|---|---|
| credentials | predictable, hard-coded signature | random, opaque, hashed, injected explicitly, no default |
| unknown fields | silently ignored | rejected with `422` |
| authorization | partially scoped | fully scoped, 404 across the boundary |
| SSRF | a host check only | scheme, host, port, credentials in the URL |
| the bundle endpoint | `501` | serves the real bundle |
| the scan endpoint | implied to scan | documented as a queue |
