# Mīzān 0.2.2.1 — Control-Plane and SARIF Audit

**Scope:** Phase 6 of the 0.2.2.1 mission - the claims must match the
implementation.

---

## 1. The control plane

### 1.1 Tokens and authentication

| Property | State | Evidence |
|---|---|---|
| the token is opaque and random | yes | `DevAuth.issue()` uses `secrets.token_urlsafe(32)` |
| only the hash is stored | yes | `Store.ensure_user()` writes `hash_token(token)` |
| there is no default credential | yes | the users come from `MIZAN_SERVER_USERS`; without it there are no users and every protected endpoint answers `401` |
| a token is never printed | yes | the CLI and the reports print `masked()` values |
| the signature is not verified | **documented** | the tokens are not JWTs; the server compares hashes. This is a development mechanism, and the module says so. |

`test_the_control_plane_stores_no_plaintext_token` reads the database and
asserts that the stored value is not the token.

### 1.2 Strict request models

Every request model derives from `StrictModel` (`extra="forbid"`). A request
that carries `owner_id`, `id`, `status` or `findings` is rejected with `422`.
`test_an_unknown_field_in_a_finding_is_rejected` proves it.

### 1.3 Ownership isolation

| Resource | Another user |
|---|---|
| the scan | 404 |
| the findings | 404 |
| the proof bundle | 404 |

`test_the_bundle_of_another_user_is_not_served` proves the bundle case.

### 1.4 The bundle endpoint and path traversal

The endpoint builds a path from the scan id. It now resolves the path and
checks that it stays inside the configured root:

```python
root = Path(app.state.bundle_root).resolve()
directory = (root / scan_id).resolve()
if root != directory and root not in directory.parents:
    raise HTTPException(status_code=404, detail="no bundle for this scan")
```

`test_the_bundle_endpoint_does_not_escape_its_root` tries
`..%2F..%2Fsecret` and asserts that nothing outside the root is served.

### 1.5 Target validation

| Check | Status |
|---|---|
| the scheme | http/https only |
| the host | an allow-list; the default is `127.0.0.1,localhost` |
| credentials in the URL | refused |
| the port | an allow-list, when one is configured |
| a malformed URL | refused |
| the bracketed IPv6 form | understood (`[::1]` -> `::1`) |

**What is NOT covered, and is not claimed:** DNS resolution (a name that
resolves to a private address is not detected), redirects (the scanner does not
follow them today, and the proxy does not either), and the network boundary of
the machine the server runs on. The default is local-only, and that is what the
tests exercise.

### 1.6 Truthful behaviour

The scan endpoint **queues** a record; it does not run a scan. The response
says `queued`, the stored scan says `queued`, and the findings counter stays 0.
`test_a_queued_scan_is_not_claimed_to_be_running` pins that down.

The bundle endpoint serves the real `replay.json` from disk, scoped to the
owner.

## 2. SARIF

### 2.1 What the validator is

`mizan.sarif.validate_sarif()` is a **structural validator**, not a schema
validation. The docstring now says so, and a test asserts that the wording is
there:

```python
def test_the_validator_is_structural_and_says_so() -> None:
    assert "structure" in (sarif.validate_sarif.__doc__ or "").lower()
```

It checks: the version, the presence of `$schema`, at least one run, the tool
driver's name, that every result names a known rule, that every result has a
message, and that every level is a valid SARIF level.

**Not covered:** validation against the official JSON schema (the schema file is
not vendored in the repository, and the test suite does not download it).

### 2.2 The export

| Property | State |
|---|---|
| SARIF 2.1.0, with the official schema reference | yes |
| a stable rule identifier per law | `MIZAN-L1` ... `MIZAN-L7` |
| the severities map onto the SARIF levels | `critical`/`high` -> `error`, `medium` -> `warning`, `low`/`info` -> `note`, unknown -> `warning` |
| the evidence travels as properties | yes |
| the principal and the resource are properties | yes |
| the reproduction is a property | yes |
| **no source locations are invented** | the `locations` key is absent |
| a missing or incomplete bundle | a warning, the bundle is skipped |
| a malformed bundle | a warning, never a crash |
| an unknown law | still produces a rule (`MIZAN-L9`) |
| **no secret is exported** | the token is a placeholder in the bundle, and the export carries the placeholder |

`test_the_export_contains_no_secret` writes a bundle with an
`Authorization: Bearer ${MIZAN_TOKEN_ALICE}` header and asserts that the
export contains no JWT-like value.

### 2.3 Tests

| Test | What it proves |
|---|---|
| `test_the_validator_is_structural_and_says_so` | the claim matches the implementation |
| `test_the_export_contains_no_secret` | no credential leaves the tool |
| `test_the_severity_mapping` | the four severity mappings |
| `test_the_rule_identifiers_are_stable` | the identifiers do not change |
| `test_multiple_results_and_missing_evidence` | several results, and a finding without evidence |
| `test_an_unknown_law_still_produces_a_rule` | an unknown law does not break the export |

## 3. Claims that are explicitly **not** made

- The control plane is **not** a production identity provider.
- The target validation is **not** a complete SSRF defence: DNS, redirects and
  the network boundary are not covered.
- The scan endpoint does **not** execute a scan.
- The SARIF validation is **structural**, not a schema validation.
- The independent validation covers **one** external application, written by
  the author of the tool. It is a controlled fixture, not an external customer.
