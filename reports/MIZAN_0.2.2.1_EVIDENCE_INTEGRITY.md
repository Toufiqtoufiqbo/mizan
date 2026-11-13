# Mīzān 0.2.2.1 — Evidence Integrity and Reproduction Correctness

**Scope:** Phase 2 of the 0.2.2.1 mission.

A finding is not trustworthy because the engine detected something. It is
trustworthy because the recorded reproduction **is** the request that was
transmitted, and replaying it reproduces the behaviour.

---

## 1. Defect A — the write probe recorded the wrong body

### What happened

`_probe_write_authorization` sends a **perturbed** body, so that the write is
visible in the data (a write that changes nothing produces no diff):

```python
probe_body = _perturb(body)          # the payload that is actually sent
response = self._request(session, method, url, json=probe_body, ...)
```

but the recorded step used the original:

```python
Step(
    method=method,
    url=url,
    body=body,  # <-- the original, not what was sent
    status=response.status_code,
    note="cross-identity write",
)
```

### Consequence

The proof bundle claimed to reproduce a request that was never sent. Replaying
it would have sent `{"status": "paid"}` where the attack had sent
`{"status": "mizan-probe-status"}`. For a server that validates the body, the
replay would have failed - or, worse, succeeded for a different reason.

### The fix

```python
body = (probe_body,)
```

### The corrected reproduction

Before:

```json
{
  "method": "PUT",
  "url": "http://127.0.0.1:8000/orders/ord-1",
  "body": { "status": "paid" },
  "note": "cross-identity write"
}
```

After:

```json
{
  "method": "PUT",
  "url": "http://127.0.0.1:8000/orders/ord-1",
  "body": { "status": "mizan-probe-status" },
  "note": "cross-identity write"
}
```

The test `test_the_write_finding_records_the_body_that_was_sent` asserts that
the recorded body carries the probe marker, i.e. that it is the payload the
application received.

## 2. Defect B — the read probe could record the wrong method

### What happened

The read probe iterated the traffic records and used the record's method in the
evidence, while the request it sent was always a `GET`:

```python
for record in records:
    ...
    response = self._request(session, "GET", url, ...)   # always a GET
    ...
    Step(method=method, ...)                              # the traffic's method
```

A traffic log that contains a `HEAD` record therefore produced an evidence
that claimed `HEAD` for a request that was transmitted as `GET`.

### The fix

A single constant is used for both the request and the evidence:

```python
READ_METHOD = "GET"
...
response = self._request(session, READ_METHOD, url, timeout=self.target.timeout)
...
Step(method=READ_METHOD, ...)
```

The test `test_the_read_probe_records_the_method_it_sent` checks the constant
and that the probe sends it.

## 3. Defect C — the owner check was too weak

### What happened

The gate proved that *at least one* finding had an owner:

```python
owners = [...]
assert any(owners), "no finding says who owns the affected object"
```

A finding without an owner passed as long as another finding had one.

### The fix

`mizan.validation.validate_finding()` checks **every** finding, one by one:

| Checked | Rule |
|---|---|
| the law identifier | present and shaped like `L<number>` |
| the principal | present |
| the action | present |
| the resource | present |
| the method | present in the first reproduction step |
| the endpoint | present in the first reproduction step |
| the response status | present in the step |
| the evidence | not empty |
| the reproduction | at least one step |
| the owner (`L2`, `L3`) | explicit, and **different from the attacking principal** |
| the evidence structure | the owner is found in the evidence or in the nested event |

A finding that cannot be validated is **not** reported as a finding: it fails
the gate. No evidence is invented to make it pass.

## 4. Defect D — replay fidelity was untested

### What happened

No test proved that a generated bundle reproduces the behaviour it claims.

### The fix

`tests/test_evidence_integrity.py::test_a_bundle_replays_the_exact_request`
runs the whole chain against the independent Flask application:

1. the application is started (the vulnerable variant);
2. Mīzān scans it and produces an `L2` finding;
3. the finding is written as a proof bundle;
4. the bundle is **replayed against the same application** - the recorded
   request verbatim: same method, same path, same body, and the token
   placeholder resolved from the environment;
5. the replay must answer `200`, exactly as the original attack did.

The bundle is also checked to carry the placeholder
(`${MIZAN_TOKEN_BOB}`) and **not** the token itself.

A replay against a *different* instance was tried first and rejected: it
returned `404`, because a fresh application has different order identifiers.
That is not a defect of the replay - it is the reason the replay has to be
tested against the instance that produced the finding.

## 5. The evidence of a finding, after the fixes

| Element | L2 (read) | L3 (write) |
|---|---|---|
| law | `L2` | `L3` |
| principal | the attacker | the attacker |
| action | `read` | `write` |
| resource | `orders:ord-...` | `orders:1` |
| method | `GET` (the method sent) | `PUT` (the method sent) |
| endpoint | the full URL | the full URL |
| body | - | **the body that was sent** |
| owner | from the response | from the database row |
| evidence | status, owner, returned owner, the object | the write event: table, row, columns, owner |
| reproduction | one step with the exact request | one step with the exact request |
| token | a placeholder, never the secret | a placeholder, never the secret |

## 6. Tests

| Test | What it proves |
|---|---|
| `test_the_read_probe_records_the_method_it_sent` | the evidence never names a method that was not transmitted |
| `test_every_finding_is_complete` | every finding passes the eleven checks of `validate_finding` |
| `test_the_owner_differs_from_the_attacker` | the owner is explicit and is not the attacker |
| `test_the_write_finding_records_the_body_that_was_sent` | the recorded body is the perturbed payload |
| `test_the_read_finding_records_a_get` | the read evidence names `GET` |
| `test_a_bundle_replays_the_exact_request` | the bundle reproduces the behaviour, and carries no secret |

All six pass on this machine (Windows 10 Pro, Python 3.12.10).
