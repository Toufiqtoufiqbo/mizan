# Mīzān 0.2.2 — Independent Application Validation

**Scope:** Phase 3 of the 0.2.2 mission - Mīzān against an application that
does not depend on Mīzān.

---

## 1. Why this phase exists

Until now Mīzān had only ever been pointed at **its own** control plane: its
own code, its own tokens, its own assumptions, its own author. That is a
comfortable test with an unknown result - a tool and its author share blind
spots.

The question this phase answers:

> Can Mīzān find a security defect in an application written by somebody else,
> against an application that has never heard of Mīzān?

## 2. The target

`tests/fixtures/external_apps/flask_store/` - a standalone Flask application.

| Property | How it is satisfied |
|---|---|
| An independent process | `python app.py --db ... --port ...` |
| Its own database | its own SQLite file, its own schema |
| Its own authentication | opaque random tokens in its own table, `secrets.token_urlsafe(32)`; **no JWT, no `mizan.tokens`** |
| Its own OpenAPI document | `openapi.json`, written by hand |
| Realistic resources | orders owned by users, with a lifecycle (create, list, read, update, delete) |
| No Mīzān internals | a test parses the imports and fails if any `mizan` module is imported |
| Reachable the documented way | ordinary HTTP; the database file is used for attribution, exactly as for any application |

Identities: `alice` and `bob` (ordinary users) and `root` (privileged).

Rules in the clean variant:

- a caller may only read, change and delete **their own** orders;
- an administrator may act on any order;
- a listing shows only the caller's orders;
- a request for somebody else's order answers `403` (and `404` when the object
  does not exist at all).

The vulnerable variant (`STORE_VULNERABLE=1`) removes exactly one thing: the
ownership check. Everything else - the authentication, the validation, the
database - is the same code.

## 3. How the scan works

```
start the application  ->  log in as alice, bob, root (the application issues
                            the tokens)  ->  learn from the application's own
                            OpenAPI document  ->  record the traffic through
                            the proxy  ->  attribute the writes from the
                            database  ->  attack
```

Nothing about the application is assumed: Mīzān reads the specification, uses
the tokens the application issued, and finds the write evidence in the
database file.

## 4. Result

| Variant | Findings | Law types | Requests | Error |
|---|---|---|---|---|
| clean | **0** | `[]` | 4 | none |
| vulnerable | **3** | `[L2, L3]` | 6 | none |

The findings on the vulnerable variant:

| Law | Finding | Principal | Resource |
|---|---|---|---|
| L2 | alice read an object owned by root | alice | `orders:ord-...` |
| L2 | bob read an object owned by root | bob | `orders:ord-...` |
| L3 | alice wrote into an object owned by root | alice | `orders:1` |

Every finding carries a principal, an endpoint, a method, a resource, the owner
and a reproduction step - the gate checks each of them.

## 5. What the independent target found in the engine

This is the real value of the phase. Six defects in Mīzān's own engine were
only visible against an application that does not share Mīzān's assumptions:

| # | Defect | Consequence |
|---|---|---|
| 1 | **Opaque tokens carried no identity.** Mīzān could only identify a request by decoding a JWT. | against any application with ordinary session tokens, Mīzān was **completely blind** - it did not know who owned what |
| 2 | The write attribution had the same problem. | no write could be attributed to anybody, so no cross-identity write could ever be found |
| 3 | **The learning phase destroyed the objects.** Its `DELETE` requests removed the very orders the attack phase needed. | the attack phase found nothing, on every application |
| 4 | **The probes started from the first traffic record**, which is usually a *failed guess* (a path parameter nobody knew yet). | the probe replayed `GET /orders/alice` (404) instead of the order that exists |
| 5 | **The candidate set was keyed per object, not per operation.** A `POST` consumed the candidate, so the `PUT` on the same object was never tried. | the cross-identity **write** was never tested |
| 6 | The learning phase sent only two fields of a body. | a request with three required fields was rejected with `422`, and the endpoint was never exercised |

The fixes are in the engine, the proxy and the learning phase:

- the proxy accepts an **identity map** (token -> principal), and the engine
  resolves the identity of its own sessions from the tokens it holds;
- the learning phase **skips destructive operations** by default, and uses the
  examples from the specification - including per-field examples;
- the probes start from the **first request that worked**;
- the candidates are keyed per **operation**.

## 6. The gate

`mizan.validation.validate_application()` runs both variants and checks seven
conditions:

1. the clean variant ran without an error;
2. the clean scan sent requests;
3. the clean variant produced no finding;
4. the vulnerable variant ran without an error;
5. the vulnerable scan sent requests;
6. the expected laws (`L2`, `L3`) were detected;
7. every finding carries its evidence.

It is a CI stage (F - independent application), and the stage fails when the
suite is skipped.

## 7. What this does and does not prove

**Proves:** Mīzān detects cross-identity reads and cross-identity writes in an
application that does not import it, uses its own authentication and its own
database, and produces findings with complete evidence.

**Does not prove:**

- that an external *customer* has adopted Mīzān - the target is a controlled
  fixture, written by the same author, with a known weakness;
- that the detection rate holds for other stacks (Node, Java, Go) - the
  benchmark still covers one stack;
- that every law is detectable through this interface. **L1** (identity
  coherence) needs a JWT or an identity map; **L4** (mass assignment) needs an
  application ledger, because a database cannot tell who sent a field; **L5**
  (races) needs the application to expose a one-shot operation.

## 8. Laws and their support in this interface

| Law | Supported here | Why |
|---|---|---|
| L2 cross-identity read | **PROVEN** | the response carries the object and its owner |
| L3 cross-identity write | **PROVEN** | the database diff attributes the write |
| L1 identity coherence | **NOT PROVEN** | the tokens are opaque; the identity map gives the *name*, not the *claim* |
| L4 mass assignment | **NOT SUPPORTED** | the database cannot tell whether the client sent the field |
| L5 race | **NOT PROVEN** | the application exposes no one-shot operation |
