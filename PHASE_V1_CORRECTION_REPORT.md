# Mīzān Phase V.1 — Ownership Semantics & Resource Identity Hardening

**Branch:** `feat/ownership-graph-v1` · **PR:** #9 · **Base:** `main` @ `dd0223e`

## 1. Executive verdict

**READY FOR REVIEW** — pending the exact-final-SHA CI result recorded in the delivery message. All four critical issues were reproduced with failing tests, corrected at the architecture level, and re-verified through the real scan pipeline. No test was deleted, skipped or relaxed.

## 2. Root causes found

| # | Root cause | Failure mode |
|---|---|---|
| A | `discover_relationships()` promoted a direct FK to an **anchored** principal record into `CONFIRMED OWNS`, using the anchor itself as "corroboration" | `created_by`, `assigned_to`, `reviewer_id`, `billing_contact` all became owners → false L2/L3 |
| B | `discover_associations()` produced `CONFIRMED SHARED_WITH` from table shape alone; `explained_by_sharing()` suppressed findings with it | watcher/audit/reviewer tables hid real IDORs |
| C | `_find_rows()` matched **any** primary-key component; row identity used `":"` concatenation; API type and DB table were assumed to align | composite keys mis-resolved, colliding identities, lost L3 on renamed tables |
| D | `_identity_observations()` selected a GET endpoint because its response merely contained a database value | a document/assignment endpoint became a false identity anchor |

## 3. Ownership semantic corrections

New `RelationshipContract` — explicit, trusted, application/operator-provided metadata (`mizan-relationships.json`). It declares which endpoint+field is an identity assertion, which FK is an ownership signal, and which association is an authorization grant. **No column name is hardcoded in production inference.**

- A foreign key is always recorded as `REFERENCES` (CONFIRMED as a structural fact).
- FK + anchor → `OWNS CANDIDATE`, never confirmed.
- `OWNS CONFIRMED` requires a semantic signal: a declared ownership FK, or a response-level owner claim naming a **configured principal**.
- `created_by` / `assigned_to` / `reviewer_id` without declaration remain candidates; two such FKs produce `CONTRADICTED`, and no owner is used.
- Response fields naming unconfigured identities are explicitly marked `unverified_response_claim`.

## 4. Sharing semantic corrections

- Association-table rows create `SHARED_WITH CANDIDATE` by default, with an explicit `sharing:<principal>:<resource>` inconclusive reason.
- `CONFIRMED SHARED_WITH` requires `semantics: authorization_grant` in the contract.
- `explained_by_sharing()` only considers CONFIRMED relationships.
- Proven: an undeclared watcher row does **not** suppress a real L2; a declared grant does suppress a legitimate collaborator access.

## 5. Identity-anchor corrections

- Only responses from the contract-declared identity endpoint/field can produce a confirmed anchor.
- Other value matches are preserved as `CANDIDATE MEMBER_OF` plus `identity:<principal>` inconclusive reasons.
- No endpoint name (`/me`, `/session`, …) is assumed; the adversarial `ambiguous_identity` variant proves a document-valued identity field yields **no** anchor and an `INCONCLUSIVE` verdict.

## 6. API-resource ↔ database-row mapping

- `ResourceIdentity` is a canonical JSON array of the **complete** declared primary key; `parse_identity()` keeps older scalar identifiers readable.
- `canonical_key()` uses JSON, so `["a:b","c"]` and `["a","b:c"]` cannot collide.
- A unique `resource_rows` / `row_resources` mapping is built only when the whole primary key matches exactly one row; ambiguity is recorded as an inconclusive reason.
- L3 resolves writes via `graph.row_to_resource(table, components)`, with a conservative legacy-rowid fallback for old ledgers; unresolved rows become `inconclusive_checks`, never findings.

## 7. Composite keys and WITHOUT ROWID

- `_find_rows()` requires `len(pk_columns) == len(components)` and compares every component.
- `SqliteAttributor.snapshot()` falls back to declared primary keys when `rowid` is unavailable; single-column keys keep scalar identity, composite keys use the canonical JSON array. Composite-key and collision cases are covered by unit tests.

## 8. L2/L3 behavior changes

- L2: confirmed semantically justified owner + owner control GET + exact cross-read + no confirmed grant + masked replayable evidence.
- L3: attributed write + uniquely mapped row + confirmed semantic owner + no confirmed grant; ambiguous/CANDIDATE/UNKNOWN ownership is recorded as inconclusive, not silently treated as clean.
- `evidence.resource_mapping` exposes table, database key and API resource for every L3 finding.

## 9. Adversarial test matrix

| Case | Expected | Actual |
|---|---|---|
| clean | CLEAN | **CLEAN** |
| read (undeclared watcher present) | L2 only | **L2 only** |
| write | L3 only | **L3 only** |
| grant (declared) | no false L2 | **CLEAN** |
| provenance-only FK | INCONCLUSIVE | **INCONCLUSIVE**, 2 candidates, 0 confirmed edges |
| ambiguous identity field | INCONCLUSIVE | **INCONCLUSIVE**, 0 anchors promoted |
| created_by / assigned_to / reviewer_id | no confirmed owner | **pass** (unit) |
| composite key / collision / WITHOUT ROWID | correct canonical identity | **pass** (unit) |

Every pipeline test also asserts the evidence/coverage explanation (confirmed edge counts, candidate counts, inconclusive reasons, masked steps).

## 10. Benchmark results with denominators

`python -m benchmarks.ownership.run` (15 cases, budget 90, fixed identifiers):

| Metric | Result | Denominator |
|---|---|---|
| Law detection | 7 | 7 eligible variants |
| Clean-control false positives | 0 | 8 controls |
| Identity-anchor false positives | 0 | 1 ambiguous-identity case |
| Association→sharing false positives | 0 | 1 unauthorized case with an association |
| Resource→row mapping resolved | 42 | 48 discovered resources |
| Inconclusive outcomes correct | 3 | 3 expected |
| Ownership edges (confirmed / candidate) | 42 / 2 | 48 resources |
| Probes executed | 24 | 93 candidates |
| Requests consumed | 348 | 15 scans |

No percentage is reported without numerator/denominator; no generalization claim beyond the three fixture families.

## 11. Full test and CI results

Local: `pytest` → **476 passed / 0 failed / 0 skipped** (451 prior + 13 adversarial-semantics unit tests + 12 adversarial-fixture pipeline tests). `ruff check .`, `ruff format --check .`, `git diff --check` clean. Cross-framework, independent-application, PostgreSQL, security-regression, benchmark and self-scan gates all pass. CI result for the exact final SHA is stated in the delivery message.

## 12. Compatibility assessment

Old ledgers (no `row_key`), old policies, traffic records, proof bundles, SARIF export, replay and all CLI commands remain supported. New fields are additive with defaults. Standard fixtures (flask/FastAPI/Express) keep their behavior; their contracts remain the default four-variant set.

## 13. Remaining limitations

- The semantic contract is trusted metadata: an application that declares a false ownership signal can still mislead the graph.
- No behavior-based proof that a declared grant is actually enforced; the contract plus the grant row is the evidence.
- PostgreSQL ownership graphs remain out of scope; standard PostgreSQL behavior is unchanged.
- No new law; JWT subjects remain extracted, not verified.

## 14. Final SHA and PR status

Recorded in the delivery message after the final commit/push; PR #9 remains open and unmerged.
