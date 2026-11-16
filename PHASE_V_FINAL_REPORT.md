# Mīzān Phase V — Evidence-Based Ownership Graph & Relationship Discovery v1

**Branch:** `feat/ownership-graph-v1` · **Base:** `main` @ `dd0223e` · **Design note:** `PHASE_V_DESIGN.md`

---

## 1. Existing architecture and limitations (before this phase)

- `traffic.infer_resource()` required a field literally named `id` and looked for an owner only in `("owner_id", "user_id", "owner", "principal_id", "account_id")`.
- `SqliteAttributor` keyed rows by SQLite `rowid` and read `row_owner` from another hardcoded column tuple; it used no primary-key or foreign-key metadata.
- `engine.learn()` set `Resource.owner` only from the response field, then turned a single "touched only owned objects" observation into an owner rule.
- L2 did not verify that the alleged owner could read the object and did not consider explicit sharing; L3 resolved rows by `rowid`.
- `learning._identifiers_in()` looked for `id`/`order_id`/`user_id`/`uuid` only, so a resource id called `document_key` was never discovered.
- `contains_object()` required a field named `id`, so a confirmed disclosure with another id field was invisible.
- Two proof-step producers (`taint.py`, `search.py`) embedded a raw bearer token in steps — a latent secret leak the canary tests exposed during this phase.

Consequence: an application with nonstandard ownership field names looked clean while no ownership check had run at all — or, worse, a wrong owner could drive a false finding.

## 2. Ownership graph model and relationship types

New module `src/mizan/ownership.py`. Entities: `principal`, `resource` (`<type>:<public id>`), `database` (`<table>:<primary key>`). Four relationship kinds are **never collapsed**:

| Kind | Meaning |
|---|---|
| `OWNS` | evidence links a principal to a resource as its owner |
| `REFERENCES` | a row points at another entity — a foreign key first, never ownership by itself |
| `MEMBER_OF` | a principal's anchor to a database identity record |
| `SHARED_WITH` | an explicit association that explains access but grants no ownership |

Evidence is a stable content hash plus source, principal, resource/entity, table/column and a short basis. No token, password, cookie or raw payload is stored. Serialization round-trips (`to_dict`/`from_dict`).

## 3. Evidence sources and confidence states

States: `CONFIRMED`, `CANDIDATE`, `AMBIGUOUS`, `CONTRADICTED`, `UNKNOWN`. Sources: `response_field`, `write_ledger`, `identity_anchor`, `sqlite_foreign_key`, `association_table`. Repeated observations dedupe by evidence id, so the same fact seen twice is not "corroboration". A later observation never overwrites an earlier one: two confirmed owners for one resource produce `CONTRADICTED`, and the disputed owner is removed from the policy so it cannot support a finding.

## 4. Principal identity anchoring method

1. Collect scalar values from recorded responses of every principal.
2. Find (table, column, value) matches that are unique within the column.
3. Require at least **two distinct principals with distinct values** — the repeatability rule.
4. Score structurally: primary key (+4), number of declared foreign keys pointing at the column (up to +4), uniqueness (+1). A unique top score is `CONFIRMED`; a tie is preserved as `AMBIGUOUS` and yields no anchor.
5. One qualifying single-object GET endpoint is replayed per principal (chosen because its recorded response already matches a database column), so no `/me`-style path name is assumed.

## 5. SQLite schema and foreign-key discovery

`SqliteAttributor.schema()` reads `sqlite_master`, `PRAGMA table_info`, `PRAGMA foreign_key_list` and `PRAGMA index_list`/`index_info`; identifiers are quoted by `quote_identifier()` (a `"` becomes `""`). Composite primary keys keep column order. `TableSnapshot.keys` records the primary key for each row; `WriteEvent.row_key` carries it into the ledger (new optional field, older ledgers still load). A foreign key to an **anchored principal record** can confirm ownership; a foreign key to an intermediate entity (workspace/tenant) stays `REFERENCES`. A table with FKs to both a resource table and an anchored identity table is an association table: its rows create `SHARED_WITH`/`MEMBER_OF`, never `OWNS`.

## 6. How L2 and L3 consume graph evidence

**L2** uses confirmed owners from `record.resource` (the engine updates traffic records from the graph). Before a finding: a control GET as the owner must return the exact resource; the attacker's GET must be 2xx and contain the same identifier by value; an explicit sharing/membership relationship suppresses the finding. Evidence now carries `owner_control_status` and stable `ownership_evidence` ids.

**L3** resolves the changed row by `row_key` (real primary key), reads the confirmed graph owner, refuses ambiguous/contradicted ownership, honours explicit sharing, and keeps unattributed writes inconclusive. Evidence carries `ownership_evidence`.

## 7. Independent fixture architecture

`tests/fixtures/external_apps/linked_store/` — a standalone Flask app importing no Mīzān module, with its own opaque tokens, SQLite database and OpenAPI document. Schema: `identities(identity_key PK, …)`, `documents(document_key PK, custodian_ref FK → identities)`, `document_grants(document_key FK, identity_key FK)`. The API exposes `document_key`, `title`, `state` and `identity_key` (the caller's own identity) — **no** `owner_id`/`user_id`/`owner`/`principal_id`/`account_id`/`tenant_id`. Six variants: `clean`, `read`, `write`, `both`, `collaborator` (an explicit grant for Bob), `ambiguous` (two real identity records per caller).

## 8. Results for all six scenarios

| Scenario | Expected | Actual |
|---|---|---|
| clean | no findings, CLEAN | **CLEAN**, no findings |
| read | L2 only | **L2 only** |
| write | L3 only | **L3 only** |
| both | L2 and L3 | **L2 + L3** |
| collaborator | no false L2 | **CLEAN**, no findings |
| ambiguous | inconclusive, no fabricated owner | **INCONCLUSIVE**, 0 owned resources, 0 findings |

All six are asserted in `tests/test_linked_store.py`; `mizan validate <linked_store>` drives all six through the real CLI/proxy path.

## 9. False ownership assignment analysis

- A foreign key to a non-anchored entity produces `REFERENCES` and, at most, `CANDIDATE`; `owner_of()` returns `None`.
- Two confirmed owners produce `CONTRADICTED`; the resource's owner is cleared and no law can use it.
- The ambiguous fixture produces no anchor at all (two valid identity values per principal) → no owner, `INCONCLUSIVE`.
- Association rows produce `SHARED_WITH`, so the collaborator variant has no false L2.
- Serialized graph evidence contains no token; proof steps use replayable placeholders only.

## 10. Benchmark results with denominators

`python -m benchmarks.ownership.run` → `benchmarks/ownership/results.json`. Fixed fixture identifiers; no random sampling in the inference; budget 90 requests per scan; 9 cases (flask_store clean/read/write, linked_store × 6).

| Metric | Result | Denominator |
|---|---|---|
| Law detection (variants with an expected law) | 5 detected | 5 eligible variants |
| False positives on clean controls | 0 | 4 controls (clean + collaborator + …) |
| Confirmable edges without corroboration | 0 candidates | 15 confirmed edges |
| Unresolved resources | 3 | 18 discovered (16.7%) |
| Probes executed | 16 | 51 candidates |
| Requests consumed | 159 | 9 scans × ≤90 budget |

Precision/recall against held-out labels are **not claimed**: the fixture's own seeded rows are the ground truth, so the report gives edge counts and limitations instead of pretending to an independent corpus.

## 11. Full regression and CI results

Local gates on the final tree: `pytest` → **451 passed, 0 failed, 0 skipped** (416 pre-existing + 21 graph tests + 14 fixture tests); `ruff check .` and `ruff format --check .` clean; `git diff --check` clean; benchmark, independent application, Flask/FastAPI/Express, PostgreSQL, security regression and self-scan gates all included in the suite. GitHub Actions verification is recorded in the delivery message for the exact final SHA (the first run exposed a fixture-variant regression, fixed in the final commit).

## 12. Exact commit SHA and PR URL

- Branch: `feat/ownership-graph-v1` (pushed without force).
- PR: **#9 — https://github.com/Toufiqtoufiqbo/mizan/pull/9** (open, unmerged).
- The exact final commit SHA and the Actions run number/result for that SHA are stated in the delivery message.

## 13. Remaining limitations

- JWT subjects remain *extracted*, never signature-verified.
- The trust in a proxy's asserted identity depends on the proxy overwriting client headers.
- Anchor scoring is structural, not semantic: a table with several inbound FKs is treated as the central identity table.
- Only SQLite schema discovery is implemented; PostgreSQL ownership graphs are not.
- The benchmark uses one conventional and one nonstandard fixture family; no generalization claim.

## 14. Deliberately not supported yet

No new law, no LLM/AI planner, no engine rewrite, no graph database, no new external DB dependency, no new web framework, no arbitrary public targets, no PostgreSQL ownership-graph support, no hardcoded fixture table names in production logic, no merge of the PR.

## Verdict

**READY FOR REVIEW** — provided every mandatory CI job passes on the exact final commit (verified in the delivery message). No confirmed finding rests on candidate ownership; the collaborator case produces no false L2; the ambiguous case produces no fabricated owner; the nonstandard L2/L3 vulnerabilities are detected; existing regressions are preserved.

---

## Phase V.1 correction notice

The inference rules in sections 2–5 were tightened after adversarial review:
structural evidence (a foreign key, an association row, a matching response
value) is no longer promoted to confirmed ownership, sharing, or identity
without an explicit semantic declaration. See `PHASE_V1_CORRECTION_REPORT.md`
for the four root causes, the reproductions, the fixes and the new
denominator-based benchmark. The corrected suite is **476 passed / 0 failed /
0 skipped**; cross-framework gate 8/8.
