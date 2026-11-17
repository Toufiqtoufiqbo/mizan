# Phase V — Design Note: Evidence-Based Ownership Graph v1

This document is the architectural audit and the design decision record for
Phase V. It was written before implementation. It describes what is in the code
today, why that is insufficient for nonstandard ownership field names, and the
smallest safe architecture that fixes it without weakening the existing law
checks.

---

## 1. Audit of the present implementation

### 1.1 What creates an owner today

`traffic.infer_resource(response, template)` (traffic.py:163–204):

- requires a scalar `id` field in the response; without it there is **no
  resource at all**;
- looks for an owner in a **hardcoded** tuple
  `("owner_id", "user_id", "owner", "principal_id", "account_id")`;
- derives the resource type from the path template.

`SqliteAttributor` (attribution.py:41–161):

- snapshots every table with `SELECT rowid AS __rowid__, * FROM "<table>"`
  and keys rows by **rowid**, not by the declared primary key;
- derives `row_owner` with a **hardcoded** tuple
  `("owner_id", "user_id", "owner", "account_id", "tenant_id")`;
- reads no primary-key or foreign-key metadata.

`Mizan.learn()` (engine.py:126–209):

- populates `policy.resources[key].owner` **only** from `record.resource.owner`,
  i.e. from the response field above;
- `owned_by_principal[requester]` counts a resource as "owned" merely because
  the response carried *some* owner value;
- creates an `owner` rule when a principal only touched resources that carried
  an owner value — one observation is enough;
- `policy.permitted()` (core.py:360–378) turns that rule into an access decision
  by comparing `resource.owner == principal.id`.

`_probe_read_authorization` (engine.py:393–465):

- requires `resource.owner`; sends a GET as a different principal; requires a
  2xx **and** that the body contains the same resource id; skips only when the
  returned body claims the attacker as owner (another hardcoded field tuple);
- it does **not** verify that the recorded owner can actually access the object
  (the detail text claims it did;
- it does **not** check for an explicit sharing/access relationship.

`_probe_write_authorization` (engine.py:563–646):

- requires a response-derived owner or `WriteEvent.row_owner` (hardcoded);
- requires an attributed write event (`event.principal == attacker.id`);
- uses `event.resource_key` = `table:rowid`, so a database row is identified
  by SQLite's internal rowid rather than by its public identifier.

### 1.2 Consequences

A target that calls the owner `custodian_ref`, or that exposes only a
`document_key`, is invisible to the engine: no resource is discovered, no owner
is known, and L2/L3 cannot run. The scan then reports a clean result with zero
eligible ownership checks — an honest verdict in that case is *inconclusive*,
but a hardcoded owner field list cannot even tell that this happened.

A second, more dangerous failure mode exists in the other direction: a
foreign key is not ownership, a successful request is not permission, and a
membership row is not an ownership grant. Treating any of those as `OWNS` would
turn legitimate behavior into a reported vulnerability.

### 1.3 What must stay unchanged

`Resource`, `Policy.to_dict/from_dict`, `ScanCoverage.to_dict`, `Verdict`,
proof bundles, `mizan replay`, `mizan export-sarif`, `TrafficRecord`, the
ledger format, and all existing fixtures and laws. Phase V adds evidence; it
does not replace the proof system or add a law.

---

## 2. The chosen architecture

One focused module, `src/mizan/ownership.py`, with a small explicit data model.
No graph database, no generic reasoning framework, no new dependency.

### 2.1 Entities

| Kind | Key | Source |
|---|---|---|
| `principal` | configured principal id | engine target / traffic |
| `resource` | `<type>:<public id>` | traffic responses |
| `database` | `<table>:<primary key value>` | SQLite schema + rows |

### 2.2 Relationship types (kept distinct)

| Type | Meaning |
|---|---|
| `OWNS` | evidence links a principal to a resource as its owner |
| `REFERENCES` | a resource row points at another entity (e.g. a FK); **never** ownership by itself |
| `MEMBER_OF` | a principal belongs to a workspace/tenant/group |
| `SHARED_WITH` | an explicit access relationship explains another principal's access |

### 2.3 Evidence states (no invented percentages)

`CONFIRMED`, `CANDIDATE`, `AMBIGUOUS`, `CONTRADICTED`, `UNKNOWN`.

Every relationship keeps the ids of its supporting evidence. Evidence is a
stable reference: source kind, principal, resource/entity, table and column,
traffic index, and a short textual basis. **No token, password, cookie or raw
request/response payload is stored in the graph.** The full evidence stays in
the existing proof bundle, which already redacts tokens.

### 2.4 Evidence sources and what each may prove

| Source | May prove |
|---|---|
| `response_field` (existing conventional names) | a direct ownership claim (`OWNS`) |
| `write_ledger` | who created/changed a row; corroborates ownership, never proves permission |
| `sqlite_primary_key` | the identity of a database row |
| `sqlite_foreign_key` | `REFERENCES` first; ownership only with corroboration |
| `identity_anchor` | principal ↔ database identity record |
| `association_table` | `SHARED_WITH` / `MEMBER_OF`; explains access, never ownership |

Repeated copies of the same observation are deduplicated by a stable evidence
id: corroboration must come from **different sources**, not from the same fact
seen twice.

---

## 3. Conservative inference rules (the core of the design)

### 3.1 Resource discovery without an `id` field

Add one convention-free fallback to `infer_resource`: when the response has no
`id`, use the concrete path segment that occupies the `{id}` placeholder and
find the response field whose value equals it. This is evidence from the
request/response pair itself, not from a field-name list.

### 3.2 Principal ↔ database anchor

1. Collect scalar values from every principal's recorded GET responses.
2. For each table/column, find values that match exactly one row.
3. Require **at least two distinct principals** with **distinct** matched values
   (the mission's repeatability requirement).
4. Score candidates structurally: primary key > column referenced by a foreign
   key elsewhere > unique value. A unique top score is `CONFIRMED`; a tie is
   `AMBIGUOUS` and is preserved, never guessed.

A table called `users` is not assumed, and a response `id` is not assumed to be
a database primary key.

### 3.3 Resource ↔ owner

1. A database row is matched to a discovered resource by comparing the
   resource's public id with **declared primary-key values** across all tables.
   Rowid is never treated as a public identifier. Zero matches → `UNKNOWN`;
   several matches → `AMBIGUOUS`.
2. A declared foreign key from that row to the anchored identity table creates
   `REFERENCES`.
3. `OWNS` becomes `CONFIRMED` only when the foreign key target is the anchored
   record **and** an independent source agrees — the principal created the row
   (write ledger) or a response-level owner claim names the same principal.
   Without corroboration it stays `CANDIDATE`.
4. If two sources name different owners, both observations are kept and the
   relationship is `CONTRADICTED`/`AMBIGUOUS`; it is never used to prove a law.
5. A table with foreign keys to **both** a resource table and the identity
   table is an association table. Its rows create `SHARED_WITH`/`MEMBER_OF`
   evidence, never `OWNS`. Such evidence explains a cross-principal access and
   suppresses an L2 finding (the access is not a breach).

### 3.4 What the graph never does

- No `OWNS` from a foreign key alone.
- No `OWNS` from a successful request alone.
- No permanent ownership from creation alone (creation corroborates; it is not
  a legal rule).
- No permission inference from one or two observations.
- No owner-only rule for an entire resource type based on a single object.

---

## 4. How L2 and L3 consume the graph

**L2**: unchanged evidence requirements, three new gates before a finding:

1. the alleged owner is a configured principal with a token — otherwise the
   check is *inconclusive*;
2. a control GET as that owner returns the same resource id (the existing
   detail text now becomes true);
3. no `SHARED_WITH`/`MEMBER_OF` evidence explains the attacker's access.

A confirmed finding links to the graph evidence ids. A candidate ownership edge
alone can never produce a finding.

**L3**: the write ledger stays authoritative for attribution. The row that was
changed is resolved by real primary-key metadata (`WriteEvent.row_key`, a new
optional field with a default, so older ledgers still load). The graph decides
whether the row's owner is confirmed; ambiguous ownership never becomes a
finding. Unattributed writes remain inconclusive (existing behavior).

**Coverage**: `ScanCoverage` gains new counters with defaults (resources with
direct evidence, corroborated, candidates, ambiguous, shared-explained,
inconclusive). Existing keys and `meaningful` stay intact: a scan with many
resources but no confirmed owner remains `INCONCLUSIVE`, not `CLEAN`.

---

## 5. The independent fixture

`tests/fixtures/external_apps/linked_store/` is a standalone Flask application
that imports no Mīzān module. Its schema deliberately breaks conventions:

```
identities(identity_key TEXT PRIMARY KEY, display_name TEXT, secret_hash TEXT)
documents(document_key TEXT PRIMARY KEY,
          custodian_ref TEXT NOT NULL REFERENCES identities(identity_key),
          title TEXT, state TEXT)
document_grants(document_key TEXT REFERENCES documents(document_key),
                identity_key TEXT REFERENCES identities(identity_key))
```

The API exposes `document_key` (a public id) and `display_name`, but **no**
`owner_id`, `user_id`, `owner`, `principal_id`, `account_id` or `tenant_id`.
`GET /session` returns the caller's identity record; ownership is discoverable
only by matching it to the database and following the declared foreign key.

Variants: `clean`, `read`, `write`, `both`, `collaborator`, `ambiguous`.
The collaborator variant adds a grant row for bob — an explicit sharing
relationship, not ownership. The ambiguous variant makes the identity anchor
non-unique so no owner can be confirmed.

---

## 6. Benchmark and validation plan

Benchmark against (1) the standard `flask_store` fixture, (2) `linked_store`,
(3) patched clean controls, (4) the collaborator control, (5) the ambiguous
case. Every metric reports its denominator: ownership precision/recall, false
ownership assignments, unresolved rate, L2/L3 detection, clean-control false
positive rate, probes and requests consumed. Fixed seed, no tuning against the
labels after observing them. No claim of generalization beyond these fixtures.

---

## 7. Deliberate non-goals

No new law, no LLM, no engine rewrite, no graph database, no new external DB
dependency, no new web framework, no arbitrary public targets, no hardcoded
fixture table/column names in production logic, no PostgreSQL ownership-graph
support in v1 (existing PostgreSQL behavior is preserved, not extended), no
removal or weakening of existing tests.

---

## 8. Decision changes made during implementation (recorded, not hidden)

1. **Anchor as corroborating evidence.** The design first required a write-ledger
   or response corroboration in addition to the foreign key. In the real Twin
   flow the ledger is produced *during* the probes, so seeded resources had no
   such corroboration at learning time. The final rule is: a **direct** foreign
   key from the resource row to a **repeatably anchored principal record** is
   `CONFIRMED OWNS`, with the anchor itself as the independent evidence. A
   foreign key to an intermediate entity (workspace, tenant, group) remains a
   `REFERENCES` edge. This keeps the "a foreign key is not automatically
   ownership" rule while making seeded resources decidable.
2. **Identity observations are replayed.** The learning phase does not
   necessarily call a "who am I" endpoint for every principal. The engine now
   replays one qualifying single-object GET endpoint for every configurable
   principal, chosen because its recorded response value matches a declared
   database column. No endpoint name is hardcoded.
3. **OpenAPI path-level parameters.** The learner now merges path-item
   parameters into operations, as the OpenAPI specification requires.
4. **Path-parameter names are the identifier names.** `learning` now looks for
   response fields named after the OpenAPI path parameters, so a resource id
   called `document_key` is discovered without adding a name to a list.
5. **Value-based resource matching.** `contains_object` and `infer_resource`
   match identifier *values* instead of requiring a field literally named `id`.
6. **A latent secret leak was fixed.** `TaintAnalyzer` and the race-search
   steps embedded a raw `Authorization: Bearer <token>` header in proof steps;
   they now use `mask_authorization` like every other step producer. The
   canary-leakage tests caught this during Phase V integration.
7. **Anchor scoring.** When a resource primary key and an identity primary key
   were both referenced, a flat "is referenced" bonus tied them. The score now
   counts the number of declared foreign keys pointing at the column, so a
   central identity record wins over a single association-table reference.

---

## 9. Phase V.1 corrections (supersedes the earlier decisions above)

An adversarial review found that the structural scoring above was still too
confident. **Phase V.1 supersedes sections 3–6 of this design**:

1. A foreign key to an anchored principal is now `REFERENCES` plus, at most,
   `OWNS CANDIDATE`. It can never be `CONFIRMED OWNS` on structural grounds.
2. Confirmed ownership and confirmed sharing require a **trusted semantic
   contract** (`mizan-relationships.json`) or an explicit response-level claim
   naming a configured principal. No column/endpoint name is hardcoded.
3. Association tables produce `SHARED_WITH CANDIDATE` unless the contract
   declares `semantics: authorization_grant`. Candidates never suppress L2/L3.
4. An identity anchor requires a contract-declared endpoint and field; any
   other value match stays candidate evidence with an explicit reason.
5. API resources map to database rows by the **complete** declared primary
   key, serialized as a canonical JSON array (no delimiter collisions), and
   ambiguous mappings become inconclusive checks.
6. `WITHOUT ROWID` tables are snapshotted from declared primary keys.

See `PHASE_V1_CORRECTION_REPORT.md` for root causes, reproductions and evidence.

## 10. Phase V.2 corrections (runtime integration and grant evidence)

V.1 tightened the *inference*, but the shaded semantics were not always the ones
the running product applied. **Phase V.2 supersedes the execution-path
assumptions of sections 3–6**:

1. The trusted contract is part of the command-line contract:
   `mizan twin --relationship-contract PATH`. It is loaded once, strictly, and
   passed to the learning engine and to every parallel worker. No contract,
   valid contract and invalid contract are three distinct states; the third
   exits non-zero with a diagnostic instead of degrading silently.
2. A declared grant is confirmed only for the exact
   `(table, resource_fk, principal_fk, authorization_grant)` tuple, with an
   anchored principal for that column and a reference that resolves to exactly
   one API resource of the matching table and complete primary key. Other
   principal foreign keys in the same row remain candidates.
3. `TaintAnalyzer` is graph-backed when a graph exists. Graph mode requires a
   unique resource mapping and `OWNS CONFIRMED`; `row_owner` and conventional
   owner columns are diagnostics there. Legacy mode is preserved only when no
   graph is attached. The engine selects graph mode for database-backed scans;
   a ledger-only deployment has no row mapping and keeps the historical
   policy-level analyzer.
4. Contract validation is schema-aware: unknown tables/columns, non-foreign-key
   columns, composite keys, same-target roles and targets without a primary key
   are rejected before a scan starts.
5. Composite row identity uses a canonical JSON array; scalar identities remain
   unchanged for compatibility.

See `PHASE_V2_INTEGRATION_REPORT.md` for the reproductions and the
denominator-based re-measurement.

### Phase V.2.1 addendum

Phase V.2.1 narrows the semantics above in two places:

1. A grant declaration must carry an explicit, non-empty `actions` array using
   the engine's operation vocabulary (`read`, `write`). The confirmed tuple is
   now `(table, resource_fk, principal_fk, authorization_grant, actions)`.
   `OwnershipGraph.explained_by_sharing(owner, other, resource_key, action)`
   requires the action to be in that scope, so a read grant can never explain a
   write. `MEMBER_OF` and unscoped relationships never suppress a finding.
2. Outcome accounting uses four explicit states (`DECIDED`,
   `ALLOWED_BY_GRANT`, `VIOLATION`, `INCONCLUSIVE`) and per-law coverage for L2
   and L3. A resolved grant is not an inconclusive check. `CLEAN` requires every
   relevant eligible L2/L3 check to have been attempted and resolved; a proven
   finding keeps `FINDINGS` precedence over incomplete coverage. See
   `PHASE_V2_1_SOUNDNESS_REPORT.md`.

### Phase V.2.2 addendum

Phase V.2.2 narrows the coverage boundary without changing the V.2.1
authorization semantics:

1. **Relevance rule.** An ownership-unresolved resource contributes to L2/L3
   coverage only when it was discovered through a successful ownership-sensitive
   traffic record (read ⇒ L2, write ⇒ L3), a non-privileged testable identity
   exists, and the resource belongs to the ownership model — it has a unique
   database row mapping, any ownership relationship evidence (even a CANDIDATE),
   an ownership/sharing declaration for its type, or a recorded mapping
   ambiguity. Health/login/static responses have no resource record and are
   excluded. Ledger-only scans (no graph) keep their historical behavior.
2. **Unresolved checks are first-class.** Relevant unresolved checks are
   recorded once per stable `(law, action, resource, principal)` identity as
   `INCONCLUSIVE` outcomes: eligible, attempted and inconclusive. They are never
   findings and never silently resolved. Duplicates from repeated traffic
   observations collapse into one denominator entry.
3. **Strict variants.** A strict contract now rejects any non-object variant
   value, an empty/non-string variant name, and invalid declarations inside a
   variant (including action/sharing errors) at load time. Lenient mode keeps
   dropping the invalid entry and never creates an effective grant.

See `PHASE_V2_2_COVERAGE_REPORT.md` for measurements and gates.

### Phase VI addendum — PostgreSQL ownership evidence

PostgreSQL uses a dedicated provider (`postgres_attribution.PostgresAttributor`)
that implements the same small interface as `SqliteAttributor`: schema, rows,
snapshot, diff and row identity. It supplies schema-qualified table keys,
complete composite primary keys, foreign keys and uniqueness information to the
**existing** `build_ownership_graph()`. Contract declarations may use a bare
name resolved against the allowlist, or a qualified name; an ambiguous bare
name is rejected. Ownership declarations may name the database table explicitly
with `table`, which is how an API resource type with a nonstandard table name is
matched.

Writes are ordered by the audit table's monotonic `id`, never by timestamp. Each
HTTP request carries a unique correlation header into a transaction-local
PostgreSQL setting, which the trigger stores with the write. Correlation is not
identity: missing correlation, unknown principals and mismatched principals are
recorded as explicit attribution states and become inconclusive outcomes, never
confirmed L3 findings. Database object changes require the explicit
`--install-audit` opt-in and are confined to allowlisted schemas.

PostgreSQL attack/twin mode is intentionally unsupported: filesystem snapshots
cannot restore a live database. It fails closed; see
`PHASE_VI_POSTGRES_GAP_AUDIT.md` and `PHASE_VI_POSTGRES_REPORT.md`.
