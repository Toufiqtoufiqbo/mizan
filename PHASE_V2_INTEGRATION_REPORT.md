# Mīzān Phase V.2 — Runtime Integration & Authorization Evidence Hardening

**Branch:** `feat/ownership-graph-v1` · **PR:** #9 · **Base:** `main`

## 1. Executive verdict

**READY FOR REVIEW** — pending the exact-final-SHA CI result recorded in the delivery message. The three V.2 defects were reproduced against the pre-V.2 tree, corrected at the execution-path level rather than in tests, and re-verified through the real `mizan twin` command, the association discovery function and the graph-backed analyzer. No test was deleted, skipped or weakened; no production branch names a fixture or a column.

## 2. Root causes found

| # | Root cause | Failure mode |
|---|---|---|
| A | `mizan twin` had no `--relationship-contract` option, and `build_engine` never passed one to `Mizan` | operator-declared identity/ownership/grant semantics were unreachable from the real command; only hand-built engines could use them |
| B | `discover_associations()` compared only the **resource** foreign key against the declaration, then confirmed a grant for *every* identity foreign key in the row | a creator/observer FK inherited a grant declared for a collaborator FK → a real cross-user read/write was suppressed |
| C | `TaintAnalyzer` had no graph; the data view trusted `row_owner` (derived from `OWNER_COLUMNS`) and the graph never reached the write probes | L3 could rest on a conventional column hint, and two different standards of ownership decided L3 in the same scan |
| D | Residual V.1: `_row_key()`/`row_identity()` joined components with `":"`, and `_resource_key_for()` matched a reference by public id across tables | composite identities could collide; a reference to one table could resolve to a resource of another |

## 3. Contract propagation through the real CLI

- New `mizan twin --relationship-contract PATH` (single file, must exist).
- Three states are kept distinct and never collapse:
  1. **no contract** (`None`): structural evidence only — nothing is invented;
  2. **valid contract**: declarations are honoured;
  3. **explicitly supplied but invalid**: `SystemExit(2)` with a diagnostic.
- The contract is resolved once, before any engine is built, and passed to every engine the command creates — the learning engine and each parallel worker (verified with `--workers 2`).
- `learn()` re-validates the contract against the live schema; a contract without a schema raises `RelationshipContractError` instead of silently weakening semantics.
- `scan_application()` / `validate_application()` load an application's `mizan-relationships.json` with `strict=True`; a malformed file becomes `result.setup_error`, never a quietly different scan.
- An invalid contract is rejected **before** the target is launched, so a misconfiguration cannot consume a scan budget.

## 4. Exact principal-FK grant enforcement

A grant is now confirmed only when **all** of the following hold:

1. the contract names this **table**;
2. the row's resource reference is the declared `resource_fk`;
3. the anchored identity value comes from the declared `principal_fk`;
4. the declaration uses `semantics: authorization_grant`;
5. the referenced principal is an anchored principal (an identity observation, declared endpoint/field);
6. the database reference resolves to **exactly one** API resource whose mapped table matches the referenced table and whose complete primary key matches the value.

Consequences:

- a second FK to the same principal table stays `CANDIDATE`; it never inherits the grant;
- a grant declared on a column the application does not authorize on suppresses nothing (the `declared_creator` variant still yields its L2);
- a grant whose principal FK has no anchored identity is recorded as `sharing:<table>` inconclusive — not as a confirmed grant;
- a reference into another table with a coincidentally equal id resolves to nothing;
- composite foreign keys are rejected at validation time, because a single column of a composite key does not identify the referenced row.

## 5. Graph-backed `TaintAnalyzer`

`TaintAnalyzer(policy, strict=False, graph=None)`:

- **Legacy mode** (`graph is None`) is byte-for-byte the historical behaviour, so DB-less ledgers and existing callers keep working.
- **Graph-backed mode** (`graph` is an `OwnershipGraph`):
  - the changed row must map to exactly one API resource via the complete primary key;
  - the graph must hold `OWNS CONFIRMED` for it, with a **unique** owner;
  - `row_owner`, `OWNER_COLUMNS` and any orchestrator-provided hint are diagnostics, never authority;
  - a confirmed grant (`explained_by_sharing`) explains the write;
  - every unresolved case becomes an entry in `analyzer.inconclusive` (surfaced as `inconclusive_checks`), never a CLEAN result and never a finding.
- L4 is preserved in both modes; `resource_mapping` and `ownership_evidence` are attached to every graph-backed L3.
- The engine passes its graph to both the data view and the per-write analyzer, and merges `analyzer.inconclusive` into the scan's `inconclusive_checks`; duplicates are collapsed by `(law, principal, resource)`.
- `_probe_write_authorization` uses the graph only: no `row_owner` fallback exists in graph mode.
- Graph-backed analysis is scoped to database-backed scans. A ledger-only deployment (no attributor, as in the AuthzBugs benchmark) has no schema and therefore no row mapping; it keeps the historical policy-level behaviour instead of turning every write into an inconclusive check. This is an explicit deployment boundary, not a fallback to `row_owner` inside graph mode.

## 6. Fail-closed contract validation

`RelationshipContract` gained `RelationshipContractError`, strict `from_dict(..., strict=)`, strict `load(..., strict=)`, strict `for_variant(..., strict=)` and `validate_schema(schema)`. Rejected explicitly:

- unreadable file, malformed JSON, unsupported `version`;
- `identity` without both an endpoint and a field;
- ownership declaration without a `source`, a `column`/`field`, or with an unsupported source;
- sharing declaration that is not an object, lacks `resource_fk`/`principal_fk`, uses the same column for both roles, or does not use `authorization_grant`;
- unknown table, unknown column, a column that is not a declared foreign key, a composite foreign key, both roles targeting the same table, or a target table without a primary key.

Lenient parsing remains only for internally composed data; an operator file never degrades silently.

## 7. Composite-key identity fix

- `ForeignKey.composite` is derived from the `PRAGMA foreign_key_list` group size.
- Row identity is canonical: a scalar for a single-column key, a canonical JSON array for a composite key (no delimiter concatenation).
- `TaintAnalyzer` parses both forms, so a legacy scalar ledger entry stays readable while a composite identity cannot collide with another.

## 8. Adversarial test matrix

Independent fixture `tests/fixtures/external_apps/adversarial_store`: an association table with **three** principal foreign keys (`creator_ref`, `collaborator_ref`, `observer_ref`).

| Variant | Expected | Actual |
|---|---|---|
| `clean` | CLEAN | **CLEAN** |
| `read` (undeclared observer row present) | L2 only | **L2 only** |
| `write` | L3 only | **L3 only** |
| `grant` (declared collaborator grant) | CLEAN | **CLEAN** |
| `creator_only` | L2 | **L2** |
| `observer_only` | L2 | **L2** |
| `declared_creator` (contract names the creator FK) | L2 | **L2** |
| `provenance` (no ownership declaration) | INCONCLUSIVE | **INCONCLUSIVE**, 0 confirmed edges |
| `ambiguous_identity` (identity field names an item) | INCONCLUSIVE | **INCONCLUSIVE**, 0 anchors |

Pre-V.2 behaviour on the same data (captured in a detached worktree at `5baa0ec`):

| Check | Pre-V.2 result |
|---|---|
| `mizan twin --help` | no `--relationship-contract` option |
| `TaintAnalyzer(policy, graph=...)` | `TypeError: unexpected keyword argument 'graph'` |
| `RelationshipContract.load("{not json")` | `None` (silent downgrade) |
| `load({"version": 99})` | accepted as version 1 |
| grant declared on `collaborator_ref`, row populated only via `creator_ref` | grant **confirmed** → finding suppressed |
| row populated only via `observer_ref` | grant **confirmed** |
| association referencing `notes('a1')` while the only resource is `artifacts:a1` | sharing edge attributed to `artifacts:a1` |

## 9. Benchmark results with denominators

`python -m benchmarks.ownership.run` (20 cases, budget 90, fixed identifiers, `benchmarks/ownership/results.json` regenerated):

| Metric | Result | Denominator |
|---|---|---|
| Law detection | 10 | 10 eligible variants |
| Clean-control false positives | 0 | 8 controls |
| CLI contract propagation | 1 | 1 end-to-end command |
| Ownership invented without a contract | 0 | 1 control |
| Invalid contracts rejected | 5 | 5 malformed/invalid files |
| Exact principal-FK selection | 3 | 3 grant-inheritance cases |
| Incorrect-grant suppression | 0 | 3 eligible cases |
| Duplicate L3 findings | 0 | 20 scans |
| Inconclusive outcomes correct | 3 | 3 expected |
| Declared grants confirmed (total) | 3 | — |
| Candidate associations (total) | 10 | — |
| Inconclusive checks recorded (total) | 8 | — |
| Resource→row mapping resolved | 56 | 62 discovered resources |
| Probes executed | 30 | 116 candidates |
| Requests consumed | 442 | 20 scans |

No percentage is reported without numerator and denominator; no generalization claim beyond the fixture families.

## 10. Pre-fix reproductions

The pre-fix table in section 8 is produced by a script run against a detached worktree at `5baa0ece896b4d1588461e395a4d5c97f88e5702`, importing that tree's `src/`. The worktree was removed afterwards; the main working tree, stashes and branches were untouched.

## 11. Full test and CI results

Local: `pytest` → **508 passed / 0 failed / 0 skipped** (476 from Phase V.1 + 26 new V.2 integration tests + 6 additional adversarial variants). The first full run exposed four failures caused by graph mode being applied to ledger-only deployments (AuthzBugs benchmark ×2, `test_mizan` end-to-end ×1, search benchmark ×1); the boundary was corrected (database-backed scans are graph-backed, ledger-only scans keep the historical policy-level analyzer) and all four pass. No test was deleted, skipped or weakened.

`ruff check .`, `ruff format --check .` and `git diff --check` are clean. Cross-framework gate: **8/8 scenarios as expected**, 8 true positives, 0 false positives, 0 false negatives, 8/8 reproductions. Independent-application, PostgreSQL, security-regression and self-scan gates are part of the same suite. The exact-final-SHA CI result is stated in the delivery message.

## 12. Compatibility assessment

- Old ledgers without `row_key` still load; they are analyzed in legacy mode or become explicit inconclusive checks under a graph, never invented findings.
- A database-backed scan uses the graph; a ledger-only scan keeps the historical policy-level analyzer, because without a schema a write cannot be mapped to a row. Both paths are explicit and covered by tests (the AuthzBugs benchmark and the search benchmark exercise the ledger-only path).
- `TaintAnalyzer(policy)` and `TaintAnalyzer(policy, strict=True)` keep their historical results.
- All existing CLI commands keep their interface; `--relationship-contract` is additive.
- Fixtures without a contract keep their previous behaviour; the standard fixtures' contracts remain the default four-variant set.
- `row_owner` remains in events and proof bundles as a diagnostic hint; it is not authority anywhere.
- Proof bundles, SARIF export, replay, parallel workers and PostgreSQL behaviour are unchanged.

## 13. Remaining limitations

- The contract is trusted metadata: a false declaration can still mislead the graph. Validation checks that the declaration *exists in the schema*, not that the application enforces it.
- A grant is evidenced by the declaration plus the association row; there is no behaviour-based proof that the application actually honours it.
- Only single-column resource/principal foreign keys are supported; composite grant keys are rejected by design.
- Ownership remains SQLite-scoped for graph evidence; PostgreSQL behaviour is unchanged and out of scope.
- No new law was added; JWT subjects remain extracted, not verified.

## 14. Final SHA and PR status

Recorded in the delivery message after the final commit/push; PR #9 remains open and unmerged, `main` untouched.
