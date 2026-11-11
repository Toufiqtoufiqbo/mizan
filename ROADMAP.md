# Roadmap

## Now (v0.1 - done)

- [x] Law model, policy inference, access matrix with residual
- [x] Write taint: ledger, Postgres log parser, cross-identity write detection
- [x] Authority creation (mass assignment) detection
- [x] Deterministic race harness (L5/L6)
- [x] Identity coherence (L1): the token claims one subject, the server acts as another
- [x] Proof bundles with replayable steps, evidence and the access-matrix diff
- [x] Patch suggestions: the shape of the fix per law, as a diff template
- [x] Regression tests: a pytest per finding that fails before the fix and passes after it
- [x] Schemathesis integration (`SCHEMATHESIS_HOOKS=mizan.schemathesis_hooks`)
- [x] **AuthzBugs-50**: 50 labelled applications, 5 laws x 10, with patched twins
- [x] **Guided search**: UCT over executed actions, a bandit over the templates,
      a prior taken from the learned policy, concurrent pairs for races and
      identifiers chained from responses - 10/10 breaches with 20.6 requests per
      application, against 49.4 for the fixed probes
- [x] End-to-end tests (57 passing)

### Measured on AuthzBugs-50

| metric | value |
|---|---|
| detection rate | 100% (50/50) |
| false positives on patched twins | 0 / 55 apps |
| unexpected findings on buggy apps | 0 |
| regression tests valid | 100% (reproduce before the fix, blocked after it) |

## Next (v0.2 - the twin, without Docker)

- [x] **Twin**: start the application as a local process on a free port, wait
      until it answers, snapshot and restore its state
- [x] **Recording proxy**: the traffic log without changing the application
- [x] **Data-level attribution**: the write ledger from the difference between
      two snapshots of the database - no instrumentation, no triggers
- [x] **Restore between probes**: the findings no longer depend on the order
      the probes ran in (proven by a test)
- [x] **Active learning**: discover the endpoints and their identifiers from
      the OpenAPI document, then exercise them
- [x] **Parallel probing**: N isolated copies of the application, each with its
      own data and port, split the probes between them
- [x] **CI gate**: `mizan replay` replays every proven attack against a target
      and fails when one still works
- [x] **Postgres auditor**: an audit table and a trigger, with the identity in
      `application_name`; primary keys read from the catalog (`id`, UUID, text,
      composite); tables without a key are unidentified, never misattributed;
      `SET LOCAL` keeps the identity inside the transaction; the round trip is
      covered by real-server tests (15 of them, in CI and locally)
- [x] **Proof bundles carry no secrets**: the bearer token is a placeholder,
      resolved from the environment when the bundle is replayed
- [x] **A write without an author is not a finding**: missing or malformed
      identities are recorded as `unknown` and never reported as a breach
- [ ] **Parallel Postgres**: the same isolation for a Postgres data directory
- [ ] **Attack regression**: re-run every proven attack on each pull request
      (the pieces exist: `mizan replay` plus the GitHub Action)

## Next (v0.4 - the second user)

- [ ] **A second, external user**: the self-scan proves the tool works on us;
      it does not prove it works on somebody else's codebase
- [ ] **Triage format**: SARIF and a pull-request comment, so findings land in
      the workflow the team already uses
- [ ] **The corpus across stacks** (Flask, FastAPI), with a manifest so
      third parties can add cases

## Later (v0.3 - the rest of the laws)

- [ ] **L7** - path confidentiality (cache, queue, logs, metrics)
- [ ] **L6** - full cardinality coverage (single-use tokens, bounded counters)
- [ ] **Process mining** - derive the state machine from event logs and report
      workflow violations (shipping before payment, approving twice, ...)
- [ ] **Authorization matrix** - subject x resource x action, mined from traces
- [ ] **LLM planner** - suggest schema-valid actions that break a law, next to
      the UCT search that explores blindly today
- [ ] **Deeper search** - replay the path of a branch instead of evaluating
      every action in the current state, so the search can rely on the effects
      of the steps before it
- [ ] **Larger benchmark** - extend AuthzBugs-50 to 100+ applications in several
      stacks (Node, Python, Java, Go) and publish the corpus openly

## Non-goals

- Replacing a scanner: Mizan reports a narrow class of findings, but reports
  them with proof.
- Running against systems you are not authorized to test: the default target
  is a local twin of code you own.
