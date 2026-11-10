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
- [x] End-to-end tests (34 passing)

### Measured on AuthzBugs-50

| metric | value |
|---|---|
| detection rate | 100% (50/50) |
| false positives on patched twins | 0 / 55 apps |
| unexpected findings on buggy apps | 0 |
| regression tests valid | 100% (reproduce before the fix, blocked after it) |

## Next (v0.2 - the twin)

- [ ] **Local twin**: generate a runnable environment from `Dockerfile`/`compose`
      + lockfiles + seeds, with mocked third parties (IdP, payments, email)
- [ ] **Snapshot & restore**: Postgres snapshot between probes so every probe
      starts from the same state (removes the ordering constraints in the engine)
- [ ] **Attack regression**: re-run every proven attack on each pull request

## Later (v0.3 - the rest of the laws)

- [ ] **L7** - path confidentiality (cache, queue, logs, metrics)
- [ ] **L6** - full cardinality coverage (single-use tokens, bounded counters)
- [ ] **Process mining** - derive the state machine from event logs and report
      workflow violations (shipping before payment, approving twice, ...)
- [ ] **Authorization matrix** - subject x resource x action, mined from traces
- [ ] **Guided search** - MCTS over actions with the law residual as the fitness
      function, instead of the current template-driven probes
- [ ] **LLM planner** - suggest schema-valid actions that break a law
- [ ] **Larger benchmark** - extend AuthzBugs-50 to 100+ applications in several
      stacks (Node, Python, Java, Go) and publish the corpus openly

## Non-goals

- Replacing a scanner: Mizan reports a narrow class of findings, but reports
  them with proof.
- Running against systems you are not authorized to test: the default target
  is a local twin of code you own.
