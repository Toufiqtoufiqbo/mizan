# Roadmap

## Now (v0.1 - done)

- [x] Law model, policy inference, access matrix with residual
- [x] Write taint: ledger, Postgres log parser, cross-identity write detection
- [x] Authority creation (mass assignment) detection
- [x] Deterministic race harness (L5/L6)
- [x] Proof bundles with replayable steps
- [x] Schemathesis integration (`SCHEMATHESIS_HOOKS=mizan.schemathesis_hooks`)
- [x] Vulnerable demo app + end-to-end tests (15 passing)

## Next (v0.2 - the twin)

- [ ] **Local twin**: generate a runnable environment from `Dockerfile`/`compose`
      + lockfiles + seeds, with mocked third parties (IdP, payments, email)
- [ ] **Snapshot & restore**: Postgres snapshot between probes so every probe
      starts from the same state (removes the ordering constraints in the engine)
- [ ] **Patch engine**: propose a fix for each finding and validate it inside the
      twin; ship it as `patch.diff` + a regression test
- [ ] **Attack regression**: re-run every proven attack on each pull request

## Later (v0.3 - the rest of the laws)

- [ ] **L1** - authentication coherence (token subject vs session vs database)
- [ ] **L7** - path confidentiality (cache, queue, logs, metrics)
- [ ] **Process mining** - derive the state machine from event logs and report
      workflow violations (shipping before payment, etc.)
- [ ] **Authorization matrix** - subject x resource x action, mined from traces
- [ ] **Guided search** - MCTS over actions with the law residual as the fitness
      function, instead of the current template-driven probes
- [ ] **The benchmark** - `AuthzBugs-100`: 100 labelled authorization bugs with
      PoCs, patches and regression tests, published openly

## Non-goals

- Replacing a scanner: Mizan reports a narrow class of findings, but reports
  them with proof.
- Running against systems you are not authorized to test: the default target
  is a local twin of code you own.
