# Mīzān 0.2.2 — Self-Scan Audit

**Scope:** Phase 1 of the 0.2.2 mission - the correctness and the trustworthiness
of the self-scan.

---

## 1. What was wrong

| # | Defect | Where | Consequence |
|---|---|---|---|
| 1 | Both variants shared one workspace | `dogfood.scan_server` | the weakened run inherited the state of the clean run; a finding could come from the wrong run |
| 2 | The CLI printed `len(result.laws)` as the number of findings | `cli.self_scan` | two findings under one law were counted as one |
| 3 | The self-scan was not fail-closed | `dogfood.run_self_check` | a crash, a server that did not start, or a scan with zero requests could be reported as "clean" |
| 4 | `budget` did not affect the execution | `cli.self_scan` | the option was decoration |
| 5 | `--out` did not affect the execution | `cli.self_scan` | the option was decoration |
| 6 | A finding without a principal or a resource was accepted | `dogfood` | an unusable finding could pass the gate |
| 7 | The temporary workspaces were not removed | `dogfood.run_self_check` | processes and databases were left behind |

## 2. What changed

- **Isolation**: `run_self_check` gives each variant its own directory -
  `clean/` and `weakened/` - and each of them owns its database, its traffic
  log, its twin directory and its server process. The check `the two variants
  are isolated` compares the workspaces, and a test compares the database
  files.
- **Counts**: the result separates `finding_count`, `law_types`,
  `request_count`, `error` and `variant`. The CLI prints all five:

  ```text
  clean:
    findings: 0
    law types: []
    requests: 6

  weakened:
    findings: 2
    law types: ['L2']
    requests: 6
  ```

- **Fail-closed**: `run_self_check` evaluates eight named checks and reports
  them one by one. A failure is a failure - an exception in a scan is stored in
  `error` and fails the gate; it is never turned into an empty result.
- **Budget**: the engine grew a `request_budget`. When it is reached, the scan
  stops cleanly (`RequestBudgetExhausted`), and the budget is now a real limit
  on the number of requests.
- **`--out`**: the proof bundles of the findings are written to the directory.
- **Evidence**: a finding must name a principal, a resource and at least one
  reproduction step, otherwise the gate fails.

## 3. The bug the self-scan found in the engine

Making the self-scan fail-closed exposed a defect in the *engine*, not in the
harness: a `200` response with an **empty list** was reported as a disclosure.
The read probe accepted any successful response, without checking that the
object was actually in it.

```python
# before
if not (200 <= response.status_code < 300):
    continue
# after
if not contains_object(body, resource.id):
    continue
```

Without the fix, every successful request to a listing endpoint would have been
reported as a cross-identity read. The self-scan is what found it - no
synthetic test had.

## 4. Test coverage added

`tests/test_dogfood.py` (14 tests) covers:

- the two variants use separate workspaces and separate databases;
- the finding count and the law count are different numbers;
- a scanner error is not an empty result;
- an empty traffic log is rejected;
- the budget is enforced;
- the control plane scopes reads to the caller;
- the control plane refuses a mass assignment;
- the control plane refuses an unknown target;
- an unauthenticated caller is refused;
- no token is stored in plain text.

## 5. Result

| Check | Result |
|---|---|
| the clean control plane | PASS - 0 findings, 6 requests |
| the weakened control plane | PASS - 2 findings, law types `[L2]`, 6 requests |
| isolation | PASS - separate workspaces, databases, traffic logs, processes |
| the whole self-scan gate | PASS (8/8 checks) |
