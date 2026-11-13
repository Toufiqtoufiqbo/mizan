# Mīzān 0.2.2.1 — Request Accounting and Budget Semantics

**Scope:** Phase 3 of the 0.2.2.1 mission.

---

## 1. What was wrong

The scan sends requests in three phases, and only one of them was counted:

| Phase | What it does | Counted before this phase |
|---|---|---|
| bootstrap | obtains the tokens from the application | **no** |
| learning | exercises the application's own endpoints to learn its rules | **no** |
| attack | the probes that look for a breach | yes (`engine.requests`) |

`ValidationResult.request_count` was `engine.requests` - the attack traffic
only. A report that said "6 requests" meant "6 attack requests", and the
learning traffic (10 requests in the same run) was invisible. The budget was
enforced for the attack phase only, so the learning phase could overrun it.

## 2. What changed

### 2.1 The accounting is explicit

```python
@dataclass
class RequestAccounting:
    bootstrap: int = 0  # the requests that obtained the tokens
    learning: int = 0  # the learning phase
    attack: int = 0  # the probes
    budget: int | None = None
    budget_exhausted: bool = False

    @property
    def total(self) -> int:
        return self.bootstrap + self.learning + self.attack
```

The result carries the whole structure, and `total` is the sum - it cannot
drift from the parts.

### 2.2 One budget covers learning and attack

The budget is now handed to the learning phase first
(`learn_from_spec(..., max_requests=...)`), and whatever is left of it becomes
the attack phase's budget:

```python
learning_budget = max(0, budget - accounting.bootstrap)
learned = learn_from_spec(spec_path, proxy.base_url, identities=tokens, max_requests=learning_budget)
accounting.learning = len(learned)
...
engine = Mizan(..., request_budget=max(0, budget - accounting.bootstrap - accounting.learning))
```

So the **total** number of requests a scan may send is the configured budget -
learning included.

### 2.3 Exhaustion is reported, not hidden

The engine records that it stopped early:

```python
except RequestBudgetExhausted:
    self.budget_exhausted = True
    break
```

and the harness carries it into the result
(`requests.budget_exhausted`). A truncated scan is not a complete one, and it
says so.

### 2.4 Every attempt is counted

The learning phase counts what it **tried**, not what succeeded: a request that
answered `404` or `422` is in the list and in the count. The attack phase
counts every request it sends, including the ones that are rejected - those are
exactly the ones that prove a check works.

## 3. Measured behaviour

On the independent Flask application (budget 60):

| Phase | Requests |
|---|---|
| bootstrap | 2 |
| learning | 10 |
| attack | 3 |
| **total** | **15** |

The same scan with a budget of 3:

| Phase | Requests |
|---|---|
| total | 3 |
| budget_exhausted | **true** |

The scan with a budget of 15 (exactly enough) reports
`budget_exhausted: false` - a budget that is exactly sufficient is used up,
not exceeded.

## 4. Acceptance tests

| Requirement | Test | Result |
|---|---|---|
| the counters increase exactly once per attempted request | `test_every_phase_is_counted`, `test_a_failed_attempt_is_accounted` | PASS |
| a failed HTTP attempt is accounted for | `test_a_failed_attempt_is_accounted` (the learning phase reaches `404`s, and they are counted) | PASS |
| no request is sent after the budget is exhausted | `test_no_request_is_sent_after_the_budget_is_exhausted` | PASS |
| the budget exhaustion is reported explicitly | `test_the_budget_stops_the_learning_phase`, `test_an_over_budget_scan_is_reported` | PASS |
| the learning traffic is not omitted from the total | `test_the_total_includes_the_learning_traffic` | PASS |
| the exact boundary and the over-budget case | `test_the_exact_boundary_is_not_an_exhaustion`, `test_an_over_budget_scan_is_reported` | PASS |
| the report uses the terminology of the counters | `test_the_report_uses_the_terminology_of_the_counters` | PASS |

## 5. Terminology

| Term | Meaning |
|---|---|
| bootstrap requests | the logins that obtain the tokens |
| learning requests | the requests that exercise the endpoints to learn the rules |
| attack requests | the requests the probes send |
| total requests | the sum of the three |
| budget | the maximum number of requests the whole scan may send |
| budget exhausted | the scan stopped because the budget ran out |

The CLI, the API and the reports use these words. `request_count` no longer
means "the whole scan" - it means the attack traffic, and the total is
`requests.total`.

## 6. What is not covered

- The budget counts **requests**, not bytes or CPU time. A single very large
  response is one request.
- The budget is per scan. There is no global budget across the scans of a
  project - the control plane does not expose one yet.
