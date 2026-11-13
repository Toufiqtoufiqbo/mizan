# Mīzān 0.3.0 — limitations and the architecture audit

**Date:** 2026-11-13
**Repository:** `Toufiqtoufiqbo/mizan`

This file states what the 0.3.0 milestone **does not** prove, and audits the
seams the milestone depends on. It is the companion to
`reports/MIZAN_0.3.0_CROSS_FRAMEWORK_RESULTS.md`, which states what it does
prove.

---

## 1. What this milestone proves

- **Detection behaviour against the tested FastAPI application** - four
  isolated variants, the expected law in each, every finding's evidence
  validated.
- **Detection behaviour against the tested Express application** - the same
  four variants, the same expected laws.
- **L2 and L3 isolation** - disabling one ownership check produces one law;
  disabling both produces both; the clean application produces none.
- **Evidence reproduction and validation** - 24 of 24 findings were replayed
  against the state the scan left behind, with the principal's own token.
- **Measured benchmark results** - three independent repetitions of the whole
  matrix, with raw counts.

## 2. What this milestone does **not** prove

| Not proven | Why |
|---|---|
| universal FastAPI compatibility | one fixture, one FastAPI version (0.162.4), one Pydantic version. A different application may use the schema differently. |
| universal Express compatibility | one fixture, Express 4.21.2, Node 26.13.1 (also verified on 24.20.0). Express 5 was not tested. |
| support for every authentication scheme | both fixtures use opaque bearer tokens. JWTs, API keys, mTLS, cookies and OAuth were not exercised in this phase. |
| multi-database attribution | both fixtures write SQLite. The attributor is SQLite-specific; PostgreSQL exists as a separate adapter and was not used here. |
| arbitrary black-box HTTP-only identity attribution | the harness is given a token→principal map through a documented local test interface. Without it, an opaque token carries no identity. |
| L1, L4, L5, L6 or L7 general support | only L2 and L3 were in scope. The other probes did not fire on either fixture, and their absence is not evidence that they work. |
| production readiness | the fixtures are controlled and small; nothing here says how Mīzān behaves against a large or a hostile application. |
| real-world customer deployment performance | there is no customer deployment. The benchmark measures two fixtures, and is not statistically representative of anything else. |
| a shared OpenAPI generator across frameworks | FastAPI generates its own document; Express ships a hand-written one. The *harness* consumes both identically, but the two fixtures do not share a document generator. |

---

## 3. The architecture audit

The mission asks for the dependencies to be stated rather than hidden. Here
they are, module by module.

### 3.1 Framework-independent

| Part | Where | Why it is framework-independent |
|---|---|---|
| the law detectors `L2`, `L3` | `mizan/engine.py` | they work on an HTTP response and on a database diff. Nothing in them knows about Flask, FastAPI or Express. |
| the traffic proxy and the identity map | `mizan/proxy.py` | it records ordinary HTTP and labels it with a map it is given. |
| the learning phase | `mizan/learning.py` | it walks an OpenAPI document and sends the smallest possible request for every operation. |
| the twin | `mizan/twin.py` | it starts a process on a free port and snapshots its data. |
| the SARIF export and the CLI | `mizan/sarif.py`, `mizan/cli.py` | they read a result. |
| the launch contract | `mizan/validation.py` | `LaunchSpec` describes *how* to start something, not *what* it is. |

### 3.2 Database-specific

| Part | Where | Dependency |
|---|---|---|
| the write attributor | `mizan/attribution.py` → `SqliteAttributor` | it diffs a SQLite file. **Both fixtures in this phase use SQLite, so the attribution path was shared.** The phase therefore tests *framework* diversity, not *storage* diversity. |
| the attributor selection | `mizan/validation.py` → `_attributor_for` | it raises for anything that is not SQLite, rather than silently guessing. |

### 3.3 Application-specific

| Part | Where | Dependency |
|---|---|---|
| the launch registry | `mizan/validation.py` → `LAUNCH_REGISTRY` | it maps three **fixture directory names** to their launch specifications. It is a test registry, not a discovery mechanism: Mīzān does not look at an application's source to decide how to attack it. |
| the credentials | `mizan/validation.py` → the default `credentials` | the harness's default pairs match the fixtures' test credentials. An application with different ones is given different ones explicitly. |
| the contract | `tests/fixtures/external_apps/contract/CONTRACT.md` | the two applications agree on it; Mīzān does not read it at run time. |

### 3.4 Dependent on an explicitly supplied identity mapping

| Part | Where | Dependency |
|---|---|---|
| the identity map | `mizan/proxy.py` → `RecordingProxy(identity_map=...)` | the harness tells the proxy which opaque token belongs to which principal, after the application issued them through its own `POST /login`. |
| the principals | `mizan/validation.py` | the same mapping becomes the engine's `Principal` list. |

**This is the single most important caveat of the phase.** An opaque token
says nothing about who holds it. Mīzān learns the relationship the same way a
tester would - by logging in - and the mapping is passed in explicitly. It is
a documented local test interface, **not** an authentication bypass: the
application still authenticates every request against its own store, and the
map is used only to label traffic and to decide who is attacking whom.

### 3.5 What the phase did **not** do

- Mīzān did not read the fixtures' source to decide which vulnerabilities to
  look for. The expected answer comes from the launch flag, and the fixtures'
  behaviour is checked over HTTP, independently, before Mīzān is involved.
- Mīzān did not import anything from either fixture, and neither fixture
  imports Mīzān.
- No framework-specific detection shortcut was added. The engine's code for
  `L2` and `L3` is unchanged by this milestone.

---

## 4. The new interfaces this phase added

Three narrow seams, each with unit tests in `tests/test_validation_launch.py`:

| Interface | What it is | Why it was needed |
|---|---|---|
| `LaunchSpec` / `SpecSource` | a launch contract: command, entry point, database, variant flag, environment, and where the OpenAPI document comes from | a Node application cannot be started by a Python convention |
| `build_command` / `environment_for` | one place where the launch command and the environment are resolved | a caller that starts an application itself (the benchmark's replay) must use exactly the same path as the harness |
| `keep_workspace` / `observer` on `scan_application` | keep the temporary directory, and look at the running application | the benchmark has to replay a finding against the same state, and measure the application's own peak memory |

None of them changes what Mīzān detects.

---

## 5. Measurement limitations

| Metric | How it was measured | Caveat |
|---|---|---|
| wall-clock time | `time.perf_counter()` around the scan | includes the application's startup; the machine is a four-core laptop, not a server |
| peak memory | the Windows kernel's `PeakWorkingSetSize` for the **application** process | it is the application's memory, not Mīzān's, and not the sum of the two |
| request counts | the harness's own accounting: bootstrap, learning, attack | the learning count depends on the credential scheme - see the cross-framework report |
| reproducibility | three independent repetitions, each with its own workspace, database and credentials | a repetition is not a statistical sample; three runs show stability, not a confidence interval |

---

## 6. The state of the work

The dependency gate is **still not satisfied**: PR #6 is open. The 0.3.0 work
therefore exists only in the local working tree, and
`feat/mizan-030-cross-framework-validation` has **not** been created. The
branch must be created from the default branch, after PR #6 lands.
