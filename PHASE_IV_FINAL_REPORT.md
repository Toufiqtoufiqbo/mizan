# Mīzān Phase IV — Final Security Hardening & Evidence-Based Acceptance Report

**Branch:** `feat/opaque-identity-mapping`
**Commit (final, rebased onto current `main`):** `4f42d75` — "feat: opaque identity mapping that never invents an identity"
**Pre-rebase commit (preserved on local branch `phase4-pre-rebase-backup`):** `75b0b00`
**Base:** `origin/main` @ `6b700aa` (0.3.0 merged on 2026-11-15; the mission's original base `ee1045b` was an ancestor of it)
**Date:** 2026-11-15
**Environment:** Python 3.11.9 (fresh install; the machine's Python 3.12 MSI registration is corrupt and blocks reinstall), venv at `Temp\opencode\mizan-venv`, Ruff 0.17.5, pytest 9.2.0, schemathesis 4.33.4, `pgserver` (real local PostgreSQL), Node.js v26.13.1 for the Express fixture

---

## 1. Implementation

### What was audited
The prior agent had left uncommitted working-tree changes on top of `ee1045b`. The adversarial audit found **four destructive rewrites**:

1. `src/mizan/cli.py` — 13 commands reduced to 4 (`laws`, `learn`, `attack`, `twin`), with a "truncated for brevity" comment. `export_sarif`, `replay`, `self_scan`, `validate`, `compare`, `benchmark`, `regress`, `verify`, `demo` were all deleted. The `--identity-map` integration was added but **never wired into the RecordingProxy** — the proxy would have recorded everything as unattributed.
2. `src/mizan/identity.py` — `forge_unsigned` destroyed (its body was folded into dead code after an unconditional `return` inside `validate_principal_id`); a `return "unknown"` placeholder added to the resolver.
3. `src/mizan/proxy.py` — wholesale rewrite; X-User-Id rescue on bearer tokens; different identity semantics from the recorder.
4. `src/mizan/recorder.py` — `return "unknown"` for unattributable opaque tokens.

Additionally, an untracked `src/mizan/cli/` **package** shadowed `cli.py`, breaking `import mizan.cli` (the console-script entry point `mizan = "mizan.cli:main"`).

### What was repaired
- `src/mizan/cli/` package **deleted** (shadowing defect).
- `cli.py`, `proxy.py`, `recorder.py` **restored from HEAD** (`git checkout HEAD --`), then **surgical patches** applied. All 13 commands verified present in the committed tree (`main, laws, learn, attack, twin, export_sarif, replay, self_scan, validate, compare, benchmark, regress, verify, demo`).
- `identity.py` rewritten: HEAD content preserved (`decode_token`, `forge_unsigned` restored, `subject_of`) plus the new fail-closed identity-map API.

### New functionality (all committed)
| Component | Change |
|---|---|
| `identity.py` | `IdentityMapError`, `IdentityMap` (schema v1, roles), `parse_identity_map`, `load_identity_map`, `resolve_identity_map`, `resolve_principal` (shared resolver), `validate_principal_id`, `RESERVED_PRINCIPAL_IDS = {"unknown"}` |
| `recorder.py` | `identity_map` parameter; `_principal` tightened; `principal_from_token(token, identity_map)` delegates to the shared resolver; `MITM_ADDON` template regenerated with the same rules |
| `proxy.py` | Strict `MIZAN_IDENTITY_MAP` env parsing (`IdentityMapError` on set-but-invalid — no silent empty map); shared resolver; `_principal` documented 4-rule order |
| `cli.py` | `--identity-map` on `twin`; `--token` + `--identity-map` → `click.UsageError("use --token or --identity-map, not both")`; missing/empty env → exit 2, token-free message; resolved principals (with roles) → engine Target; `{token: principal}` → RecordingProxy |
| `learning.py` | `exclude_paths: Collection[str] = ()` parameter on `learn_from_spec` (merged onto 0.3.0's `spec: str | Path | dict` signature) |
| `validation.py` | `scan_application` passes `exclude_paths=("/login",)` |
| `flask_store/app.py` | Independent fixture now seeds `MIZAN_TOKEN_ALICE`/`MIZAN_TOKEN_BOB` out-of-band (INSERT OR REPLACE into its own tokens table) |

### Rebase onto current main (mandatory correction)
`origin/main` had advanced 13 commits (0.3.0 merged) and **touched the same files** (`learning.py`, `validation.py`, plus `core.py`/`engine.py`/`twin.py` reformatted, `conftest.py` added, cross-framework tests added). The work was **rebuilt on top of `origin/main`** (`4f42d75`) with the two conflicts (`learning.py`, `validation.py`) resolved by merging both sides: 0.3.0's `spec`-as-dict signature and budget accounting kept, our `exclude_paths` added. **All gates were then re-run from scratch on the rebased tree** (not carried over from the pre-rebase run). A first run showed 31 failures — all in `test_express_validation.py`, all with the same root cause: `Cannot find module 'express'` (the fixture's npm dependencies were never installed on this machine). Fixed by `npm ci` in `tests/fixtures/external_apps/express_store` — an **environment setup step from the 0.3.0 branch**, unrelated to our code. All 37 then passed; the full suite followed.

---

## 2. Test Collection Audit (the 303 → 178 question)

**Method:** identical pytest invocation on both trees; environment identical.

- `feat/opaque-identity-mapping` @ `ee1045b` (pristine HEAD): **collects exactly 178 tests** — verified by stashing all Phase IV working-tree changes, moving the shadowing `cli/` package aside, and running `pytest --collect-only -q`. The modified working tree collected the **same 178 tests, same test IDs, zero collection loss**.
- The 303 count came from the **other branch**: `feat/mizan-030-cross-framework-validation` @ `371b7bb`, which adds `test_cross_framework_benchmark.py` (+343 lines), `test_express_validation.py` (+427), `test_fastapi_validation.py` (+335), `test_validation_launch.py` (+471), plus express/fastapi fixtures ≈ **+125 tests**. `git diff --stat ee1045b 371b7bb -- tests/` proves this.
- **Update:** that branch was later merged into `main` (6b700aa), so the rebased tree legitimately collects **more** tests (main's 303-set + our 62 new). The audit's conclusion stands: Phase IV deleted/renamed/skipped nothing; the 303 was never "our" count.

**Conclusion:** no test was deleted, renamed, or skipped by Phase IV. Final tree: **365 tests** (main's set + 54 identity-map + 8 CLI-integration), all passing; the 15 PostgreSQL tests run for real (see §6).

---

## 3. Identity Semantics

### The core rule: no invented identities
`resolve_principal(token, identity_map)` — one implementation used by **all three recorders** (WSGI `Recorder`, `RecordingProxy`, MITM addon template):

1. token listed in the identity map → the **configured principal** (explicit configuration wins);
2. token is a readable JWT → its **subject** — documented as *extracted, not verified* (no signature check is performed; docstrings say so);
3. otherwise → **`None`**.

`"unknown"` is never returned by a recorder. Rationale proven in code: `engine.learn()` (engine.py:125–131) turns every non-empty `record.principal` into a real `Principal` — a fabricated `"unknown"` string would create a fake user that ownership reasoning treats as real. With `None`, the record stays in `TaintAnalyzer.unattributed` and unattributed writes are **never** reported as breaches (taint.py skips events whose principal is `None`/`UNKNOWN_PRINCIPAL`) — so unattributable traffic can only produce *inconclusive*, never PASS or a false positive.

Two unattributable tokens (Alice token-A, Bob token-B, both unknown) stay **two** `None` records — never conflated into one user. Pinned by `test_two_unattributed_tokens_are_never_conflated`.

The reserved sentinel `UNKNOWN_PRINCIPAL = "unknown"` (core.py) remains an engine-internal marker; a configured principal cannot claim it (`RESERVED_PRINCIPAL_IDS`, rejected at parse time).

### X-User-Id policy (consistent across all three recorders)
- Honored **only when no Authorization header at all** — the deployment's own caller signal.
- **Never consulted when a bearer token was presented** — a forged header can never attribute traffic to someone else, and an unknown opaque token stays `None` even with `X-User-Id: alice` present.
- Pinned by a 6-case parametrized matrix run against both the WSGI recorder and the proxy, plus an exec-based MITM addon test: `[("tok-a"+forged bob) → alice, ("tok-b"+forged alice) → bob, (unknown+forged) → None, (JWT+conflicting header) → alice, (no auth, X-User-Id) → alice, (no headers) → None]`.

---

## 4. Independent Validation (Phase D — real CLI, real app, opaque tokens)

`tests/test_opaque_cli.py` — 8 tests driving the **real `mizan twin --identity-map` command** through the full path **CLI → RecordingProxy → Recorder → traffic JSONL → Identity Mapping → Learning → attack/Validation → proof bundles**:

- Target: `tests/fixtures/external_apps/flask_store` — knows nothing about Mīzān: own Flask app, own SQLite DB, own OpenAPI document, **opaque random bearer tokens in its own database** (no JWTs).
- Tokens deployed out-of-band via `MIZAN_TOKEN_ALICE`/`MIZAN_TOKEN_BOB` (accepted by the app through its own tokens table).
- Identity map file contains **only environment-variable names**; tokens travel only through the process environment.
- All four variants proven end-to-end through the real CLI subprocess pipeline:
  - `clean` → **zero findings**
  - `read` → exactly **L2**, nothing else
  - `write` → exactly **L3**, nothing else
  - `both` → exactly **L2 and L3**
- Attribution proven: every learned request in the traffic log is attributed to `alice` or `bob` — the set of principals is exactly `{"alice", "bob"}` (no `None`, no `"unknown"`).
- Behavioral anti-forgery check against the real app process: forged `X-User-Id` + unknown token → 401; no token + `X-User-Id` → 401; the deployed opaque token without any user header → 200 as `alice`.

Result: **8/8 pass**.

---

## 5. Secret Leakage (Phase E)

Canary tokens — `MIZAN_SECRET_CANARY_ALICE_7F31` (Alice) and `MIZAN_SECRET_CANARY_BOB_9C42` (Bob) — are the **actual deployed bearer tokens** in the CLI integration tests. Every artifact Mīzān writes is scanned for them:

| Artifact | Canary check | Result |
|---|---|---|
| Traffic JSONL | grep | clean — attribution (`"principal": "alice"`) present, token value absent |
| Proof bundles (`*.json`) | grep | clean |
| SARIF export (`export-sarif` CLI on the produced bundles) | parsed + grep; document is valid SARIF 2.1.0 | clean |
| Any `.md` files in the workspace | grep | clean |
| CLI stdout | grep | clean |
| Identity-map error messages | unit tests | clean — messages name principals/env-var names, never token values (token-free by construction: the file format holds env names only) |
| Benchmark report artifacts | grep (`MIZAN_SECRET_CANARY\|opaque-alice\|opaque-bob`) | clean |

Also structural: the learning phase now **excludes `/login`** from recorded traffic (`exclude_paths`), so credential-exchange responses — which contain fresh tokens — can never enter the traffic log in the first place.

Result: **no canary appears in any artifact**.

---

## 6. Regression Results (exact counts)

Final gates, run on the exact committed rebased tree `4f42d75`:

```
pytest -q -p no:cacheprovider        →  365 passed, 0 failed, 0 skipped, 1 warning  (227.35s)
ruff check src/mizan tests           →  All checks passed!
ruff format --check src/mizan tests  →  62 files already formatted
git diff --check                     →  clean (exit 0)
```

- Breakdown: main's full set (including the 0.3.0 cross-framework tests) + **54 new identity-map tests** (`tests/test_identity_map.py`: 23 parametrized config-rejection cases, env resolution fail-closed cases, canary-in-error checks, shared resolver semantics, WSGI recorder behavior, 6-case recorder/proxy header-override matrix, MITM addon exec test, CLI fail-closed tests) + **8 CLI integration tests** + **15 PostgreSQL tests** (real local PostgreSQL via `pgserver`, previously skipped; the skip reason "pgserver is needed" is now satisfied — `pgserver` installed, so they run for real).
- No test was marked skip/xfail anywhere to beautify results; the single warning is a pre-existing third-party `StarletteDeprecationWarning` from fastapi's testclient, unrelated to Mīzān code.
- Ruff errors: **zero project errors, zero dependency errors** to distinguish — no `--ignore`/per-file exclusions were added; the only fixes were formatting/import-order in my own new test file.
- Environment note: the 31 initial express failures were a missing `npm ci` in the 0.3.0 fixture (fixed; all pass).

Benchmark (Phase H): `tests/test_benchmark.py` **8 passed in 34.08s** (part of the 365): every bug kind detected (`confused_identity`, `idor_read`, `idor_write`, `mass_assignment`, `race`), patched control applications produce **zero** findings, suite shape and report metrics hold. A real CLI run `mizan benchmark --size 10 --controls 2`:

```
L2 idor_read x2, L3 idor_write x2, L4 mass_assignment x2, L5 race x2, L1 confused_identity x2
Detection rate: 100% (10/10) | false positives on patched apps: 0/2
```

**Metrics & limitations:** the labelled benchmark applications exercise the five documented bug kinds and their exact patches; the control set is small (2 apps in the CLI run, the pinned set in the test suite); detection is exact-match on law type per application; runtime scales linearly with app count (34s for the full pinned suite at default size; the CLI run above took ~2 min). Findings are not guaranteed on *arbitrary* real-world code paths outside these labelled behaviors — the benchmark measures the engine against its own specification, not a third-party corpus.

---

## 7. GitHub

- **Branch pushed:** `feat/opaque-identity-mapping`
- **PR:** **#8** — https://github.com/Toufiqtoufiqbo/mizan/pull/8 (base `main`, head `feat/opaque-identity-mapping`, **open, not merged**)
- **Code commit verified by CI:** `4f42d750b69155925450279282458def16d8984b`
- **Actions run:** id **43750823953** (run #216), workflow `mizan`, `head_sha = 4f42d750b69155925450279282458def16d8984b` — **exactly the pushed HEAD** — status `completed`, conclusion **`success`**
  - https://github.com/Toufiqtoufiqbo/mizan/actions/runs/43750823953
  - Jobs (8): `A - static & unit` ✅ · `B - PostgreSQL` ✅ · `C - security regression` ✅ · `D - benchmark` ✅ · `E - Mizan scans Mizan` ✅ · `F - independent application` ✅ · `G - cross-framework gate` ✅ · `G - external target (opt-in)` ⏭️ *skipped by design* (it needs a real external target supplied by the operator; it contains no tests).
  - The **`No skipped tests`** steps passed in jobs A, B, C and G — the suite is not weakened anywhere.
  - The `G - cross-framework gate` job installs the Express fixture's dependencies from the lockfile — the same `npm ci` step we had to add locally (§1).
- The PR was **not merged** and no merge was attempted. No workaround, skip, or ignore was added to make any gate pass.

## 8. Known Limitations

1. **JWT subjects are extracted, not verified.** The resolver reads the `sub` claim without signature verification; this is documented in docstrings and tests. Identity maps exist precisely for tokens that carry no readable claims.
2. **`X-User-Id` fallback is inherently unauthenticated.** It is honored only when no Authorization header exists and is documented as the deployment's own signal; deployments that do not set this header should disable it (`user_id_header=None`).
3. **Python 3.12 uninstallable on this machine** (corrupt MSI registration, error 0x80070643); everything was validated on Python 3.11.9, which satisfies `requires-python >= 3.11`.
4. **GitHub connectivity is intermittently blocked from this network.** Direct `github.com`/`api.github.com` connections flap between working and timing out (443 and 22); the push used the session's configured GitHub token through a transient credential store (deleted after use), with retries until a route answered. Documented for reproducibility.
5. **Environment variables are read at resolution time** (`resolve_identity_map`), not re-read per request; changing a token mid-scan requires re-running the command. By design: one consistent identity view per scan.
6. The identity map schema is **v1 only**; a `version` bump is a fail-closed error, not a best-effort parse.
7. **Three files (`cli.py`, `proxy.py`, `flask_store/app.py`) are stored with CRLF line endings on `main`**; our commits normalized them to LF, so the PR diff shows those files as fully rewritten even though the semantic changes are small. Documented in the PR description.

## 9. Final Verdict

**READY FOR REVIEW**

Every mandated gate is satisfied with evidence, not assertion:

| Gate | Result |
|---|---|
| Phase A — test-collection audit | 178 → 178 identical on both trees; the 303 belonged to the other branch; nothing deleted/renamed/skipped |
| Phase B — unattributable identities | never conflated, never a placeholder; unknown ⇒ `None` ⇒ INCONCLUSIVE, never a false positive |
| Phase C — identity map & CLI | 12/12 cases: tokens never in file/errors/CLI output, no silent override, `--token`+`--identity-map` rejected, real `mizan twin --identity-map` exercised |
| Phase D — independent validation | 8/8 real-CLI integration tests over 4 variants (clean/read/write/both) against an opaque-token app with its own auth and DB |
| Phase E — secret leakage | canaries `MIZAN_SECRET_CANARY_ALICE_7F31` / `BOB_9C42` absent from traffic, bundles, SARIF, CLI output, benchmark artifacts |
| Phase F — `X-User-Id` | cannot become a trusted identity; identical rule in WSGI recorder, proxy and MITM addon; proven against the running app (401) |
| Phase G — full gates | **365 passed / 0 failed / 0 skipped** locally (incl. 15 real-PostgreSQL), ruff check + format clean, CI green on the pushed SHA (run 43750823953) |
| Phase H — benchmark | every bug kind detected; 0 false positives on patched controls; metrics and limits documented in §6 |
| Phase I — GitHub | branch pushed, one PR (#8) to `main`, Actions verified on the exact pushed SHA, **not merged** |

The only deviations from the letter of the mission are documented and justified in §8 (line-ending normalization of three pre-existing CRLF files; GitHub network reachability from this machine; the 0.3.0 branch's npm dependency step). No engine rewrite, no new framework, no new database, no deleted or weakened test, no expansion of AuthzBugs, no scope creep into 0.5.0.
