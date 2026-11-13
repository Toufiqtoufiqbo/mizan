"""Request accounting and budget semantics.

A scan sends requests in several phases. Reporting only the attack requests as
"the cost of the scan" is the kind of small lie that makes a tool hard to
trust, so every phase is counted separately and the total is the sum.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mizan.core import Principal, RequestBudgetExhausted
from mizan.engine import Mizan, Target
from mizan.learning import learn_from_spec
from mizan.validation import scan_application

APP = Path(__file__).resolve().parent / "fixtures" / "external_apps" / "flask_store"


def test_every_phase_is_counted() -> None:
    result = scan_application(APP, variant="clean", budget=60)
    assert result.error is None, result.error
    accounting = result.requests
    assert accounting.bootstrap == 2, "the two logins were not counted"
    assert accounting.learning > 0, "the learning traffic was not counted"
    assert accounting.attack > 0, "the attack traffic was not counted"
    assert accounting.total == accounting.bootstrap + accounting.learning + accounting.attack


def test_the_total_includes_the_learning_traffic() -> None:
    result = scan_application(APP, variant="clean", budget=60)
    accounting = result.requests
    assert accounting.total > accounting.attack, "the learning traffic is missing from the total"


def test_a_failed_attempt_is_accounted() -> None:
    """The learning phase counts what it tried, not only what succeeded."""

    from mizan.twin import Twin, TwinSpec, script_command

    root = Path(__file__).parent / "fixtures" / "external_apps" / "flask_store"
    workspace = Path(__file__).parent.parent.parent / ".pytest-accounting"
    workspace.mkdir(parents=True, exist_ok=True)
    twin = Twin(
        TwinSpec(
            command=script_command(root / "app.py", "--db", str(workspace / "a.sqlite"), "--port", "{port}"),
            workdir=workspace,
            data_paths=[workspace / "a.sqlite"],
            health_path="/health",
            health_timeout=60.0,
        ),
        workspace=workspace / "twin",
    )
    twin.start()
    try:
        from mizan.validation import _login

        token = _login(twin.base_url, "alice", "alice-secret")
        assert token
        learned = learn_from_spec(root / "openapi.json", twin.base_url, identities={"alice": token}, max_requests=10)
        # Every attempt is counted, successful or not.
        assert len(learned) <= 10, "the learning phase exceeded its budget"
        assert len(learned) == len([item for item in learned if "status" in item or "error" in item])
        # Some of the attempts failed - the paths with unknown identifiers.
        statuses = {item.get("status") for item in learned}
        assert 404 in statuses, "no attempt failed, the test proves nothing"
    finally:
        twin.stop()


def test_the_budget_stops_the_learning_phase() -> None:
    """A budget that is too small truncates the learning, and says so."""
    result = scan_application(APP, variant="clean", budget=4)
    assert result.setup_error is None
    accounting = result.requests
    assert accounting.total <= 4, "the scan sent more than the budget allowed"
    assert accounting.budget_exhausted is True, "the exhaustion was not reported"


def test_no_request_is_sent_after_the_budget_is_exhausted() -> None:
    class _Session:
        headers = {"Authorization": "Bearer token"}

        def request(self, *args, **kwargs):  # pragma: no cover - must not be reached
            raise AssertionError("a request was sent after the budget was exhausted")

    engine = Mizan(
        Target(base_url="http://127.0.0.1:1", principals=[Principal(id="alice", token="token")]),
        request_budget=0,
    )
    with pytest.raises(RequestBudgetExhausted):
        engine._request(_Session(), "GET", "http://127.0.0.1:1/x")
    assert engine.requests == 0


def test_the_exact_boundary_is_not_an_exhaustion() -> None:
    """A budget that is exactly enough is used up, not exceeded."""
    result = scan_application(APP, variant="clean", budget=15)
    accounting = result.requests
    assert accounting.total <= 15
    assert accounting.budget_exhausted is False, "a budget that was exactly sufficient was reported as exhausted"


def test_an_over_budget_scan_is_reported() -> None:
    result = scan_application(APP, variant="clean", budget=3)
    accounting = result.requests
    assert accounting.total <= 3
    assert accounting.budget_exhausted is True


def test_the_report_uses_the_terminology_of_the_counters() -> None:
    """The result must not call the attack count 'the requests'."""
    result = scan_application(APP, variant="clean", budget=60)
    data = result.to_dict()
    assert "requests" in data
    assert set(data["requests"]) >= {"bootstrap", "learning", "attack", "total", "budget"}
