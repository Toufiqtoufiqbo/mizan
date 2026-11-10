"""Schemathesis hooks module.

Load it with Schemathesis to get the law checks in every run::

    SCHEMATHESIS_HOOKS=mizan.schemathesis_hooks schemathesis run http://127.0.0.1:8000/openapi.json

or point a ``conftest.py`` at it::

    from mizan.schemathesis_hooks import register  # noqa: F401

The checks need two things:

``MIZAN_POLICY``
    Path to a policy learned with ``mizan learn``. Without it the checks fall
    back to a structural rule: a response must not contain an object owned by
    somebody else.

``MIZAN_LEDGER``
    Path to a ledger of attributed writes. With it, Mizan also reports
    write-side breaches (L3, L4) that no response-level check can see.
"""

from __future__ import annotations

from mizan.schemathesis_plugin import register

# Registering on import is what Schemathesis' hook loader expects.
register()

__all__ = ["register"]
