"""Patch suggestions.

Mizan cannot rewrite somebody's code base safely, and it should not pretend
otherwise. What it can do is point at the exact place where the law is broken
and show the shape of the fix, together with the test that proves the fix
works. The suggestions are templates: they are meant to be adapted, and the
generated regression test is what decides whether the adaptation was correct.
"""

from __future__ import annotations

from dataclasses import dataclass

from mizan.core import Violation


@dataclass(frozen=True)
class PatchSuggestion:
    """A template for the fix of one finding."""

    law: str
    title: str
    where: str
    rationale: str
    diff: str

    def to_dict(self) -> dict[str, str]:
        return {
            "law": self.law,
            "title": self.title,
            "where": self.where,
            "rationale": self.rationale,
            "diff": self.diff,
        }


_L2 = PatchSuggestion(
    law="L2",
    title="Check the owner before returning the object",
    where="the handler that reads the object, before the response is built",
    rationale=(
        "The object was returned to a caller that does not own it. The check must happen "
        "on the server, next to the data, not in the client."
    ),
    diff="""--- a/handlers/orders.py
+++ b/handlers/orders.py
@@ def get_order(order_id, current_principal):
     order = await orders.get(order_id)
     if order is None:
         raise NotFound()
+    # The law: an object is only readable by its owner.
+    if order.owner_id != current_principal.id and not current_principal.is_admin:
+        raise Forbidden()
     return order
""",
)

_L3 = PatchSuggestion(
    law="L3",
    title="Check the owner inside the transaction that writes",
    where="the handler that writes the row",
    rationale=(
        "The write landed in a row owned by somebody else. The check and the write belong "
        "in one transaction, otherwise the row can change between them."
    ),
    diff="""--- a/handlers/orders.py
+++ b/handlers/orders.py
@@ def update_order(order_id, payload, current_principal):
-    order = await orders.get(order_id)
-    await order.update(**payload)
+    async with db.transaction():
+        # The lock makes the check and the write atomic.
+        order = await orders.get(order_id, for_update=True)
+        if order.owner_id != current_principal.id and not current_principal.is_admin:
+            raise Forbidden()
+        await order.update(**payload)
""",
)

_L4 = PatchSuggestion(
    law="L4",
    title="Decide which fields a client may write",
    where="the handler that updates the object from the request body",
    rationale=(
        "The client was able to write a field that carries authority. The server decides "
        "which fields exist, the client only supplies values."
    ),
    diff="""--- a/handlers/users.py
+++ b/handlers/users.py
@@ def update_me(payload, current_principal):
-    await current_principal.update(**payload)
+    # Only these fields may come from the client.
+    WRITABLE = {"name", "email"}
+    await current_principal.update(**{k: v for k, v in payload.items() if k in WRITABLE})
""",
)

_L5 = PatchSuggestion(
    law="L5",
    title="Make the check and the action one atomic statement",
    where="the handler that transitions the object",
    rationale=(
        "Two concurrent requests both applied the same transition. A conditional update "
        "gives exactly one winner; the loser gets a conflict."
    ),
    diff="""--- a/handlers/orders.py
+++ b/handlers/orders.py
@@ def approve_order(order_id, current_principal):
-    order = await orders.get(order_id)
-    if order.status != "pending":
-        raise Conflict()
-    order.status = "approved"
-    await order.save()
+    # One statement, one winner. The loser sees rowcount == 0.
+    result = await db.execute(
+        update(Order)
+        .where(Order.id == order_id, Order.status == "pending")
+        .values(status="approved")
+    )
+    if result.rowcount != 1:
+        raise Conflict()
""",
)

_L1 = PatchSuggestion(
    law="L1",
    title="Act as the identity the token claims",
    where="the place where the session is turned into a principal",
    rationale=(
        "The server acted as somebody else. The principal must come from the verified "
        "claims of the token, not from a stale mapping."
    ),
    diff="""--- a/auth/session.py
+++ b/auth/session.py
@@ def principal_for(token):
-    user = await users.get_by_session(session_id)
+    # The verified claims of the token decide who the caller is.
+    claims = jwt.verify(token, public_key, algorithms=["RS256"])
+    user = await users.get(claims["sub"])
""",
)

_BY_LAW = {"L1": _L1, "L2": _L2, "L3": _L3, "L4": _L4, "L5": _L5}


def suggest(violation: Violation) -> PatchSuggestion | None:
    """The suggested fix for a finding, if there is one."""
    return _BY_LAW.get(violation.law)


def render(violation: Violation) -> str | None:
    """The suggestion as text, ready to be written next to the evidence."""
    suggestion = suggest(violation)
    if suggestion is None:
        return None
    return f"""# Suggested fix - {violation.law}: {suggestion.title}

Where: {suggestion.where}

Why:
{suggestion.rationale}

This is a template, not an applied patch. Adapt it to your code base, then run the
generated regression test to prove the fix works.

```diff
{suggestion.diff.rstrip()}
```
"""
