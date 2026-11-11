"""Guided search: look for the action that breaks a law, instead of trying all of them.

The fixed probes are a list of hypotheses: "read somebody else's object", "write
into somebody else's row", "set a field that carries authority". They work, but
they are written down, and they only try the requests that a human thought of.

This module searches instead. It keeps a tree of executed request sequences and
uses UCT - the same rule Monte-Carlo tree search uses - to decide what to try
next: promising branches get visited more, unexplored branches get a bonus.

Two things make it possible to search over real requests:

* the **fitness** is the size of the breach, measured in the data, not a guess:
  a write into somebody else's row is worth more than a rejected request;
* the **state is restorable** (see :mod:`mizan.twin`), so every branch starts
  from the same application state and the search is reproducible.

The search also chains: identifiers found in a response are offered back to the
templates, so a sequence like "list the orders, then read one that is not yours"
is discovered rather than written down.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any

from mizan.core import Step, Violation
from mizan.races import looks_single_use

#: How much a breach is worth, per law. A breach that grants authority is
#: worth more than one that leaks a field.
SEVERITY_WEIGHT: dict[str, float] = {
    "L1": 6.0,
    "L2": 2.0,
    "L3": 3.0,
    "L4": 5.0,
    "L5": 4.0,
    "L6": 2.5,
    "L7": 1.5,
}


@dataclass(frozen=True)
class Action:
    """One request the search may send."""

    method: str
    path: str
    body: Any
    principal: str
    template: str
    kind: str = "other"
    #: How many copies of the request to send at the same time. Two identical
    #: requests that are both accepted is how a race looks from the outside.
    repeat: int = 1

    @property
    def key(self) -> tuple[str, str, str, str, int]:
        return (self.principal, self.method, self.path, str(self.body), self.repeat)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "body": self.body,
            "principal": self.principal,
            "template": self.template,
            "repeat": self.repeat,
        }


@dataclass
class Node:
    """A node of the search tree: one executed action."""

    action: Action | None
    parent: Node | None = None
    children: list[Node] = field(default_factory=list)
    untried: list[Action] = field(default_factory=list)
    visits: int = 0
    value: float = 0.0

    def best_child(self, exploration: float) -> Node | None:
        """The child with the best UCT score."""
        if not self.children:
            return None
        log_parent = math.log(max(1, self.visits))
        best = None
        best_score = -math.inf
        for child in self.children:
            exploitation = child.value / child.visits if child.visits else 0.0
            bonus = exploration * math.sqrt(log_parent / child.visits) if child.visits else math.inf
            score = exploitation + bonus
            if score > best_score:
                best_score = score
                best = child
        return best

    def path(self) -> list[Action]:
        """The actions from the root to this node."""
        actions: list[Action] = []
        node: Node | None = self
        while node is not None and node.action is not None:
            actions.append(node.action)
            node = node.parent
        return list(reversed(actions))


@dataclass
class SearchResult:
    """What the search found."""

    best_sequence: list[Action] = field(default_factory=list)
    violations: list[Violation] = field(default_factory=list)
    requests: int = 0
    iterations: int = 0

    @property
    def laws(self) -> set[str]:
        return {violation.law for violation in self.violations}


class GuidedSearch:
    """Search for the request sequence that breaks a law."""

    def __init__(
        self,
        engine: Any,
        *,
        budget: int = 40,
        depth: int = 2,
        exploration: float = 1.4,
        patience: int = 30,
        min_actions: int = 40,
        seed: int | None = 7,
    ) -> None:
        self.engine = engine
        self.budget = budget
        self.depth = depth
        self.exploration = exploration
        self.patience = patience
        self.min_actions = min_actions
        self.random = random.Random(seed)
        self.requests = 0
        self.violations: list[Violation] = []
        self._seen_violations: set[tuple[str, str | None, str | None]] = set()
        self._discovered_ids: list[str] = self._known_ids()
        #: What each template paid off - the bandit over action classes.
        self._template_gains: dict[str, list[float]] = {}
        self._counts: dict[str, int] = {}
        #: How many actions ago the search found something new.
        self._since_finding = 0
        self._root = Node(action=None)

    def _known_ids(self) -> list[str]:
        """The identifiers the learned policy already knows.

        They are the seeds of the search: without them the search can only
        follow identifiers it has just seen, and it would never try the
        resources that are still waiting.
        """
        identifiers: list[str] = []
        for key, resource in self.engine.policy.resources.items():
            if resource.id and resource.id not in identifiers:
                identifiers.append(resource.id)
        return identifiers

    # -- action space ------------------------------------------------------- #

    def _bodies(self, template: str, body: Any) -> list[Any]:
        """The bodies the search may send for a template.

        Besides the recorded body, it offers the variants that put a sentinel in
        an authority field - that is how a mass assignment becomes visible.
        """
        bodies: list[Any] = []
        if isinstance(body, dict):
            bodies.append(body)
            for field_name in sorted(self.engine._authority_fields()):
                variant = dict(body)
                variant[field_name] = f"mizan-probe-{field_name}"
                bodies.append(variant)
        else:
            bodies.append(body)
        return bodies

    def _principals_for(self, path: str) -> list[Any]:
        """The identities an action may use.

        The identity endpoints are tried with *every* identity, including the
        ones the application never used in the traffic: a server that resolves
        a token to the wrong account is exactly the kind of bug that hides in
        an unused identity.
        """
        identity_paths = self.engine._identity_paths()
        if path in identity_paths or any("{" not in known and known == path for known in identity_paths):
            return [principal for principal in self.engine.target.principals if principal.token]
        return [
            principal
            for principal in self.engine.target.principals
            if principal.token and self.engine._is_testable(principal)
        ]

    def _owned_ids(self, principal: str) -> list[str]:
        """The identifiers of the resources a principal owns.

        The policy knows who owns what, so the search does not have to guess:
        a concurrent pair belongs on the caller's *own* resource, where a
        one-shot action is supposed to be rejected the second time.
        """
        return [
            resource.id
            for resource in self.engine.policy.resources.values()
            if resource.owner == principal and resource.id
        ]

    def _paths_for(self, template: str, record_path: str, principal: str, *, own_only: bool) -> list[str]:
        """The concrete paths an action may use.

        The paths are built from the template and the identifiers the policy
        knows, not from the recorded path: a traffic log contains concrete
        paths, and `/orders/bob` is a path nobody meant to request.
        """
        if "{id}" not in template:
            return [record_path]
        identifiers: list[str] = []
        if own_only:
            identifiers.extend(self._owned_ids(principal))
        else:
            identifiers.extend(self._owned_ids(principal))
            identifiers.extend(
                resource.id
                for resource in self.engine.policy.resources.values()
                if resource.id and resource.id not in identifiers
            )
            identifiers.extend(identifier for identifier in self._discovered_ids if identifier not in identifiers)
        paths = [template.replace("{id}", identifier) for identifier in identifiers]
        if record_path and record_path not in paths:
            paths.append(record_path)
        return list(dict.fromkeys(paths))

    def initial_actions(self) -> list[Action]:
        """The actions the search may start with."""
        actions: list[Action] = []
        for (method, template), records in self.engine._examples().items():
            if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
                continue
            record = records[0]
            for principal in self._principals_for(record.path):
                for path_value in self._paths_for(template, record.path, principal.id, own_only=False):
                    for body in self._bodies(template, record.body):
                        actions.append(
                            Action(
                                method=method,
                                path=path_value,
                                body=body,
                                principal=principal.id,
                                template=template,
                                kind="read" if method in {"GET", "HEAD"} else "write",
                            )
                        )
                        actions.extend(self._race_variants(method, template, path_value, body, principal.id))
        return actions

    def _race_variants(self, method: str, template: str, record_path: str, body: Any, principal: str) -> list[Action]:
        """Two identical requests at the same time, on the caller's own resource.

        That is where a one-shot action must reject the second request.
        """
        if method not in {"POST", "PUT", "PATCH"}:
            return []
        variants: list[Action] = []
        for path in self._paths_for(template, record_path, principal, own_only=True):
            if not looks_single_use(path):
                continue
            variants.append(
                Action(
                    method=method,
                    path=path,
                    body=body,
                    principal=principal,
                    template=template,
                    kind="write",
                    repeat=2,
                )
            )
        return variants

    def expand(self, node: Node, path: list[Action]) -> list[Action]:
        """The actions that can follow the given path.

        Identifiers discovered on the way are offered back to the templates, so
        the search can chain: list, then read, then write.
        """
        actions: list[Action] = []
        for (method, template), records in self.engine._examples().items():
            if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
                continue
            record = records[0]
            for principal in self._principals_for(record.path):
                for path_value in self._paths_for(template, record.path, principal.id, own_only=False):
                    for body in self._bodies(template, record.body):
                        actions.append(
                            Action(
                                method=method,
                                path=path_value,
                                body=body,
                                principal=principal.id,
                                template=template,
                                kind="read" if method in {"GET", "HEAD"} else "write",
                            )
                        )
                        actions.extend(self._race_variants(method, template, path_value, body, principal.id))
        return actions

    # -- the search --------------------------------------------------------- #

    def run(self) -> SearchResult:
        """Run the search and return what it found."""
        root = self._root
        root.untried = self.initial_actions()
        self._restore()
        for _iteration in range(self.budget):
            node = self._select(root)
            if node is None:
                break
            if not node.untried:
                node.untried = self._untried_for(node)
                if not node.untried:
                    # Nothing new here: go back to the parent.
                    parent = node.parent
                    if parent is None:
                        break
                    parent.untried = parent.untried or self._untried_for(parent)
                    continue
            action = self._next_action(node)
            if action is None:
                break
            gain, _violations = self._execute(action)
            self._record_gain(action.template, gain)
            if gain > 0:
                self._since_finding = 0
            else:
                self._since_finding += 1
            child = Node(action=action, parent=node)
            node.children.append(child)
            self._backpropagate(child, gain)
            if self.patience and self.requests >= self.min_actions and self._since_finding >= self.patience:
                # Nothing new for a while: the search has converged.
                break
        best = self._best_node()
        sequence = best.path() if best is not None else []
        return SearchResult(
            best_sequence=sequence,
            violations=self.violations,
            requests=self.requests,
            iterations=self.budget,
        )

    def _untried_for(self, node: Node) -> list[Action]:
        """The actions that are still worth trying in this node."""
        tried = {action.key for action in self._tried(node)}
        candidates = self.expand(node, node.path())
        return [action for action in candidates if action.key not in tried]

    def _tried(self, node: Node) -> list[Action]:
        """Every action already tried in this subtree."""
        actions: list[Action] = []
        stack = [node]
        while stack:
            current = stack.pop()
            if current.action is not None:
                actions.append(current.action)
            stack.extend(current.children)
        return actions

    def _select(self, root: Node) -> Node | None:
        """Walk down the tree while the UCT rule prefers a visited child."""
        node = root
        while len(node.path()) < self.depth:
            if node.untried:
                return node
            child = node.best_child(self.exploration)
            if child is None:
                return node
            node = child
        return node

    def _priority(self, action: Action) -> int:
        """How promising an action looks, judged by the learned policy.

        The policy knows who owns what, so an action that crosses an ownership
        boundary is worth trying before an action that stays at home.
        """
        score = 0
        if action.repeat > 1:
            # A one-shot operation is the classic place for a race.
            score += 2
        if self.engine._is_identity_path(action.path):
            score += 1
        if "{id}" in action.template:
            identifier = action.path.rsplit("/", 1)[-1]
            for resource in self.engine.policy.resources.values():
                if resource.id == identifier and resource.owner and resource.owner != action.principal:
                    score += 2
                    break
        return score

    def _next_action(self, node: Node) -> Action | None:
        """Pick the next action to try in this node.

        The actions are grouped by template and the templates are chosen with
        UCB1: the ones that produced breaches are tried more, the ones that
        never did are tried rarely. Within a template, the most promising
        action goes first.
        """
        if not node.untried:
            return None
        groups: dict[str, list[Action]] = {}
        for action in node.untried:
            groups.setdefault(action.template, []).append(action)
        if len(groups) == 1:
            template = next(iter(groups))
        else:
            scores = {name: self._ucb(name) for name in groups}
            best = max(scores.values())
            # Fair exploration: when the templates are equally promising, the
            # next one is drawn at random instead of always the first.
            candidates = [name for name, score in scores.items() if score == best]

            # Among the equally promising templates, the one whose best action
            # looks most promising goes first.
            def potential(name: str) -> int:
                actions = groups[name]
                return max(self._priority(action) for action in actions)

            top = max(potential(name) for name in candidates)
            candidates = [name for name in candidates if potential(name) == top]
            template = candidates[self.random.randrange(len(candidates))]
        actions = groups[template]
        best = max(self._priority(action) for action in actions)
        candidates = [action for action in actions if self._priority(action) == best]
        index = self.random.randrange(len(candidates))
        action = candidates[index]
        actions.remove(action)
        # The action leaves the list of untried ones as well, otherwise it
        # would be picked again.
        self._forget(node, action)
        return action

    def _forget(self, node: Node, action: Action) -> None:
        """Remove an action from the untried list of a node."""
        node.untried = [candidate for candidate in node.untried if candidate.key != action.key]

    def _ucb(self, template: str) -> float:
        """The UCB1 score of a template."""
        gains = self._template_gains.get(template, [])
        total = max(1, sum(self._counts.values()))
        if not gains:
            # An untried template must be tried at least once. The tie is broken
            # at random, so every template gets its turn early.
            return math.inf
        mean = sum(gains) / len(gains)
        return mean + self.exploration * math.sqrt(math.log(total) / len(gains))

    def _record_gain(self, template: str, gain: float) -> None:
        """Remember what a template paid off."""
        self._template_gains.setdefault(template, []).append(gain)
        self._counts[template] = self._counts.get(template, 0) + 1

    def _execute(self, action: Action) -> tuple[float, list[Violation]]:
        """Send the action and measure the breach it causes."""
        if action.repeat > 1:
            return self._execute_concurrently(action)
        self.requests += 1
        response, violations, identifiers = self.engine.evaluate_action(
            action.principal, action.method, action.path, action.body
        )
        for identifier in identifiers:
            if identifier not in self._discovered_ids:
                self._discovered_ids.append(identifier)
        gain = 0.0
        fresh: list[Violation] = []
        for violation in violations:
            key = (violation.law, violation.principal, violation.resource)
            if key in self._seen_violations:
                continue
            self._seen_violations.add(key)
            fresh.append(violation)
            gain += SEVERITY_WEIGHT.get(violation.law, 1.0)
        self.violations.extend(fresh)
        return gain, fresh

    def _execute_concurrently(self, action: Action) -> tuple[float, list[Violation]]:
        """Send the same request twice at the same time.

        Two identical one-shot requests that are both accepted are the outside
        of a check-then-act race.
        """
        from mizan.races import run_concurrently

        principal = self.engine.target.principal(action.principal)
        if principal is None:
            return 0.0, []
        session = self.engine.target.session_for(principal)
        url = self.engine._url(action.path)

        def call():
            return session.request(
                action.method,
                url,
                json=action.body if action.body is not None else {},
                timeout=self.engine.target.timeout,
            )

        self.requests += action.repeat
        responses = run_concurrently([call for _ in range(action.repeat)])
        statuses = [getattr(response, "status_code", None) for response in responses]
        accepted = sum(1 for status in statuses if status is not None and 200 <= status < 300)
        if accepted < 2:
            return 0.0, []
        violation = Violation(
            law="L5",
            title="The same state transition was applied twice",
            detail=(
                f"Two concurrent `{action.method} {action.path}` requests were both accepted. "
                f"The operation looks single-use, so one of them should have been rejected."
            ),
            severity="high",
            principal=action.principal,
            resource=None,
            action="write",
            evidence={"statuses": statuses, "url": url},
        )
        violation.steps = [
            Step(
                method=action.method,
                url=url,
                headers={"Authorization": f"Bearer {principal.token}"} if principal.token else {},
                body=action.body,
                status=statuses[0] if statuses else None,
                note="first of two concurrent identical requests",
            ),
            Step(
                method=action.method,
                url=url,
                headers={"Authorization": f"Bearer {principal.token}"} if principal.token else {},
                body=action.body,
                status=statuses[1] if len(statuses) > 1 else None,
                note="second, concurrent - it should have been rejected",
            ),
        ]
        key = (violation.law, violation.principal, violation.resource)
        if key in self._seen_violations:
            return 0.0, []
        self._seen_violations.add(key)
        self.violations.append(violation)
        return SEVERITY_WEIGHT.get("L5", 4.0), [violation]

    def _backpropagate(self, node: Node, gain: float) -> None:
        """Share the result of an action with the path that led to it."""
        current: Node | None = node
        while current is not None:
            current.visits += 1
            current.value += gain
            current = current.parent

    def _best_node(self) -> Node | None:
        best: Node | None = None
        best_value = -math.inf
        stack = [self._root]
        while stack:
            node = stack.pop()
            if node.action is not None and node.value > best_value:
                best_value = node.value
                best = node
            stack.extend(node.children)
        return best

    def _restore(self) -> None:
        """Put the application back into the state the search starts from."""
        self.engine._restore()
