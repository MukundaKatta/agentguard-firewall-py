"""Policy declaration + checker.

A policy is a plain dict with three optional sections:

    {
        "network": {"allow": [...], "deny": [...], "methods": [...]},
        "budget": {"max_requests": int},
        "violations": "throw" | "block",
    }

Patterns supported in ``network.allow`` / ``network.deny``:

* exact host:           ``"api.openai.com"``
* wildcard subdomain:   ``"*.example.com"`` (matches example.com and any subdomain)
* global wildcard:      ``"*"`` (matches everything; useful as catch-all in deny)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Mapping, Optional, Union
from urllib.parse import urlsplit


@dataclass(frozen=True)
class _NetworkPolicy:
    allow: Optional[tuple]  # tuple[str, ...] or None
    deny: Optional[tuple]
    methods: Optional[tuple]


@dataclass(frozen=True)
class _BudgetPolicy:
    max_requests: Optional[int] = None


@dataclass(frozen=True)
class Policy:
    """Validated, immutable policy.

    Build via :func:`policy` -- never construct directly so the spec stays
    validated.
    """

    network: Optional[_NetworkPolicy]
    budget: Optional[_BudgetPolicy]
    violations: str  # 'throw' | 'block'


@dataclass(frozen=True)
class Decision:
    """Decision returned by :func:`check`.

    ``action`` is ``"allow"`` or ``"deny"``. When deny, ``reason`` and
    ``detail`` carry a stable code + human-readable explanation.
    """

    action: str
    reason: Optional[str] = None
    detail: Optional[str] = None

    def __iter__(self):  # support dict-unpack-style use
        yield ("action", self.action)
        if self.reason is not None:
            yield ("reason", self.reason)
        if self.detail is not None:
            yield ("detail", self.detail)


def policy(spec: Mapping[str, Any]) -> Policy:
    """Validate + normalize a policy spec. Raises ``TypeError`` if malformed."""
    if not isinstance(spec, Mapping):
        raise TypeError("policy: spec must be a mapping (dict)")

    net_spec = spec.get("network")
    network = _normalize_network(net_spec) if net_spec is not None else None

    budget_spec = spec.get("budget")
    budget = _normalize_budget(budget_spec) if budget_spec is not None else None

    violations = spec.get("violations", "throw")
    if violations not in ("throw", "block"):
        raise TypeError(
            "policy: violations must be 'throw' or 'block', got " + repr(violations)
        )

    return Policy(network=network, budget=budget, violations=violations)


def _normalize_network(net: Mapping[str, Any]) -> _NetworkPolicy:
    if not isinstance(net, Mapping):
        raise TypeError("policy.network must be a mapping")
    allow = _to_pattern_list(net.get("allow"), "network.allow") if net.get("allow") is not None else None
    deny = _to_pattern_list(net.get("deny"), "network.deny") if net.get("deny") is not None else None
    methods = None
    if net.get("methods") is not None:
        m = net["methods"]
        if not isinstance(m, (list, tuple)):
            raise TypeError("policy.network.methods must be a list or tuple")
        methods = tuple(str(x).upper() for x in m)
    return _NetworkPolicy(allow=allow, deny=deny, methods=methods)


def _normalize_budget(b: Mapping[str, Any]) -> _BudgetPolicy:
    if not isinstance(b, Mapping):
        raise TypeError("policy.budget must be a mapping")
    max_req = b.get("max_requests")
    # Accept JS-style camelCase as a convenience.
    if max_req is None and "maxRequests" in b:
        max_req = b["maxRequests"]
    if max_req is not None:
        if not isinstance(max_req, int) or max_req < 0:
            raise TypeError("policy.budget.max_requests must be a non-negative int")
    return _BudgetPolicy(max_requests=max_req)


def _to_pattern_list(value, label: str) -> tuple:
    if not isinstance(value, (list, tuple)):
        raise TypeError(label + " must be a list of host patterns")
    out = []
    for p in value:
        if not isinstance(p, str) or not p:
            raise TypeError(label + " entries must be non-empty strings")
        out.append(p.lower())
    return tuple(out)


def check(
    policy: Policy,
    url: Union[str, Any],
    init: Optional[Mapping[str, Any]] = None,
) -> Decision:
    """Pure decision function. No side effects.

    Returns a :class:`Decision`. Use this if you want to enforce the policy
    in a transport other than the built-in adapters (e.g. an HTTP/2 client).
    """
    if not isinstance(policy, Policy):
        raise TypeError(
            "check: policy must be a normalized Policy (use policy() first)"
        )

    init = init or {}
    method = str(init.get("method") or "GET").upper()

    try:
        parsed = urlsplit(str(url))
        if not parsed.hostname:
            raise ValueError("missing host")
    except Exception:
        return Decision(action="deny", reason="invalid_url", detail=str(url))

    hostname = parsed.hostname.lower()

    if policy.network and policy.network.methods is not None:
        if method not in policy.network.methods:
            return Decision(action="deny", reason="method_blocked", detail=method)

    # deny rules win over allow rules
    if policy.network and policy.network.deny:
        for pattern in policy.network.deny:
            if _match_host(hostname, pattern):
                return Decision(
                    action="deny",
                    reason="denylist_match",
                    detail=hostname + " matches " + pattern,
                )

    if policy.network and policy.network.allow is not None:
        allowed = any(_match_host(hostname, p) for p in policy.network.allow)
        if not allowed:
            return Decision(action="deny", reason="not_in_allowlist", detail=hostname)

    return Decision(action="allow")


def _match_host(host: str, pattern: str) -> bool:
    h = host.lower()
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return h == suffix or h.endswith("." + suffix)
    return h == pattern
