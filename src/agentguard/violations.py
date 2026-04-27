"""PolicyViolation -- raised when a request is denied by an agentguard policy."""

from __future__ import annotations


class PolicyViolation(Exception):
    """Raised by enforcing wrappers when a request is denied.

    Attributes:
        reason: Stable short code (e.g. ``"not_in_allowlist"``,
            ``"denylist_match"``, ``"budget_exceeded"``, ``"method_blocked"``,
            ``"invalid_url"``).
        detail: Human-readable detail.
        url: The URL that was blocked.
        method: HTTP method (uppercase).
    """

    def __init__(self, reason: str, detail: str, url: str, method: str) -> None:
        super().__init__(
            "agentguard: blocked " + method + " " + url + " -- " + reason + ": " + detail
        )
        self.name = "PolicyViolation"
        self.reason = reason
        self.detail = detail
        self.url = url
        self.method = method
