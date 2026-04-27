"""agentguard -- network egress firewall for AI agents.

Public surface (mirrors the JS sibling, minus the global ``fetch`` patch
which doesn't have a clean Python equivalent):

    from agentguard import policy, check, Policy, PolicyViolation

* ``policy(spec)`` -- normalize + validate a policy declaration.
* ``check(policy, url, init=None)`` -- pure decision function.
* ``Policy`` -- the validated, immutable policy dataclass.
* ``PolicyViolation`` -- exception raised when a request is denied.

Python users typically wire this into ``httpx``/``requests`` via a transport
or session adapter rather than monkey-patching globals. ``check()`` is the
primitive you'd call from such a wrapper.
"""

from .policy import Decision, Policy, check, policy
from .violations import PolicyViolation

__version__ = "0.1.0"
VERSION = __version__

__all__ = [
    "VERSION",
    "Decision",
    "Policy",
    "PolicyViolation",
    "check",
    "policy",
]
