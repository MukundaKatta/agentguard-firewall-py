# agentguard-py

[![PyPI](https://img.shields.io/pypi/v/agentguard-py.svg)](https://pypi.org/project/agentguard-py/)
[![Python](https://img.shields.io/pypi/pyversions/agentguard-py.svg)](https://pypi.org/project/agentguard-py/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Network egress firewall for AI agents.** Declarative allow/deny list of hosts your agent tools may reach. Zero runtime dependencies.

Python port of [@mukundakatta/agentguard](https://github.com/MukundaKatta/agentguard).

## Install

```bash
pip install agentguard-py
```

## Usage

```python
from agentguard import policy, check, PolicyViolation

p = policy({
    "network": {
        "allow": ["api.openai.com", "*.anthropic.com"],
        "deny":  ["billing.openai.com"],
        "methods": ["GET", "POST"],
    },
})

decision = check(p, "https://api.openai.com/v1/chat", {"method": "POST"})
# Decision(action='allow')

decision = check(p, "https://evil.example.com/")
# Decision(action='deny', reason='not_in_allowlist', detail='evil.example.com')
```

## Plugging into HTTP clients

`check()` is the decision primitive. Wrap your favorite HTTP client around it:

```python
import httpx
from agentguard import policy, check, PolicyViolation

p = policy({"network": {"allow": ["api.openai.com"]}})

class GuardedClient(httpx.Client):
    def send(self, request, **kw):
        d = check(p, str(request.url), {"method": request.method})
        if d.action == "deny":
            raise PolicyViolation(d.reason, d.detail, str(request.url), request.method)
        return super().send(request, **kw)
```

## Pattern matching

| Pattern | Matches |
|---|---|
| `"api.openai.com"` | exact host |
| `"*.example.com"` | `example.com` and any subdomain (`api.example.com`, `*.api.example.com`, ...) |
| `"*"` | everything (handy as a catch-all in `deny`) |

Deny rules win over allow rules.

## API differences from the JS sibling

* No `firewall(spec, fn)` -- Python doesn't have AsyncLocalStorage / a clean global-fetch monkey-patching equivalent. Wire `check()` into your HTTP client of choice (see above).
* No `wrap_fetch()` for the same reason.
* `Policy`, `Decision`, and the inner network/budget objects are immutable dataclasses.
* `budget.maxRequests` is accepted as an alias for `budget.max_requests` for parity with the JS docs.

See the JS sibling's [README](https://github.com/MukundaKatta/agentguard) for the full design notes.
