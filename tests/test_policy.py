"""Tests for ``agentguard.policy`` and ``agentguard.check``."""

from __future__ import annotations

import pytest

from agentguard import Policy, PolicyViolation, check, policy


def test_policy_returns_validated_object():
    p = policy({"network": {"allow": ["api.openai.com"]}})
    assert isinstance(p, Policy)
    assert p.violations == "throw"  # default
    assert p.network is not None
    assert p.network.allow == ("api.openai.com",)


def test_policy_invalid_violations_raises():
    with pytest.raises(TypeError):
        policy({"violations": "ignore"})


def test_policy_non_mapping_raises():
    with pytest.raises(TypeError):
        policy("nope")  # type: ignore[arg-type]


def test_policy_methods_uppercased():
    p = policy({"network": {"methods": ["get", "Post"]}})
    assert p.network.methods == ("GET", "POST")


def test_policy_allow_lowercased():
    p = policy({"network": {"allow": ["API.OpenAI.COM", "*.Example.COM"]}})
    assert p.network.allow == ("api.openai.com", "*.example.com")


def test_check_allow_when_in_allowlist():
    p = policy({"network": {"allow": ["api.openai.com"]}})
    d = check(p, "https://api.openai.com/v1/chat")
    assert d.action == "allow"


def test_check_deny_not_in_allowlist():
    p = policy({"network": {"allow": ["api.openai.com"]}})
    d = check(p, "https://evil.example.com/")
    assert d.action == "deny"
    assert d.reason == "not_in_allowlist"
    assert d.detail == "evil.example.com"


def test_check_wildcard_subdomain():
    p = policy({"network": {"allow": ["*.example.com"]}})
    assert check(p, "https://api.example.com/").action == "allow"
    assert check(p, "https://example.com/").action == "allow"
    assert check(p, "https://api.notexample.com/").action == "deny"


def test_check_global_wildcard():
    p = policy({"network": {"allow": ["*"]}})
    assert check(p, "https://anywhere.example/").action == "allow"


def test_check_deny_wins_over_allow():
    p = policy(
        {
            "network": {
                "allow": ["*.openai.com"],
                "deny": ["billing.openai.com"],
            }
        }
    )
    assert check(p, "https://api.openai.com/").action == "allow"
    blocked = check(p, "https://billing.openai.com/charge")
    assert blocked.action == "deny"
    assert blocked.reason == "denylist_match"


def test_check_method_blocking():
    p = policy({"network": {"allow": ["*"], "methods": ["GET"]}})
    assert check(p, "https://x.example/", {"method": "GET"}).action == "allow"
    blocked = check(p, "https://x.example/", {"method": "POST"})
    assert blocked.action == "deny"
    assert blocked.reason == "method_blocked"
    assert blocked.detail == "POST"


def test_check_invalid_url_returns_deny():
    p = policy({"network": {"allow": ["*"]}})
    d = check(p, "not-a-real-url")
    assert d.action == "deny"
    assert d.reason == "invalid_url"


def test_check_requires_normalized_policy():
    with pytest.raises(TypeError):
        check({"network": {"allow": []}}, "https://api.openai.com/")  # type: ignore[arg-type]


def test_check_default_method_is_get():
    # No init -> method defaults to GET
    p = policy({"network": {"allow": ["*"], "methods": ["GET"]}})
    assert check(p, "https://x.example/").action == "allow"


def test_policy_violation_carries_metadata():
    err = PolicyViolation("not_in_allowlist", "evil.com", "https://evil.com/", "GET")
    assert err.reason == "not_in_allowlist"
    assert err.url == "https://evil.com/"
    assert err.method == "GET"
    assert "blocked GET https://evil.com/" in str(err)


def test_policy_camelcase_max_requests_accepted():
    p = policy({"budget": {"maxRequests": 5}})
    assert p.budget.max_requests == 5


def test_policy_snake_case_max_requests_accepted():
    p = policy({"budget": {"max_requests": 7}})
    assert p.budget.max_requests == 7


def test_policy_negative_max_requests_raises():
    with pytest.raises(TypeError):
        policy({"budget": {"max_requests": -1}})


def test_policy_non_int_max_requests_raises():
    with pytest.raises(TypeError):
        policy({"budget": {"max_requests": "5"}})  # type: ignore[dict-item]


def test_policy_empty_spec_has_no_sections():
    p = policy({})
    assert p.network is None
    assert p.budget is None
    assert p.violations == "throw"


def test_policy_non_string_pattern_raises():
    with pytest.raises(TypeError):
        policy({"network": {"allow": [123]}})  # type: ignore[list-item]


def test_policy_empty_string_pattern_raises():
    with pytest.raises(TypeError):
        policy({"network": {"allow": [""]}})


def test_policy_network_not_mapping_raises():
    with pytest.raises(TypeError):
        policy({"network": ["api.openai.com"]})  # type: ignore[dict-item]


def test_policy_methods_not_list_raises():
    with pytest.raises(TypeError):
        policy({"network": {"methods": "GET"}})  # type: ignore[dict-item]


def test_check_empty_allowlist_denies_everything():
    # An explicit empty allowlist is a deny-all.
    p = policy({"network": {"allow": []}})
    d = check(p, "https://anywhere.example/")
    assert d.action == "deny"
    assert d.reason == "not_in_allowlist"


def test_check_no_network_allows_everything():
    p = policy({})
    assert check(p, "https://anywhere.example/").action == "allow"


def test_check_deny_only_allows_non_denied():
    p = policy({"network": {"deny": ["bad.example.com"]}})
    assert check(p, "https://ok.example.com/").action == "allow"
    blocked = check(p, "https://bad.example.com/")
    assert blocked.action == "deny"
    assert blocked.reason == "denylist_match"


def test_check_host_is_case_insensitive():
    p = policy({"network": {"allow": ["api.openai.com"]}})
    assert check(p, "https://API.OpenAI.COM/v1").action == "allow"


def test_check_ignores_port_and_credentials():
    p = policy({"network": {"allow": ["api.openai.com"]}})
    assert check(p, "https://user:pass@api.openai.com:443/v1").action == "allow"


def test_decision_is_dict_unpackable():
    p = policy({"network": {"allow": ["api.openai.com"]}})
    allowed = dict(check(p, "https://api.openai.com/"))
    assert allowed == {"action": "allow"}
    denied = dict(check(p, "https://evil.example/"))
    assert denied["action"] == "deny"
    assert denied["reason"] == "not_in_allowlist"
    assert denied["detail"] == "evil.example"
