import pytest

from glep.scope import ScopeError, check_target


def test_loopback_is_allowed_without_flags():
    decision = check_target("127.0.0.1")
    assert decision.allowed
    assert decision.kind == "loopback"


def test_private_requires_authorized():
    blocked = check_target("192.168.1.10")
    assert not blocked.allowed
    assert blocked.kind == "private"

    allowed = check_target("192.168.1.10", authorized=True)
    assert allowed.allowed


def test_public_requires_authorized_and_allow_public():
    assert not check_target("8.8.8.8", authorized=True).allowed
    assert not check_target("8.8.8.8", allow_public=True).allowed
    assert check_target("8.8.8.8", authorized=True, allow_public=True).allowed


def test_unspecified_is_rejected():
    decision = check_target("0.0.0.0")
    assert not decision.allowed
    assert decision.kind == "invalid"


def test_unresolvable_host_raises():
    with pytest.raises(ScopeError):
        check_target("this-host-should-not-resolve.invalid")
