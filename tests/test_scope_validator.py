"""Tests for ScopeValidator — exact, CIDR, wildcard, and out-of-scope cases."""
from __future__ import annotations
import pytest
from pentest_governance.scope_validator import ScopeValidator


SCOPE = [
    "app.example.com",
    "api.example.com",
    "10.0.1.0/24",
    "192.168.0.0/16",
    "*.staging.example.com",
    "*.internal.corp",
]


@pytest.fixture
def validator() -> ScopeValidator:
    return ScopeValidator(SCOPE)


class TestExactMatch:
    def test_exact_hostname_in_scope(self, validator):
        assert validator.validate("app.example.com") is True

    def test_exact_hostname_api_in_scope(self, validator):
        assert validator.validate("api.example.com") is True

    def test_exact_hostname_case_insensitive(self, validator):
        assert validator.validate("APP.EXAMPLE.COM") is True

    def test_unknown_hostname_not_in_scope(self, validator):
        assert validator.validate("evil.example.com") is False


class TestCIDRMatch:
    def test_ip_in_first_cidr(self, validator):
        """10.0.1.50 falls within 10.0.1.0/24."""
        assert validator.validate("10.0.1.50") is True

    def test_ip_at_cidr_boundary(self, validator):
        """10.0.1.254 is the last usable host in 10.0.1.0/24."""
        assert validator.validate("10.0.1.254") is True

    def test_ip_in_second_cidr(self, validator):
        """192.168.100.1 falls within 192.168.0.0/16."""
        assert validator.validate("192.168.100.1") is True

    def test_ip_outside_all_cidrs(self, validator):
        """172.16.0.1 is not in any authorized CIDR."""
        assert validator.validate("172.16.0.1") is False

    def test_ip_just_outside_cidr(self, validator):
        """10.0.2.1 is outside 10.0.1.0/24."""
        assert validator.validate("10.0.2.1") is False


class TestWildcardMatch:
    def test_wildcard_staging_subdomain(self, validator):
        assert validator.validate("dev.staging.example.com") is True

    def test_wildcard_qa_subdomain(self, validator):
        assert validator.validate("qa.staging.example.com") is True

    def test_wildcard_internal_corp(self, validator):
        assert validator.validate("jenkins.internal.corp") is True

    def test_wildcard_does_not_match_base_domain(self, validator):
        """The pattern *.staging.example.com should not match staging.example.com itself."""
        assert validator.validate("staging.example.com") is False

    def test_wildcard_case_insensitive(self, validator):
        assert validator.validate("DEV.STAGING.EXAMPLE.COM") is True


class TestOutOfScope:
    def test_completely_foreign_domain(self, validator):
        assert validator.validate("attacker.io") is False

    def test_similar_but_different_domain(self, validator):
        """example.org is not example.com."""
        assert validator.validate("app.example.org") is False

    def test_empty_string_is_not_in_scope(self, validator):
        assert validator.validate("") is False

    def test_ip_not_in_any_range(self, validator):
        assert validator.validate("8.8.8.8") is False
