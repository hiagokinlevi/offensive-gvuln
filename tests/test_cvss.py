"""
Tests for CVSS v3.1 base score calculator.

Reference scores from the CVSS v3.1 specification examples and NIST NVD.
"""
from vuln_management.cvss import (
    CvssVector, AttackVector, AttackComplexity, PrivilegesRequired,
    UserInteraction, Scope, Impact, calculate_base_score, severity_rating,
    parse_vector_string,
)


def _vec(av=AttackVector.NETWORK, ac=AttackComplexity.LOW, pr=PrivilegesRequired.NONE,
         ui=UserInteraction.NONE, s=Scope.UNCHANGED,
         c=Impact.HIGH, i=Impact.HIGH, a=Impact.HIGH) -> CvssVector:
    return CvssVector(
        attack_vector=av, attack_complexity=ac, privileges_required=pr,
        user_interaction=ui, scope=s, confidentiality=c, integrity=i, availability=a,
    )


def test_perfect_10():
    """AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0"""
    v = _vec(s=Scope.CHANGED)
    assert calculate_base_score(v) == 10.0


def test_high_score():
    """AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8"""
    v = _vec()
    assert calculate_base_score(v) == 9.8


def test_medium_score():
    """AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N → lower score"""
    v = _vec(
        av=AttackVector.LOCAL, ac=AttackComplexity.HIGH,
        pr=PrivilegesRequired.HIGH, ui=UserInteraction.REQUIRED,
        s=Scope.UNCHANGED, c=Impact.LOW, i=Impact.LOW, a=Impact.NONE,
    )
    score = calculate_base_score(v)
    assert 1.0 <= score <= 5.0


def test_no_impact_is_zero():
    """Zero impact across C/I/A → score 0.0"""
    v = _vec(c=Impact.NONE, i=Impact.NONE, a=Impact.NONE)
    assert calculate_base_score(v) == 0.0


def test_severity_ratings():
    assert severity_rating(0.0)  == "None"
    assert severity_rating(3.9)  == "Low"
    assert severity_rating(4.0)  == "Medium"
    assert severity_rating(6.9)  == "Medium"
    assert severity_rating(7.0)  == "High"
    assert severity_rating(9.0)  == "Critical"
    assert severity_rating(10.0) == "Critical"


def test_vector_string_roundtrip():
    v = _vec(s=Scope.CHANGED, c=Impact.LOW)
    vector_str = v.to_vector_string()
    assert vector_str.startswith("CVSS:3.1/")
    parsed = parse_vector_string(vector_str)
    assert parsed.scope == Scope.CHANGED
    assert parsed.confidentiality == Impact.LOW


def test_parse_known_vector():
    """Parse a well-known NVD vector string."""
    v = parse_vector_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert v.attack_vector == AttackVector.NETWORK
    assert calculate_base_score(v) == 9.8


def test_parse_invalid_raises():
    import pytest
    with pytest.raises(ValueError):
        parse_vector_string("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C")
