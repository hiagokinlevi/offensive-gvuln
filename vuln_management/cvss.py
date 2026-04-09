"""
CVSS v3.1 base score calculator.

Implements the CVSS v3.1 specification base score formula exactly as defined in:
https://www.first.org/cvss/v3.1/specification-document

Only the Base Score is computed here — Temporal and Environmental scores require
additional context that must be provided by the analyst.

Metric values use official CVSS v3.1 single-letter abbreviations.
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum


# ── Attack Vector ────────────────────────────────────────────────────────────

class AttackVector(str, Enum):
    NETWORK          = "N"   # Remotely exploitable over a network
    ADJACENT         = "A"   # Requires access to the same network segment
    LOCAL            = "L"   # Requires local (physical or logged-in) access
    PHYSICAL         = "P"   # Requires physical access to the target


class AttackComplexity(str, Enum):
    LOW  = "L"   # No special conditions required
    HIGH = "H"   # Requires additional attacker-controlled prerequisites


class PrivilegesRequired(str, Enum):
    NONE  = "N"  # No privileges required
    LOW   = "L"  # Low-level privileges required (e.g., normal user account)
    HIGH  = "H"  # High-level privileges required (e.g., admin)


class UserInteraction(str, Enum):
    NONE     = "N"  # No user interaction required
    REQUIRED = "R"  # User must take some action for exploitation


class Scope(str, Enum):
    UNCHANGED = "U"  # Vulnerable component and impacted component are the same
    CHANGED   = "C"  # Exploit impacts components beyond the vulnerable component


class Impact(str, Enum):
    NONE = "N"
    LOW  = "L"
    HIGH = "H"


# ── CVSS v3.1 metric weights (from the specification) ────────────────────────

_AV_WEIGHTS = {
    AttackVector.NETWORK:  0.85,
    AttackVector.ADJACENT: 0.62,
    AttackVector.LOCAL:    0.55,
    AttackVector.PHYSICAL: 0.20,
}

_AC_WEIGHTS = {
    AttackComplexity.LOW:  0.77,
    AttackComplexity.HIGH: 0.44,
}

_PR_UNCHANGED_WEIGHTS = {
    PrivilegesRequired.NONE: 0.85,
    PrivilegesRequired.LOW:  0.62,
    PrivilegesRequired.HIGH: 0.27,
}

_PR_CHANGED_WEIGHTS = {
    PrivilegesRequired.NONE: 0.85,
    PrivilegesRequired.LOW:  0.68,
    PrivilegesRequired.HIGH: 0.50,
}

_UI_WEIGHTS = {
    UserInteraction.NONE:     0.85,
    UserInteraction.REQUIRED: 0.62,
}

_IMPACT_WEIGHTS = {
    Impact.NONE: 0.00,
    Impact.LOW:  0.22,
    Impact.HIGH: 0.56,
}


@dataclass
class CvssVector:
    """
    CVSS v3.1 base metric vector.

    All fields use the official metric abbreviations.
    """
    attack_vector:        AttackVector
    attack_complexity:    AttackComplexity
    privileges_required:  PrivilegesRequired
    user_interaction:     UserInteraction
    scope:                Scope
    confidentiality:      Impact
    integrity:            Impact
    availability:         Impact

    def to_vector_string(self) -> str:
        """Return the canonical CVSS v3.1 vector string."""
        return (
            f"CVSS:3.1/AV:{self.attack_vector.value}"
            f"/AC:{self.attack_complexity.value}"
            f"/PR:{self.privileges_required.value}"
            f"/UI:{self.user_interaction.value}"
            f"/S:{self.scope.value}"
            f"/C:{self.confidentiality.value}"
            f"/I:{self.integrity.value}"
            f"/A:{self.availability.value}"
        )


def calculate_base_score(vector: CvssVector) -> float:
    """
    Compute the CVSS v3.1 Base Score from a metric vector.

    Implements the exact formula from the CVSS v3.1 specification:
    https://www.first.org/cvss/v3.1/specification-document (Section 7.1)

    Args:
        vector: Populated CvssVector with all base metrics.

    Returns:
        Base score as a float rounded to one decimal place (0.0–10.0).
    """
    # Exploitability sub-score
    av  = _AV_WEIGHTS[vector.attack_vector]
    ac  = _AC_WEIGHTS[vector.attack_complexity]
    pr_map = _PR_CHANGED_WEIGHTS if vector.scope == Scope.CHANGED else _PR_UNCHANGED_WEIGHTS
    pr  = pr_map[vector.privileges_required]
    ui  = _UI_WEIGHTS[vector.user_interaction]
    ess = 8.22 * av * ac * pr * ui

    # Impact sub-score
    isc_c = _IMPACT_WEIGHTS[vector.confidentiality]
    isc_i = _IMPACT_WEIGHTS[vector.integrity]
    isc_a = _IMPACT_WEIGHTS[vector.availability]
    isc_base = 1.0 - (1.0 - isc_c) * (1.0 - isc_i) * (1.0 - isc_a)

    if vector.scope == Scope.UNCHANGED:
        iss = 6.42 * isc_base
    else:
        iss = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15.0

    # If there is no impact, score is 0
    if iss <= 0:
        return 0.0

    if vector.scope == Scope.UNCHANGED:
        base = min(iss + ess, 10.0)
    else:
        base = min(1.08 * (iss + ess), 10.0)

    # Round up to one decimal place (CVSS uses ceiling rounding)
    return _roundup(base)


def _roundup(value: float) -> float:
    """
    CVSS v3.1 'Roundup' function — ceiling to one decimal place.

    This is NOT standard Python rounding. CVSS rounds UP, so 3.75 → 3.8.
    """
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (int_input // 10000 + 1) / 10.0


def severity_rating(score: float) -> str:
    """
    Map a CVSS v3.1 base score to its qualitative severity rating.

    Ranges per CVSS v3.1 specification:
      None:     0.0
      Low:      0.1 – 3.9
      Medium:   4.0 – 6.9
      High:     7.0 – 8.9
      Critical: 9.0 – 10.0

    Args:
        score: CVSS base score (0.0–10.0).

    Returns:
        Severity rating string.
    """
    if score == 0.0:
        return "None"
    if score <= 3.9:
        return "Low"
    if score <= 6.9:
        return "Medium"
    if score <= 8.9:
        return "High"
    return "Critical"


def parse_vector_string(vector_str: str) -> CvssVector:
    """
    Parse a CVSS v3.1 vector string into a CvssVector.

    Accepts strings in the form:
      CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

    Args:
        vector_str: CVSS v3.1 vector string.

    Returns:
        Populated CvssVector.

    Raises:
        ValueError: If the string is malformed or contains unknown metric values.
    """
    if not vector_str.startswith("CVSS:3."):
        raise ValueError(f"Not a CVSS v3.x vector: {vector_str!r}")

    parts = dict(item.split(":", 1) for item in vector_str.split("/")[1:])

    try:
        return CvssVector(
            attack_vector=AttackVector(parts["AV"]),
            attack_complexity=AttackComplexity(parts["AC"]),
            privileges_required=PrivilegesRequired(parts["PR"]),
            user_interaction=UserInteraction(parts["UI"]),
            scope=Scope(parts["S"]),
            confidentiality=Impact(parts["C"]),
            integrity=Impact(parts["I"]),
            availability=Impact(parts["A"]),
        )
    except (KeyError, ValueError) as e:
        raise ValueError(f"Invalid CVSS vector: {e}") from e
