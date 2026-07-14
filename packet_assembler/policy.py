"""The policy gate: seven named, independent rules.

Each rule is a small function that takes the assembled packet and returns
``(passed, reason)``. Rules are intentionally *not* implemented as a schema
validator: keeping them as explicit, individually named functions makes the
gate auditable — every accept/reject decision maps to a specific rule with a
human-readable reason.

The gate is fail-closed: :func:`evaluate` reports the result of *every* rule so
that a rejection lists all failures at once, and a packet is released only when
no rule fails.
"""

from __future__ import annotations

import re
from datetime import datetime

# C- followed by exactly three digits, e.g. C-007.
_COMPONENT_ID_RE = re.compile(r"^C-\d{3}$")

# A valid fail-closed behaviour must describe what happens to requests when the
# component fails; we require at least one of these outcome words.
_FAIL_CLOSED_KEYWORDS = ("rejected", "blocked", "denied", "refused")


def _text(value):
    """Return ``value`` as a stripped string, or '' if it is missing/None."""
    if value is None:
        return ""
    return str(value).strip()


def rule_001_component_id(packet):
    """component_id must be present and match the format C-NNN (3 digits)."""
    value = packet.get("component_id")
    if not isinstance(value, str) or not _COMPONENT_ID_RE.match(value):
        return False, "component_id must be present and match format C-NNN (3-digit number)"
    return True, "component_id is present and matches C-NNN"


def rule_002_release(packet):
    """release must be exactly 'Release1-MVP'."""
    if packet.get("release") != "Release1-MVP":
        return False, 'release must be exactly "Release1-MVP"'
    return True, "release is Release1-MVP"


def rule_003_owns(packet):
    """owns must be non-empty and must not contain 'TBD' or 'TODO'."""
    value = _text(packet.get("owns"))
    if not value:
        return False, "owns must be non-empty"
    upper = value.upper()
    if "TBD" in upper or "TODO" in upper:
        return False, 'owns must not contain a placeholder ("TBD" or "TODO")'
    return True, "owns is non-empty and free of placeholders"


def rule_004_does_not_own(packet):
    """does_not_own must be non-empty; the literal value 'None' is rejected."""
    value = _text(packet.get("does_not_own"))
    if not value:
        return False, "does_not_own must be non-empty"
    if value.lower() == "none":
        return False, 'does_not_own must be explicit; the value "None" is not acceptable'
    return True, "does_not_own states explicit non-responsibilities"


def rule_005_fail_closed(packet):
    """fail_closed_behaviour must be non-empty and describe a closed outcome."""
    value = _text(packet.get("fail_closed_behaviour"))
    if not value:
        return False, "fail_closed_behaviour must be non-empty"
    lowered = value.lower()
    if not any(keyword in lowered for keyword in _FAIL_CLOSED_KEYWORDS):
        return (
            False,
            "fail_closed_behaviour must describe what happens to requests on failure "
            '(contain one of: "rejected", "blocked", "denied", "refused")',
        )
    return True, "fail_closed_behaviour describes a fail-closed outcome"


def rule_006_acceptance_tests(packet):
    """acceptance_tests must be a non-empty list."""
    value = packet.get("acceptance_tests")
    if not isinstance(value, list) or len(value) == 0:
        return False, "acceptance_tests must be a non-empty list"
    return True, "acceptance_tests is a non-empty list"


def rule_007_assembled_at(packet):
    """assembled_at must be a valid ISO 8601 UTC timestamp ending in 'Z'."""
    value = packet.get("assembled_at")
    if not isinstance(value, str) or not value.endswith("Z"):
        return False, "assembled_at must be an ISO 8601 UTC timestamp ending in Z"
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False, "assembled_at must be a valid ISO 8601 UTC timestamp ending in Z"
    return True, "assembled_at is a valid ISO 8601 UTC timestamp"


# Ordered registry of (rule_id, function). Order defines report order.
POLICY_RULES = [
    ("RULE-001", rule_001_component_id),
    ("RULE-002", rule_002_release),
    ("RULE-003", rule_003_owns),
    ("RULE-004", rule_004_does_not_own),
    ("RULE-005", rule_005_fail_closed),
    ("RULE-006", rule_006_acceptance_tests),
    ("RULE-007", rule_007_assembled_at),
]


def evaluate(packet):
    """Run every policy rule against ``packet``.

    Returns
    -------
    list of dict
        One entry per rule: ``{"rule": id, "passed": bool, "reason": str}``.
        Every rule is always evaluated so a rejection can report all failures.
    """
    results = []
    for rule_id, rule_fn in POLICY_RULES:
        passed, reason = rule_fn(packet)
        results.append({"rule": rule_id, "passed": passed, "reason": reason})
    return results
