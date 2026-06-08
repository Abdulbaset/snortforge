"""Seed list of MITRE ATT&CK Enterprise techniques for the rule builder.

Only current, valid Enterprise techniques are seeded here. T1043 is deprecated
and must never be added (see build spec section 7.3 / 11.4). Verify any new IDs
against the live ATT&CK Enterprise matrix at https://attack.mitre.org before
adding them.

Each entry is (technique_id, name). Sub-techniques use the dotted form.
"""

from __future__ import annotations

from typing import List, Tuple

# (id, name) — keep sorted by id for a stable multi-select order.
MITRE_TECHNIQUES: List[Tuple[str, str]] = [
    ("T1041", "Exfiltration Over C2 Channel"),
    ("T1071", "Application Layer Protocol"),
    ("T1071.001", "Web Protocols"),
    ("T1071.004", "DNS"),
    ("T1090", "Proxy"),
    ("T1095", "Non-Application Layer Protocol"),
    ("T1105", "Ingress Tool Transfer"),
    ("T1190", "Exploit Public-Facing Application"),
    ("T1203", "Exploitation for Client Execution"),
    ("T1219", "Remote Access Software"),
    ("T1505.003", "Web Shell"),
    ("T1568", "Dynamic Resolution"),
    ("T1571", "Non-Standard Port"),
    ("T1572", "Protocol Tunnelling"),
]

# Explicitly deprecated / forbidden IDs. Used by validators to reject them even
# if a caller tries to inject them via a loaded rule.
DEPRECATED_TECHNIQUES = {"T1043"}


def technique_labels() -> List[str]:
    """Return human-friendly labels, e.g. 'T1071 — Application Layer Protocol'."""
    return [f"{tid} — {name}" for tid, name in MITRE_TECHNIQUES]


def label_to_id(label: str) -> str:
    """Extract the technique ID from a label produced by technique_labels()."""
    return label.split("—", 1)[0].strip()


def is_known(technique_id: str) -> bool:
    """True if the ID is in the seed list."""
    return any(tid == technique_id for tid, _ in MITRE_TECHNIQUES)
