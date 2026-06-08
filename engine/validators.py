"""SnortForge validation engine.

Pre-flight, syntax-shape checks only. A rule that passes these checks is
*well-formed*, not *validated by Snort*. The only true validator is the Snort
engine itself (``snort -c <conf> -T``). Never present these checks as
engine-level validation.

This module provides:
  * Pure helper validators (IP/CIDR, port, SID, PCRE) that return a small
    result object instead of raising, so the UI can show inline messages.
  * Pydantic v2 models that wrap the same logic for whole-rule validation.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import List, Optional

import regex as pcre_regex
from pydantic import BaseModel, Field, field_validator

from data.mitre_techniques import DEPRECATED_TECHNIQUES

# --- Constants ----------------------------------------------------------------

#: SIDs at or above this are the reserved range for local/custom rules.
CUSTOM_SID_MIN = 1_000_000

#: Header literals accepted in place of an IP or port.
IP_VARIABLES = {"$HOME_NET", "$EXTERNAL_NET", "$DNS_SERVERS", "$HTTP_SERVERS"}
PORT_VARIABLES = {"$HTTP_PORTS", "$SSH_PORTS", "$FTP_PORTS"}

MAX_PORT = 65535


# --- Lightweight result type --------------------------------------------------


@dataclass
class CheckResult:
    """Result of a single pre-flight check.

    ``ok`` is True when the value is well-formed. ``message`` carries the inline
    error (or warning) text for the UI. ``is_warning`` marks soft failures that
    warn rather than block (e.g. a reserved-range SID).
    """

    ok: bool
    message: str = ""
    is_warning: bool = False


# --- IP / CIDR ----------------------------------------------------------------


def validate_ip(value: str) -> CheckResult:
    """Validate a source/destination IP field.

    Accepts: ``any``, header variables ($HOME_NET etc.), a single IP, or a
    CIDR network (e.g. 192.168.1.0/24). Rejects anything else with a clear
    message. Does not yet handle negation/lists; those are out of v1 scope.
    """
    if value is None:
        return CheckResult(False, "IP field is empty.")
    v = value.strip()
    if v == "":
        return CheckResult(False, "IP field is empty.")
    if v == "any" or v in IP_VARIABLES:
        return CheckResult(True)
    # A bare variable that simply is not in our known set: accept the $ form but
    # nudge the user, since custom variables are legitimate in Snort configs.
    if v.startswith("$"):
        return CheckResult(
            True,
            f"'{v}' is treated as a Snort variable; ensure it is defined in your "
            "snort.lua/vars.",
            is_warning=True,
        )
    try:
        if "/" in v:
            ipaddress.ip_network(v, strict=False)
        else:
            ipaddress.ip_address(v)
        return CheckResult(True)
    except ValueError:
        return CheckResult(
            False, f"'{v}' is not a valid IP address, CIDR network, or variable."
        )


# --- Ports --------------------------------------------------------------------


def _validate_single_port(token: str) -> Optional[str]:
    """Return an error string for a single port token, or None if valid."""
    token = token.strip()
    if token == "":
        return "Empty port value."
    if not token.isdigit():
        return f"'{token}' is not a numeric port."
    port = int(token)
    if port < 0 or port > MAX_PORT:
        return f"Port {port} is out of range (0–{MAX_PORT})."
    return None


def validate_port(value: str) -> CheckResult:
    """Validate a port field.

    Accepts: ``any``, port variables ($HTTP_PORTS etc.), a single port (80),
    a comma list (80,443), or a range (1024:65535). Rejects out-of-range ports
    and inverted ranges (e.g. 200:100).
    """
    if value is None:
        return CheckResult(False, "Port field is empty.")
    v = value.strip()
    if v == "":
        return CheckResult(False, "Port field is empty.")
    if v == "any" or v in PORT_VARIABLES:
        return CheckResult(True)
    if v.startswith("$"):
        return CheckResult(
            True,
            f"'{v}' is treated as a Snort port variable; ensure it is defined.",
            is_warning=True,
        )

    # Range form, e.g. 1024:65535 (Snort also allows open-ended :1024 / 1024:).
    if ":" in v:
        low_s, _, high_s = v.partition(":")
        low_s, high_s = low_s.strip(), high_s.strip()
        low = 0 if low_s == "" else None
        high = MAX_PORT if high_s == "" else None
        if low_s != "":
            err = _validate_single_port(low_s)
            if err:
                return CheckResult(False, f"Invalid range start: {err}")
            low = int(low_s)
        if high_s != "":
            err = _validate_single_port(high_s)
            if err:
                return CheckResult(False, f"Invalid range end: {err}")
            high = int(high_s)
        if low is not None and high is not None and low > high:
            return CheckResult(
                False, f"Inverted port range: {low} is greater than {high}."
            )
        return CheckResult(True)

    # List form, e.g. 80,443.
    if "," in v:
        for token in v.split(","):
            err = _validate_single_port(token)
            if err:
                return CheckResult(False, err)
        return CheckResult(True)

    # Single port.
    err = _validate_single_port(v)
    if err:
        return CheckResult(False, err)
    return CheckResult(True)


# --- SID ----------------------------------------------------------------------


def validate_sid(sid: int) -> CheckResult:
    """Validate a SID.

    Custom rules should use ``sid >= 1_000_000``. A lower value is warned about
    (the range is reserved) but not hard-blocked, per spec 8.2.
    """
    try:
        sid_int = int(sid)
    except (TypeError, ValueError):
        return CheckResult(False, "SID must be an integer.")
    if sid_int <= 0:
        return CheckResult(False, "SID must be a positive integer.")
    if sid_int < CUSTOM_SID_MIN:
        return CheckResult(
            False,
            f"SID {sid_int} is below {CUSTOM_SID_MIN:,}; that range is reserved. "
            "Use a SID >= 1000000 for custom rules.",
            is_warning=True,
        )
    return CheckResult(True)


# --- PCRE ---------------------------------------------------------------------


def validate_pcre(pattern: str) -> CheckResult:
    """Test-compile a PCRE pattern with the ``regex`` module.

    This checks *compilability* only, not Snort's PCRE2 semantics. Leading/
    trailing slashes and trailing flag letters (e.g. ``/foo/i``) are stripped
    before compiling so user-entered Snort-style patterns compile cleanly.
    """
    if pattern is None or pattern.strip() == "":
        return CheckResult(True)  # empty PCRE is allowed (optional field)

    body = pattern.strip()
    if body.startswith("/"):
        # Strip the opening slash and the closing slash + optional flags.
        last = body.rfind("/")
        if last > 0:
            body = body[1:last]
        else:
            body = body[1:]
    try:
        pcre_regex.compile(body)
        return CheckResult(True, "Pattern compiles (syntax only, not Snort PCRE2 semantics).")
    except pcre_regex.error as exc:
        return CheckResult(False, f"Regex compile error: {exc}")


# --- MITRE --------------------------------------------------------------------


def validate_mitre_id(technique_id: str) -> CheckResult:
    """Reject deprecated technique IDs (e.g. T1043)."""
    tid = (technique_id or "").strip()
    if tid in DEPRECATED_TECHNIQUES:
        return CheckResult(
            False, f"{tid} is deprecated and must not be used."
        )
    return CheckResult(True)


# --- Pydantic whole-rule model ------------------------------------------------


class ContentRow(BaseModel):
    """A single content match row."""

    content: str = Field(min_length=1)
    nocase: bool = False
    fast_pattern: bool = False
    buffer: Optional[str] = None


class SnortRule(BaseModel):
    """Pydantic v2 model for a whole rule.

    Field validators reuse the helper checks above and raise ValueError with the
    inline message on hard failures. Soft warnings (reserved SID range, unknown
    variables) do not raise here; the UI surfaces those separately via the
    helper functions so it can render an amber warning rather than block.
    """

    action: str
    protocol: str
    src_ip: str
    src_port: str
    direction: str
    dst_ip: str
    dst_port: str
    msg: Optional[str] = None
    contents: List[ContentRow] = Field(default_factory=list)
    pcre: Optional[str] = None
    mitre: List[str] = Field(default_factory=list)
    sid: int
    rev: int = 1

    @field_validator("direction")
    @classmethod
    def _check_direction(cls, v: str) -> str:
        if v not in ("->", "<>"):
            raise ValueError("Direction must be '->' or '<>'.")
        return v

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _check_ip(cls, v: str) -> str:
        result = validate_ip(v)
        if not result.ok:
            raise ValueError(result.message)
        return v

    @field_validator("src_port", "dst_port")
    @classmethod
    def _check_port(cls, v: str) -> str:
        result = validate_port(v)
        if not result.ok:
            raise ValueError(result.message)
        return v

    @field_validator("pcre")
    @classmethod
    def _check_pcre(cls, v: Optional[str]) -> Optional[str]:
        if v:
            result = validate_pcre(v)
            if not result.ok:
                raise ValueError(result.message)
        return v

    @field_validator("mitre")
    @classmethod
    def _check_mitre(cls, v: List[str]) -> List[str]:
        for tid in v:
            result = validate_mitre_id(tid)
            if not result.ok:
                raise ValueError(result.message)
        return v

    @field_validator("rev")
    @classmethod
    def _check_rev(cls, v: int) -> int:
        if v < 1:
            raise ValueError("rev must be >= 1.")
        return v
