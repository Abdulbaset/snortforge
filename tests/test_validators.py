"""Tests for engine/validators.py (Phase 2 acceptance criteria).

Covers each named failure case: malformed IP, inverted port range, SID below
1,000,000, and a broken regex. Also covers the deprecated MITRE ID guard.
"""

import pytest

from engine.validators import (
    CUSTOM_SID_MIN,
    SnortRule,
    validate_ip,
    validate_mitre_id,
    validate_pcre,
    validate_port,
    validate_sid,
)


# --- IP -----------------------------------------------------------------------


def test_valid_ip_forms():
    assert validate_ip("any").ok
    assert validate_ip("$HOME_NET").ok
    assert validate_ip("192.168.1.1").ok
    assert validate_ip("192.168.1.0/24").ok


def test_malformed_ip_produces_message():
    result = validate_ip("999.1.1.1")
    assert not result.ok
    assert "not a valid IP" in result.message


def test_malformed_cidr_produces_message():
    result = validate_ip("192.168.1.0/99")
    assert not result.ok
    assert result.message


# --- Ports --------------------------------------------------------------------


def test_valid_port_forms():
    assert validate_port("80").ok
    assert validate_port("80,443").ok
    assert validate_port("1024:65535").ok
    assert validate_port("any").ok
    assert validate_port("$HTTP_PORTS").ok


def test_out_of_range_port():
    result = validate_port("70000")
    assert not result.ok
    assert "out of range" in result.message


def test_inverted_port_range_produces_message():
    result = validate_port("200:100")
    assert not result.ok
    assert "Inverted port range" in result.message


def test_non_numeric_port():
    assert not validate_port("abc").ok


# --- SID ----------------------------------------------------------------------


def test_sid_below_custom_range_warns():
    result = validate_sid(500)
    assert not result.ok
    assert result.is_warning
    assert "reserved" in result.message
    assert str(CUSTOM_SID_MIN).replace(",", "") in result.message.replace(",", "")


def test_sid_in_custom_range_ok():
    assert validate_sid(1000001).ok


def test_sid_non_positive():
    assert not validate_sid(0).ok


# --- PCRE ---------------------------------------------------------------------


def test_broken_regex_blocks_with_message():
    result = validate_pcre("a(b")  # unbalanced paren
    assert not result.ok
    assert "compile error" in result.message.lower()


def test_valid_regex_compiles():
    assert validate_pcre("/admin/i").ok
    assert validate_pcre("[a-z]+\\d{2}").ok


def test_empty_pcre_allowed():
    assert validate_pcre("").ok


# --- MITRE --------------------------------------------------------------------


def test_deprecated_mitre_rejected():
    result = validate_mitre_id("T1043")
    assert not result.ok
    assert "deprecated" in result.message


def test_valid_mitre_ok():
    assert validate_mitre_id("T1071").ok


# --- Whole-rule Pydantic model ------------------------------------------------


def _good_kwargs(**overrides):
    kwargs = dict(
        action="alert",
        protocol="tcp",
        src_ip="$HOME_NET",
        src_port="any",
        direction="->",
        dst_ip="$EXTERNAL_NET",
        dst_port="443",
        sid=1000001,
        rev=1,
    )
    kwargs.update(overrides)
    return kwargs


def test_model_accepts_good_rule():
    rule = SnortRule(**_good_kwargs())
    assert rule.sid == 1000001


def test_model_rejects_bad_ip():
    with pytest.raises(ValueError):
        SnortRule(**_good_kwargs(src_ip="999.1.1.1"))


def test_model_rejects_inverted_port():
    with pytest.raises(ValueError):
        SnortRule(**_good_kwargs(dst_port="200:100"))


def test_model_rejects_bad_direction():
    with pytest.raises(ValueError):
        SnortRule(**_good_kwargs(direction="=>"))


def test_model_rejects_broken_pcre():
    with pytest.raises(ValueError):
        SnortRule(**_good_kwargs(pcre="a(b"))


def test_model_rejects_deprecated_mitre():
    with pytest.raises(ValueError):
        SnortRule(**_good_kwargs(mitre=["T1043"]))
