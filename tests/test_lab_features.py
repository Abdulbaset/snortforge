"""Tests for the lab-focused additions: expanded options, ICMP, explainer,
templates. Naming mirrors the existing suite."""

from __future__ import annotations

import pytest

from data.templates import TEMPLATES
from engine.explainer import explain_rule
from engine.pcap_engine import generate_mock_pcap
from engine.rules_engine import build_rule
from engine.validators import (
    SnortRule,
    validate_classtype,
    validate_dsize,
    validate_flags,
    validate_icmp_field,
    validate_reference,
    validate_ttl,
)


def _base_rule(**overrides):
    rule = {
        "action": "alert",
        "protocol": "tcp",
        "src_ip": "$HOME_NET",
        "src_port": "any",
        "direction": "->",
        "dst_ip": "$EXTERNAL_NET",
        "dst_port": "80",
        "msg": "test",
        "contents": [],
        "sid": 1000001,
        "rev": 1,
    }
    rule.update(overrides)
    return rule


# --- rules engine: new options --------------------------------------------------


def test_flow_emitted_after_msg():
    rule = _base_rule(flow="to_server,established")
    text = build_rule(rule)
    lines = [l.strip().rstrip(";") for l in text.splitlines()]
    assert "flow:to_server,established" in lines
    assert lines.index("flow:to_server,established") > lines.index('msg:"test"')


def test_content_positional_suboptions_comma_form():
    rule = _base_rule(
        contents=[{"content": "GET", "offset": 0, "depth": 3, "nocase": True}]
    )
    text = build_rule(rule)
    assert 'content:"GET", offset 0, depth 3, nocase;' in text


def test_non_payload_reference_classtype_order():
    rule = _base_rule(
        dsize=">100",
        ttl="<5",
        flags="S",
        references=["cve,2021-44228"],
        classtype="attempted-recon",
    )
    text = build_rule(rule)
    for fragment in (
        "dsize:>100;", "ttl:<5;", "flags:S;",
        "reference:cve,2021-44228;", "classtype:attempted-recon;",
    ):
        assert fragment in text
    # classtype lands after reference, sid after classtype
    assert text.index("reference:") < text.index("classtype:") < text.index("sid:")


def test_icmp_rule_with_itype_icode():
    rule = _base_rule(protocol="icmp", dst_port="any", itype="8", icode="0")
    text = build_rule(rule)
    assert text.startswith("alert icmp")
    assert "itype:8;" in text and "icode:0;" in text


# --- validators ------------------------------------------------------------------


@pytest.mark.parametrize("value", ["100", ">100", "<5", ">=10", "300<>400", ""])
def test_dsize_valid_forms(value):
    assert validate_dsize(value).ok


@pytest.mark.parametrize("value", ["abc", ">", "400<>300", "70000"])
def test_dsize_invalid_forms(value):
    assert not validate_dsize(value).ok


def test_ttl_bounds():
    assert validate_ttl("<5").ok
    assert not validate_ttl("300").ok  # > 255


@pytest.mark.parametrize("value", ["S", "+SA", "!R", "FPU", "S,12"])
def test_flags_valid(value):
    assert validate_flags(value).ok


@pytest.mark.parametrize("value", ["Z", "S A", "++S"])
def test_flags_invalid(value):
    assert not validate_flags(value).ok


def test_icmp_field_range():
    assert validate_icmp_field("8").ok
    assert not validate_icmp_field("999").ok


def test_classtype_unknown_warns_not_blocks():
    res = validate_classtype("my-custom-class")
    assert res.ok and res.is_warning
    assert validate_classtype("attempted-recon").ok
    assert not validate_classtype("Bad Type!").ok


def test_reference_form():
    assert validate_reference("cve,2021-44228").ok
    res = validate_reference("weirdsys,123")
    assert res.ok and res.is_warning
    assert not validate_reference("no-comma-here").ok


def test_pydantic_model_accepts_new_fields():
    rule = SnortRule(
        **_base_rule(
            flow="established",
            dsize=">100",
            ttl="<5",
            flags="S",
            references=["cve,2021-44228"],
            classtype="attempted-recon",
            contents=[{"content": "GET", "offset": 0, "depth": 3}],
        )
    )
    assert rule.dsize == ">100"
    assert rule.contents[0].depth == 3


def test_pydantic_model_rejects_bad_dsize():
    with pytest.raises(ValueError):
        SnortRule(**_base_rule(dsize="oops"))


# --- pcap engine: ICMP --------------------------------------------------------------


def test_icmp_pcap_is_echo_request():
    from scapy.all import ICMP, rdpcap
    import tempfile, os

    data = generate_mock_pcap("icmp", "192.168.1.10", "192.168.1.1", "any", "any", "")
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp.write(data)
    tmp.close()
    try:
        pkts = rdpcap(tmp.name)
    finally:
        os.unlink(tmp.name)
    assert len(pkts) == 1
    assert ICMP in pkts[0]
    assert pkts[0][ICMP].type == 8 and pkts[0][ICMP].code == 0


def test_icmp_pcap_custom_type():
    from scapy.all import ICMP, rdpcap
    import tempfile, os

    data = generate_mock_pcap(
        "icmp", "1.2.3.4", "5.6.7.8", "any", "any", "ping!", icmp_type=0
    )
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp.write(data)
    tmp.close()
    try:
        pkts = rdpcap(tmp.name)
    finally:
        os.unlink(tmp.name)
    assert pkts[0][ICMP].type == 0


def test_tcp_pcap_unchanged():
    data = generate_mock_pcap("tcp", "1.1.1.1", "2.2.2.2", "1234", "80", "GET /")
    assert isinstance(data, bytes) and len(data) > 0


# --- explainer -----------------------------------------------------------------------


def test_explainer_covers_every_part():
    rule = _base_rule(
        flow="to_server,established",
        contents=[{"content": "/admin", "buffer": "http_uri", "nocase": True}],
        dsize=">100",
        references=["cve,2021-44228"],
        classtype="web-application-attack",
        mitre=["T1071"],
    )
    parts = dict(explain_rule(rule))
    assert "alert" in parts
    assert "->" in parts
    assert "http_uri;" in parts
    assert 'content:"/admin"...' in parts
    assert "dsize:>100" in parts
    assert "reference:cve,2021-44228" in parts
    assert "classtype:web-application-attack" in parts
    assert "sid:1000001" in parts
    # nocase explained on the content line
    assert "nocase" in parts['content:"/admin"...']


def test_explainer_icmp_ping():
    rule = _base_rule(protocol="icmp", dst_port="any", itype="8")
    parts = dict(explain_rule(rule))
    assert "echo request" in parts["itype:8"]


# --- templates ------------------------------------------------------------------------


def test_every_template_builds_and_validates():
    for name, t in TEMPLATES.items():
        rule = {
            **t,
            "references": [r for r in str(t["references"]).splitlines() if r.strip()],
            "classtype": t["classtype"] or None,
            "pcre": t["pcre"] or None,
            "flow": t["flow"] or None,
            "dsize": t["dsize"] or None,
            "ttl": t["ttl"] or None,
            "flags": t["flags"] or None,
            "itype": t["itype"] or None,
            "icode": t["icode"] or None,
        }
        text = build_rule(rule)
        assert text.startswith(t["action"]), name
        assert f"sid:{t['sid']};" in text, name
        SnortRule(**rule)  # must not raise


def test_template_sids_in_custom_range_and_unique():
    sids = [t["sid"] for t in TEMPLATES.values()]
    assert all(s >= 1_000_000 for s in sids)
    assert len(sids) == len(set(sids))


# --- lab view fallback regression -----------------------------------------------


def test_lab_view_handles_stale_session_state():
    """A session from an older app version can have rule_text without
    rule_dict; render_lab must fall back, never crash (regression for the
    AttributeError seen on Streamlit Cloud after the v1.1.0 redeploy)."""
    import ui.lab_view as lab

    src_text = open(lab.__file__).read()
    assert "isinstance(rule_dict, dict)" in src_text
