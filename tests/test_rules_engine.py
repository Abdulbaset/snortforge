"""Tests for engine/rules_engine.py (Phase 1 acceptance criteria)."""

from engine.rules_engine import build_header, build_rule


def _base_rule(**overrides):
    rule = {
        "action": "alert",
        "protocol": "tcp",
        "src_ip": "$HOME_NET",
        "src_port": "any",
        "direction": "->",
        "dst_ip": "$EXTERNAL_NET",
        "dst_port": "443",
        "msg": None,
        "contents": [],
        "pcre": None,
        "mitre": [],
        "sid": 1000001,
        "rev": 1,
    }
    rule.update(overrides)
    return rule


def test_header_with_variables():
    rule = _base_rule()
    assert build_header(rule) == "alert tcp $HOME_NET any -> $EXTERNAL_NET 443"


def test_header_with_cidr():
    rule = _base_rule(src_ip="192.168.1.0/24", dst_ip="10.0.0.5", dst_port="80")
    assert build_header(rule) == "alert tcp 192.168.1.0/24 any -> 10.0.0.5 80"


def test_single_content():
    rule = _base_rule(
        msg="single",
        contents=[{"content": "admin", "nocase": True, "fast_pattern": False}],
    )
    out = build_rule(rule)
    assert 'content:"admin", nocase;' in out
    assert "sid:1000001;" in out
    assert "rev:1;" in out
    assert out.startswith("alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (")


def test_multi_content():
    rule = _base_rule(
        contents=[
            {"content": "GET", "nocase": False, "fast_pattern": True},
            {"content": "admin", "nocase": True, "fast_pattern": False},
        ]
    )
    out = build_rule(rule)
    assert 'content:"GET", fast_pattern;' in out
    assert 'content:"admin", nocase;' in out


def test_buffer_ordering_buffer_before_content():
    """The sticky buffer line must appear immediately before its content."""
    rule = _base_rule(
        contents=[
            {"content": "GET", "buffer": "http_uri"},
        ]
    )
    out = build_rule(rule)
    lines = [ln.strip() for ln in out.splitlines()]
    buf_idx = lines.index("http_uri;")
    content_idx = lines.index('content:"GET";')
    assert buf_idx < content_idx


def test_buffer_dedup_shared_buffer_emitted_once():
    """Two contents sharing http_uri emit the buffer line exactly once."""
    rule = _base_rule(
        contents=[
            {"content": "GET", "buffer": "http_uri"},
            {"content": "admin", "buffer": "http_uri"},
        ]
    )
    out = build_rule(rule)
    assert out.count("http_uri;") == 1
    # And both content lines are present, in order, after the buffer line.
    assert out.index("http_uri;") < out.index('content:"GET";')
    assert out.index('content:"GET";') < out.index('content:"admin";')


def test_buffer_change_emits_new_buffer():
    """Switching buffers re-emits a buffer line for the new buffer."""
    rule = _base_rule(
        contents=[
            {"content": "GET", "buffer": "http_uri"},
            {"content": "Host", "buffer": "http_header"},
        ]
    )
    out = build_rule(rule)
    assert out.count("http_uri;") == 1
    assert out.count("http_header;") == 1
    assert out.index("http_uri;") < out.index("http_header;")


def test_full_phase1_acceptance_rule():
    """Acceptance: two contents + http_uri buffer, buffer above content."""
    rule = _base_rule(
        msg="phase1",
        contents=[
            {"content": "GET", "nocase": True, "buffer": "http_uri"},
            {"content": "/admin", "nocase": False, "buffer": "http_uri"},
        ],
    )
    out = build_rule(rule)
    assert out.count("http_uri;") == 1
    lines = [ln.strip() for ln in out.splitlines()]
    assert lines.index("http_uri;") < lines.index('content:"GET", nocase;')


def test_metadata_and_pcre_render():
    rule = _base_rule(
        pcre="/admin/i",
        mitre=["T1071", "T1071.001"],
    )
    out = build_rule(rule)
    assert 'pcre:"/admin/i";' in out
    assert "metadata:mitre_attack T1071, mitre_attack T1071.001;" in out


def test_content_quote_escaping():
    rule = _base_rule(contents=[{"content": 'say "hi"'}])
    out = build_rule(rule)
    assert r'content:"say \"hi\"";' in out
