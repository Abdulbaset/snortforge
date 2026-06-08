"""Tests for engine/converter.py (Phase 3 converter acceptance criteria)."""

from engine.converter import convert_snort2_to_snort3


def _lines(rule_text):
    return [ln.strip() for ln in rule_text.splitlines()]


def test_single_content_with_buffer_and_nocase():
    """http_uri; on its own line above content, nocase folded in."""
    s2 = 'alert tcp any any -> any any (content:"GET"; http_uri; nocase; sid:1000001;)'
    out = convert_snort2_to_snort3(s2)
    lines = _lines(out)
    assert "http_uri;" in lines
    # buffer appears before the content line
    assert lines.index("http_uri;") < lines.index('content:"GET", nocase;')
    assert 'content:"GET", nocase;' in lines


def test_two_contents_sharing_buffer_emitted_once():
    s2 = (
        'alert tcp any any -> any any '
        '(content:"GET"; http_uri; content:"/admin"; http_uri; sid:1000002;)'
    )
    out = convert_snort2_to_snort3(s2)
    assert out.count("http_uri;") == 1
    lines = _lines(out)
    assert lines.index("http_uri;") < lines.index('content:"GET";')
    assert lines.index('content:"GET";') < lines.index('content:"/admin";')


def test_content_without_buffer_unchanged_form():
    s2 = 'alert tcp any any -> any any (content:"evil"; sid:1000003;)'
    out = convert_snort2_to_snort3(s2)
    # No buffer lines at all
    for buf in ("http_uri;", "http_header;", "dns_query;"):
        assert buf not in _lines(out)
    assert 'content:"evil";' in _lines(out)


def test_general_options_preserved_and_ordered():
    s2 = (
        'alert tcp $HOME_NET any -> $EXTERNAL_NET 80 '
        '(msg:"test"; flow:to_server,established; content:"x"; '
        'sid:1000004; rev:2;)'
    )
    out = convert_snort2_to_snort3(s2)
    lines = _lines(out)
    # header preserved
    assert out.startswith("alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (")
    # order: msg before flow before content before sid before rev
    order = [
        lines.index('msg:"test";'),
        lines.index("flow:to_server,established;"),
        lines.index('content:"x";'),
        lines.index("sid:1000004;"),
        lines.index("rev:2;"),
    ]
    assert order == sorted(order)


def test_garbage_input_returns_clean_error():
    out = convert_snort2_to_snort3("this is not a rule at all")
    assert out.startswith("Error:")


def test_empty_input_returns_error():
    assert convert_snort2_to_snort3("").startswith("Error:")
    assert convert_snort2_to_snort3("   ").startswith("Error:")


def test_modifiers_with_values_folded():
    """offset/depth carry their values into the folded content line."""
    s2 = (
        'alert tcp any any -> any any '
        '(content:"x"; offset:4; depth:10; nocase; sid:1000005;)'
    )
    out = convert_snort2_to_snort3(s2)
    assert 'content:"x", offset:4, depth:10, nocase;' in _lines(out)


def test_no_exception_on_weird_input():
    # Should never raise, always return a string.
    for bad in ("(", ")", "()", "alert ()", "content:"):
        assert isinstance(convert_snort2_to_snort3(bad), str)
