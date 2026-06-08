"""SnortForge rules engine: turn a clean dict into a Snort 3 rule string.

The engine assumes the input dict has already been sanitised by the validation
layer (engine/validators.py). It performs no network or Snort-engine calls; it
only renders syntax. A rule produced here is *well-formed*, not engine-validated.

Input dict shape (all keys optional unless noted):

    {
        "action":    "alert",                  # required
        "protocol":  "tcp",                    # required
        "src_ip":    "$HOME_NET",              # required
        "src_port":  "any",                    # required
        "direction": "->",                     # required ("->" or "<>")
        "dst_ip":    "$EXTERNAL_NET",          # required
        "dst_port":  "443",                    # required
        "msg":       "Example rule",
        "contents":  [
            {"content": "GET", "nocase": True, "fast_pattern": False,
             "buffer": "http_uri"},
        ],
        "pcre":      "/admin/i",               # bare pattern, slashes optional
        "mitre":     ["T1071", "T1071.001"],
        "sid":       1000001,                  # required
        "rev":       1,                        # required
    }

Sticky-buffer rule (section 7.3): a sticky buffer applies to all following
content until another buffer changes it. The engine therefore emits a buffer
line only when the active buffer changes, never repeating it for consecutive
content rows that share the same buffer.
"""

from __future__ import annotations

from typing import Any, Dict, List

# Known sticky buffers the builder offers. Kept here so the engine stays the
# single source of truth for what a "buffer" is.
STICKY_BUFFERS = [
    "http_uri",
    "http_header",
    "http_client_body",
    "http_method",
    "http_cookie",
    "http_raw_uri",
    "dns_query",
]


def _escape_content(value: str) -> str:
    r"""Escape characters that are special inside a Snort content string.

    Snort treats the double quote and backslash specially inside
    ``content:"..."``. We escape backslash first, then the quote.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_header(rule: Dict[str, Any]) -> str:
    """Assemble the space-separated rule header.

    e.g. ``alert tcp $HOME_NET any -> $EXTERNAL_NET 443``
    """
    parts = [
        str(rule["action"]).strip(),
        str(rule["protocol"]).strip(),
        str(rule["src_ip"]).strip(),
        str(rule["src_port"]).strip(),
        str(rule["direction"]).strip(),
        str(rule["dst_ip"]).strip(),
        str(rule["dst_port"]).strip(),
    ]
    return " ".join(parts)


def _normalise_pcre(pattern: str) -> str:
    """Wrap a bare PCRE pattern in slashes if the user omitted them.

    Accepts ``/admin/i`` as-is, and turns ``admin`` into ``/admin/``.
    """
    pattern = pattern.strip()
    if not pattern:
        return pattern
    if pattern.startswith("/"):
        return pattern
    return f"/{pattern}/"


def _build_metadata(mitre_tags: List[str]) -> str:
    """Build the ``metadata:`` option from MITRE technique IDs.

    Keys are lowercase and comma-separated, e.g.
    ``metadata:mitre_attack T1071, mitre_attack T1071.001``.
    """
    tags = [t.strip() for t in mitre_tags if t and t.strip()]
    items = [f"mitre_attack {t}" for t in tags]
    return "metadata:" + ", ".join(items)


def build_options(rule: Dict[str, Any]) -> List[str]:
    """Build the ordered list of option strings (each without trailing ';').

    Order: msg -> [buffer/content pairs] -> pcre -> metadata -> sid -> rev.
    """
    options: List[str] = []

    msg = rule.get("msg")
    if msg:
        options.append(f'msg:"{_escape_content(str(msg))}"')

    active_buffer = None
    for row in rule.get("contents", []) or []:
        content = row.get("content")
        if content is None or str(content) == "":
            continue

        buffer = row.get("buffer")
        if buffer and buffer != active_buffer:
            options.append(f"{buffer}")
            active_buffer = buffer

        modifiers: List[str] = []
        if row.get("nocase"):
            modifiers.append("nocase")
        if row.get("fast_pattern"):
            modifiers.append("fast_pattern")

        content_opt = f'content:"{_escape_content(str(content))}"'
        if modifiers:
            content_opt += ", " + ", ".join(modifiers)
        options.append(content_opt)

    pcre = rule.get("pcre")
    if pcre:
        options.append(f'pcre:"{_normalise_pcre(str(pcre))}"')

    mitre_tags = rule.get("mitre") or []
    if mitre_tags:
        options.append(_build_metadata(mitre_tags))

    # sid and rev close out the rule.
    if rule.get("sid") is not None:
        options.append(f"sid:{int(rule['sid'])}")
    if rule.get("rev") is not None:
        options.append(f"rev:{int(rule['rev'])}")

    return options


def build_rule(rule: Dict[str, Any]) -> str:
    """Render a full multi-line Snort 3 rule string from a clean dict."""
    header = build_header(rule)
    options = build_options(rule)
    body = "".join(f"    {opt};\n" for opt in options)
    return f"{header} (\n{body})"
