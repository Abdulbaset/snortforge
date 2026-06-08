"""Legacy Snort 2 -> Snort 3 rule converter.

This is the highest-risk component. The original draft used
``list.insert(-1, ...)`` to place sticky buffers, which only worked when the
content happened to be the last appended option. This rebuild walks the options
in order, groups each ``content:`` with the modifiers that trail it, and emits
the matching sticky buffer line *before* the content line — only when the active
buffer changes (matching Phase 1 behaviour).

On unparsable input it returns a clear error string and never a half-converted
rule.
"""

from __future__ import annotations

import re

# Snort 2 modifiers that select a sticky buffer in Snort 3. The key is the
# Snort 2 modifier; the value is the Snort 3 sticky buffer line to emit.
BUFFER_MODIFIERS = {
    "http_uri": "http_uri",
    "http_raw_uri": "http_raw_uri",
    "http_header": "http_header",
    "http_raw_header": "http_raw_header",
    "http_client_body": "http_client_body",
    "http_method": "http_method",
    "http_cookie": "http_cookie",
    "http_stat_code": "http_stat_code",
    "http_stat_msg": "http_stat_msg",
    "dns_query": "dns_query",
}

# Content-scoped modifiers that fold into the comma form on the content line.
CONTENT_MODIFIERS = {
    "nocase",
    "offset",
    "depth",
    "distance",
    "within",
    "fast_pattern",
    "rawbytes",
}

_ERR_FORMAT = (
    "Error: invalid rule format. Could not separate header from options."
)
_ERR_EMPTY = "Error: empty rule."
_ERR_NO_HEADER = "Error: rule header is missing."


def _option_key(option: str) -> str:
    """Return the bare keyword of an option, e.g. 'nocase' or 'http_uri'.

    Handles both ``key:value`` and bare ``key`` forms, plus a stray leading
    comma from folded modifiers.
    """
    return option.split(":", 1)[0].split(",", 1)[0].strip()


def convert_snort2_to_snort3(snort2_rule: str) -> str:
    """Convert a single Snort 2 rule string to Snort 3 form.

    Returns the converted multi-line rule, or an ``Error: ...`` string if the
    input cannot be parsed. Never raises on bad input.
    """
    if snort2_rule is None or snort2_rule.strip() == "":
        return _ERR_EMPTY

    # Collapse all whitespace runs to single spaces so the header/options split
    # is stable regardless of input formatting.
    rule = " ".join(snort2_rule.split())

    m = re.match(r"(.*?)\((.*)\)\s*$", rule)
    if not m:
        return _ERR_FORMAT

    header = m.group(1).strip()
    if header == "":
        return _ERR_NO_HEADER

    raw = [o.strip() for o in m.group(2).split(";") if o.strip()]
    if not raw:
        return f"{header} (\n)"

    out_lines: list[str] = []
    active_buffer: str | None = None
    i = 0
    while i < len(raw):
        opt = raw[i]
        if opt.startswith("content:"):
            content = opt
            mods: list[str] = []
            buffer_for_this: str | None = None
            j = i + 1
            while j < len(raw):
                key = _option_key(raw[j])
                if key in BUFFER_MODIFIERS:
                    # Last buffer modifier before the next content wins.
                    buffer_for_this = BUFFER_MODIFIERS[key]
                    j += 1
                elif key in CONTENT_MODIFIERS:
                    mods.append(raw[j])
                    j += 1
                else:
                    break
            if buffer_for_this and buffer_for_this != active_buffer:
                out_lines.append(f"{buffer_for_this};")
                active_buffer = buffer_for_this
            body = content if not mods else f"{content}, " + ", ".join(mods)
            out_lines.append(f"{body};")
            i = j
        else:
            # Preserve every other option (msg, flow, sid, rev, reference,
            # metadata, pcre, ...) in place and in order.
            out_lines.append(f"{opt};")
            i += 1

    formatted = "\n    ".join(out_lines)
    return f"{header} (\n    {formatted}\n)"
