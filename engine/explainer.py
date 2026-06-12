"""Rule explainer: turn a clean rule dict into plain-English annotations.

Built for teaching. Each entry pairs the exact rule fragment with what it does,
in the order the fragments appear, so students can read the generated rule
side-by-side with the lab notes (header components, then the four option
categories: meta-data, payload, non-payload, post-detection).

Like the rules engine, this module assumes the dict has already passed the
validation layer and performs no checks of its own.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

_ACTION_TEXT = {
    "alert": "generate an alert using the configured method and log the packet",
    "log": "log the packet without alerting",
    "pass": "ignore the packet",
    "drop": "drop the packet and log it (blocks traffic — inline mode only)",
    "reject": (
        "drop the packet, log it, and send a TCP reset (or ICMP port "
        "unreachable for UDP) — inline mode only"
    ),
}

_BUFFER_TEXT = {
    "http_uri": "the normalised HTTP request URI",
    "http_raw_uri": "the raw, un-normalised HTTP request URI",
    "http_header": "the normalised HTTP headers",
    "http_raw_header": "the raw HTTP headers",
    "http_client_body": "the HTTP request body (e.g. POST data)",
    "http_method": "the HTTP method (GET, POST, ...)",
    "http_cookie": "the HTTP Cookie header",
    "http_host": "the HTTP Host header",
    "http_stat_code": "the HTTP response status code",
    "http_stat_msg": "the HTTP response status message",
    "dns_query": "the queried DNS name",
}


def _ip_text(value: str, role: str) -> str:
    v = str(value).strip()
    if v == "any":
        return f"{role}: any IP address"
    if v == "$HOME_NET":
        return f"{role}: your protected network (the HOME_NET variable from snort.lua)"
    if v == "$EXTERNAL_NET":
        return f"{role}: everything outside HOME_NET (the EXTERNAL_NET variable)"
    if v.startswith("$"):
        return f"{role}: the Snort variable {v} defined in your configuration"
    if "/" in v:
        return f"{role}: any address inside the {v} network (CIDR notation)"
    return f"{role}: the single host {v}"


def _port_text(value: str, role: str) -> str:
    v = str(value).strip()
    if v == "any":
        return f"{role} port: any"
    if v.startswith("$"):
        return f"{role} port: the Snort variable {v}"
    if ":" in v:
        return f"{role} port: the range {v}"
    if "," in v:
        return f"{role} port: any of {v}"
    return f"{role} port: {v}"


def explain_rule(rule: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Return ordered (fragment, explanation) pairs for the whole rule."""
    parts: List[Tuple[str, str]] = []

    # --- Header (mirrors the lab notes' "Rule header components") -------------
    action = str(rule.get("action", "")).strip()
    parts.append(
        (action, f"Action — when a packet matches, {_ACTION_TEXT.get(action, 'perform this action')}.")
    )
    protocol = str(rule.get("protocol", "")).strip()
    parts.append((protocol, f"Protocol — only inspect {protocol.upper()} traffic."))
    parts.append((str(rule.get("src_ip", "")), _ip_text(rule.get("src_ip", ""), "Source")))
    parts.append((str(rule.get("src_port", "")), _port_text(rule.get("src_port", ""), "Source")))
    direction = str(rule.get("direction", "->")).strip()
    parts.append(
        (
            direction,
            "Direction — one-way: match traffic flowing from source to destination."
            if direction == "->"
            else "Direction — bidirectional: match traffic in either direction.",
        )
    )
    parts.append((str(rule.get("dst_ip", "")), _ip_text(rule.get("dst_ip", ""), "Destination")))
    parts.append((str(rule.get("dst_port", "")), _port_text(rule.get("dst_port", ""), "Destination")))

    # --- Meta-data options -----------------------------------------------------
    if rule.get("msg"):
        parts.append(
            (f'msg:"{rule["msg"]}"', "Meta-data — the message written to the alert/log when this rule fires.")
        )

    # --- Flow -------------------------------------------------------------------
    if rule.get("flow"):
        parts.append(
            (
                f"flow:{rule['flow']}",
                "Non-payload — restricts matching to packets in this part of a "
                "session (e.g. to_server,established = client-to-server traffic "
                "after the TCP handshake).",
            )
        )

    # --- Payload options ---------------------------------------------------------
    active_buffer = None
    for row in rule.get("contents", []) or []:
        content = row.get("content")
        if not content:
            continue
        buffer = row.get("buffer")
        if buffer and buffer != active_buffer:
            where = _BUFFER_TEXT.get(buffer, f"the {buffer} buffer")
            parts.append(
                (
                    f"{buffer};",
                    f"Sticky buffer — every content match below this line searches "
                    f"{where}, until another buffer line changes it.",
                )
            )
            active_buffer = buffer
        detail = [f'Payload — search for the bytes "{content}"']
        if row.get("offset") not in (None, ""):
            detail.append(f"starting {int(row['offset'])} bytes into the payload (offset)")
        if row.get("depth") not in (None, ""):
            detail.append(f"looking at most {int(row['depth'])} bytes deep (depth)")
        if row.get("distance") not in (None, ""):
            detail.append(f"at least {int(row['distance'])} bytes after the previous match (distance)")
        if row.get("within") not in (None, ""):
            detail.append(f"within {int(row['within'])} bytes of the previous match (within)")
        if row.get("nocase"):
            detail.append("ignoring upper/lower case (nocase)")
        if row.get("fast_pattern"):
            detail.append("used as the fast-pattern matcher for engine speed")
        parts.append((f'content:"{content}"...', ", ".join(detail) + "."))

    if rule.get("pcre"):
        parts.append(
            (
                f'pcre:"{rule["pcre"]}"',
                "Payload — the payload must also match this Perl-compatible "
                "regular expression. Powerful but slower than content matches.",
            )
        )

    # --- Non-payload options -----------------------------------------------------
    non_payload = {
        "dsize": "tests the payload size in bytes — useful for spotting buffer overflows",
        "ttl": "tests the IP time-to-live value — useful for detecting traceroute attempts",
        "flags": "tests which TCP flags are set (S=SYN, A=ACK, F=FIN, R=RST, P=PSH, U=URG)",
        "itype": "tests the ICMP type (8 = echo request, i.e. a ping; 0 = echo reply)",
        "icode": "tests the ICMP code that qualifies the ICMP type",
    }
    for key, text in non_payload.items():
        value = rule.get(key)
        if value is not None and str(value).strip() != "":
            parts.append((f"{key}:{value}", f"Non-payload — {text}."))

    # --- Trailing meta-data --------------------------------------------------------
    for ref in rule.get("references") or []:
        if str(ref).strip():
            parts.append(
                (
                    f"reference:{ref}",
                    "Meta-data — links the rule to an external attack identifier "
                    "(e.g. a CVE) so analysts can read up on what was detected.",
                )
            )
    if rule.get("classtype"):
        parts.append(
            (
                f"classtype:{rule['classtype']}",
                "Meta-data — categorises the attack and sets the default alert "
                "priority via classification.config.",
            )
        )
    if rule.get("mitre"):
        parts.append(
            (
                "metadata:mitre_attack ...",
                "Meta-data — maps the rule to MITRE ATT&CK techniques for SOC "
                "triage and reporting.",
            )
        )

    if rule.get("sid") is not None:
        parts.append(
            (
                f"sid:{rule['sid']}",
                "Meta-data — the unique signature ID. Custom/local rules must use "
                "1,000,000 or above; lower SIDs are reserved.",
            )
        )
    if rule.get("rev") is not None:
        parts.append(
            (f"rev:{rule['rev']}", "Meta-data — the revision number; bump it each time you edit the rule.")
        )

    return parts
