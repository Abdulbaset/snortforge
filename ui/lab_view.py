"""Lab Helper: bridge a built rule to the standard Snort 3 workflow.

Covers the loop every Snort deployment and course goes through: install Snort
on a Linux machine, configure snort.lua (network variables, rule locations),
write detection rules, validate them with the engine, and test against real or
replayed traffic.

This view takes the rule last generated in the Rule Builder and produces the
exact artefacts needed on the Snort machine: the local.rules file, the
snort.lua snippets, the verification/run commands, and a synthetic trigger
pcap to replay offline. It performs no engine validation itself; the commands
it prints are what perform the true validation.
"""

from __future__ import annotations

import streamlit as st

from engine.pcap_engine import generate_mock_pcap

# Paths used in the printed commands. Kept as constants so a module-wide change
# (e.g. a different install prefix on the lab VMs) is a one-line edit.
SNORT_CONF = "/usr/local/etc/snort/snort.lua"
RULES_PATH = "/usr/local/etc/rules/local.rules"

_FALLBACK_RULE = (
    'alert icmp any any -> $HOME_NET any (\n'
    '    msg:"ICMP echo request detected";\n'
    "    itype:8;\n"
    "    sid:1000001;\n"
    "    rev:1;\n"
    ")"
)


def _derive_trigger_payload(rule: dict) -> tuple[str, str]:
    """Build a payload likely to trigger the rule, plus a human note.

    Heuristics only: content strings are folded into a plausible payload. For
    HTTP-shaped rules a minimal request line is synthesised so the bytes the
    rule looks for actually appear on the wire.
    """
    contents = [c for c in (rule.get("contents") or []) if c.get("content")]
    if not contents:
        return "", "No content matches in the rule, so the packet carries no payload."

    buffers = {c.get("buffer") for c in contents if c.get("buffer")}
    if any(b and str(b).startswith("http") for b in buffers):
        method = next(
            (c["content"] for c in contents if c.get("buffer") == "http_method"), "GET"
        )
        uri = next(
            (c["content"] for c in contents if c.get("buffer") in ("http_uri", "http_raw_uri")),
            "/",
        )
        host_bits = [c["content"] for c in contents
                     if c.get("buffer") in ("http_header", "http_host")]
        host = host_bits[0] if host_bits else "lab.test"
        payload = f"{method} {uri} HTTP/1.1\r\nHost: {host}\r\n\r\n"
        return payload, (
            "HTTP-shaped payload synthesised from your content matches. Note: "
            "sticky-buffer rules (http_uri etc.) need Snort's HTTP inspector to "
            "see a full TCP session — if the replay does not alert, generate "
            "real traffic instead (e.g. curl from a second VM)."
        )
    if "dns_query" in buffers:
        name = next(c["content"] for c in contents if c.get("buffer") == "dns_query")
        return name, (
            "Raw payload carrying the queried name. A dns_query rule needs the "
            "DNS inspector to parse a real query; if the replay does not alert, "
            "trigger it with `dig` or `nslookup` from the VM instead."
        )
    payload = " ".join(c["content"] for c in contents)
    return payload, "Payload is your content match strings joined together."


def render_lab() -> None:
    st.subheader("Lab Helper")
    st.caption(
        "Turns the rule from the **Rule Builder** tab into the files and "
        "commands you need on the machine running Snort. The commands below are what perform "
        "true Snort-engine validation — SnortForge itself only pre-checks syntax."
    )

    rule_text = st.session_state.get("current_rule_text")
    rule_dict = st.session_state.get("current_rule_dict")
    # A session carried over from an older app version can hold rule_text
    # without rule_dict. Treat any incomplete pair as "no rule yet" and fall
    # back, rather than assuming both are present.
    if not rule_text or not isinstance(rule_dict, dict):
        st.info(
            "No rule built yet in this session — showing a classic ICMP ping "
            "example. Build a rule in the **Rule Builder** tab and come back; "
            "this page will switch to your rule automatically."
        )
        rule_text = _FALLBACK_RULE
        rule_dict = {
            "action": "alert", "protocol": "icmp", "src_ip": "any",
            "src_port": "any", "direction": "->", "dst_ip": "$HOME_NET",
            "dst_port": "any", "contents": [], "itype": "8", "sid": 1000001,
        }

    sid = rule_dict.get("sid", 1000001)

    # --- Step 1: the rules file -------------------------------------------------
    st.markdown("#### 1 — Put the rule in `local.rules`")
    st.code(rule_text, language="text")
    st.download_button(
        "⬇ Download local.rules",
        data=rule_text + "\n",
        file_name="local.rules",
        mime="text/plain",
        type="primary",
    )
    st.markdown(
        f"Copy it onto the VM (or paste into an editor) at `{RULES_PATH}`:"
    )
    st.code(f"sudo mkdir -p /usr/local/etc/rules\nsudo nano {RULES_PATH}", language="bash")

    # --- Step 2: snort.lua ---------------------------------------------------------
    st.markdown("#### 2 — Point `snort.lua` at your network and rules")
    st.markdown(
        "Snort needs to know what your network looks like and where your rules "
        "live. Open the config and check these two places:"
    )
    st.code(
        "-- near the top of snort.lua: define what 'home' means\n"
        "HOME_NET = '192.168.x.0/24'   -- your lab VM network\n"
        "EXTERNAL_NET = '!$HOME_NET'\n"
        "\n"
        "-- in the ips section: load your local rules\n"
        "ips =\n"
        "{\n"
        "    enable_builtin_rules = true,\n"
        f"    include = '{RULES_PATH}',\n"
        "    variables = default_variables\n"
        "}",
        language="lua",
    )
    st.caption(
        "Paths note: these commands assume Snort built from source "
        f"(`{SNORT_CONF}`). If Snort came from a package manager (e.g. "
        "`apt install snort`), the config usually lives at "
        "`/etc/snort/snort.lua` — adjust the paths to match your install."
    )

    # --- Step 3: validate -------------------------------------------------------------
    st.markdown("#### 3 — Validate with the Snort engine (the only true check)")
    st.code(f"snort -c {SNORT_CONF} -T", language="bash")
    st.markdown(
        "Look for `Snort successfully validated the configuration` at the end. "
        "If it errors, the message names the line in `local.rules` to fix."
    )

    # --- Step 4: trigger pcap -----------------------------------------------------------
    st.markdown("#### 4 — Test offline with a trigger pcap")
    payload, note = _derive_trigger_payload(rule_dict)
    st.markdown(f"*{note}*")
    if st.button("🎯 Generate trigger .pcap for this rule", type="secondary"):
        itype_raw = str(rule_dict.get("itype") or "8")
        icode_raw = str(rule_dict.get("icode") or "0")
        try:
            icmp_type = int("".join(ch for ch in itype_raw if ch.isdigit()) or 8)
            icmp_code = int("".join(ch for ch in icode_raw if ch.isdigit()) or 0)
            data = generate_mock_pcap(
                rule_dict.get("protocol", "tcp"),
                rule_dict.get("src_ip", "any"),
                rule_dict.get("dst_ip", "any"),
                rule_dict.get("src_port", "any"),
                rule_dict.get("dst_port", "any"),
                payload,
                is_hex=False,
                icmp_type=icmp_type,
                icmp_code=icmp_code,
            )
            st.session_state["lab_pcap"] = data
        except ValueError as exc:
            st.session_state.pop("lab_pcap", None)
            st.error(str(exc))
    if st.session_state.get("lab_pcap"):
        st.download_button(
            "⬇ Download trigger.pcap",
            data=st.session_state["lab_pcap"],
            file_name=f"trigger_{sid}.pcap",
            mime="application/vnd.tcpdump.pcap",
        )
        st.markdown("Replay it through Snort on the VM:")
        st.code(
            f"snort -c {SNORT_CONF} -r trigger_{sid}.pcap -A alert_fast -q",
            language="bash",
        )
        st.warning(
            "Honest limitation: this is a single crafted packet with no TCP "
            "handshake. Rules using `flow:established` or HTTP/DNS sticky "
            "buffers may not fire on it — that is Snort working correctly, not "
            "your rule failing. For those, generate real traffic (ping, curl, "
            "dig) while Snort runs live in step 5."
        )

    # --- Step 5: run live -----------------------------------------------------------------
    st.markdown("#### 5 — Run Snort live in IDS mode and trigger it for real")
    st.code(
        f"# find your interface name first\nip a\n\n"
        f"# run Snort as an IDS with console alerts\n"
        f"sudo snort -c {SNORT_CONF} -i eth0 -A alert_fast -q",
        language="bash",
    )
    proto = str(rule_dict.get("protocol", "")).lower()
    if proto == "icmp":
        st.markdown("Then, from another machine (or the host), ping the VM:")
        st.code("ping -c 4 <VM_IP>", language="bash")
    elif proto in ("tcp", "http"):
        st.markdown("Then generate matching traffic, e.g.:")
        st.code("curl http://<target>/admin", language="bash")
    elif proto == "udp":
        st.markdown("Then generate matching traffic, e.g.:")
        st.code("dig @<dns_server> badsite.example", language="bash")
    st.markdown(
        "Each alert line in the console shows the timestamp, your `msg` text, "
        "the classification, and the source → destination of the matching packet "
        "— exactly what the lab asks you to screenshot as evidence."
    )
