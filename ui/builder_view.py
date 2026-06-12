"""Phase 1 + 2 UI: the visual Snort 3 rule builder with inline validation.

Extended for teaching and lab use: template presets, per-content positional
sub-options (offset/depth/distance/within), non-payload options (dsize, ttl,
flags, itype, icode), classtype + reference meta-data, and an "Explain this
rule" panel that annotates the generated rule line by line.
"""

from __future__ import annotations

from datetime import datetime, timezone

import streamlit as st

from data.mitre_techniques import label_to_id, technique_labels
from data.templates import TEMPLATE_NONE, TEMPLATES
from engine.explainer import explain_rule
from engine.rules_engine import STICKY_BUFFERS, build_rule
from engine.validators import (
    CUSTOM_SID_MIN,
    KNOWN_CLASSTYPES,
    validate_classtype,
    validate_dsize,
    validate_flags,
    validate_icmp_field,
    validate_ip,
    validate_pcre,
    validate_port,
    validate_reference,
    validate_sid,
    validate_ttl,
)
from storage.models import SavedRuleModel
from storage.repository import get_repository
from ui.branding import FORGE_AMBER

ACTIONS = ["alert", "log", "drop", "reject", "pass"]
PROTOCOLS = ["tcp", "udp", "icmp", "ip", "http", "ftp", "tls", "ssh"]
BLOCKING_ACTIONS = {"drop", "reject"}
BUFFER_NONE = "(none)"
CLASSTYPE_NONE = "(none)"
FLOW_PRESETS = ["", "to_server,established", "to_client,established", "established", "stateless"]

# UI-level sticky-buffer choices for the builder dropdown. Defined here (not in
# the engine) so the engine stays untouched per the improvement brief's
# guardrails. The engine emits whatever buffer string it is handed and the
# buffer-first ordering is unchanged. Adds http_host (and http_stat_code) on top
# of the engine's known buffers, http_* grouped first then dns_query.
_EXTRA_BUILDER_BUFFERS = ["http_host", "http_stat_code"]
# Alphabetical so the dropdown is easy to scan. "(none)" is prepended at use.
BUILDER_STICKY_BUFFERS = sorted(set(STICKY_BUFFERS) | set(_EXTRA_BUILDER_BUFFERS))

_EMPTY_ROW = {
    "content": "", "nocase": False, "fast_pattern": False, "buffer": BUFFER_NONE,
    "offset": "", "depth": "", "distance": "", "within": "",
}


#: Default widget values, seeded through session state once. Widgets then
#: declare only their key — never a value — so template loads (which write the
#: same keys) cannot conflict with widget defaults. This avoids Streamlit's
#: "created with a default value but also had its value set via the Session
#: State API" warning.
_WIDGET_DEFAULTS = {
    "b_src_ip": "$HOME_NET",
    "b_src_port": "any",
    "b_dst_ip": "$EXTERNAL_NET",
    "b_dst_port": "443",
    "b_msg": "SnortForge custom rule",
    "b_pcre": "",
    "b_rev": 1,
}


def _init_state() -> None:
    if "content_rows" not in st.session_state:
        st.session_state.content_rows = [dict(_EMPTY_ROW)]
    if "next_sid" not in st.session_state:
        st.session_state.next_sid = CUSTOM_SID_MIN + 1
    for key, default in _WIDGET_DEFAULTS.items():
        st.session_state.setdefault(key, default)
    st.session_state.setdefault("b_sid", int(st.session_state.next_sid))


def _apply_template(name: str) -> None:
    """Pre-fill every builder widget from a template, then rerun.

    Widget state is keyed (b_*) so a template can write directly into
    st.session_state before the widgets render on the next run.
    """
    t = TEMPLATES[name]
    ss = st.session_state
    ss["b_action"] = t["action"]
    ss["b_protocol"] = t["protocol"]
    ss["b_direction"] = t["direction"]
    ss["b_src_ip"] = t["src_ip"]
    ss["b_src_port"] = t["src_port"]
    ss["b_dst_ip"] = t["dst_ip"]
    ss["b_dst_port"] = t["dst_port"]
    ss["b_msg"] = t["msg"]
    ss["b_pcre"] = t["pcre"]
    ss["b_flow"] = t["flow"]
    ss["b_dsize"] = t["dsize"]
    ss["b_ttl"] = t["ttl"]
    ss["b_flags"] = t["flags"]
    ss["b_itype"] = t["itype"]
    ss["b_icode"] = t["icode"]
    ss["b_references"] = t["references"]
    ss["b_classtype"] = t["classtype"] or CLASSTYPE_NONE
    ss["b_sid"] = int(t["sid"])
    ss["b_rev"] = int(t["rev"])
    rows = []
    for row in t["contents"] or [dict(_EMPTY_ROW)]:
        r = dict(_EMPTY_ROW)
        r.update({k: ("" if v is None else v) for k, v in row.items()})
        if not r.get("buffer"):
            r["buffer"] = BUFFER_NONE
        rows.append(r)
    if not rows:
        rows = [dict(_EMPTY_ROW)]
    ss.content_rows = rows
    # Drop stale per-row widget keys so the new rows render with template values.
    for key in list(ss.keys()):
        if key.startswith(("content_", "buffer_", "nocase_", "fp_",
                           "offset_", "depth_", "distance_", "within_")):
            del ss[key]


def _inline(result, field_label: str) -> None:
    """Show an inline message for a CheckResult next to a field.

    Precedence matters: a soft failure flagged as a warning (e.g. a reserved-
    range SID, or a $variable note) must render as an amber warning, not a red
    error, even though its ``ok`` flag is False.
    """
    if not result.message:
        return
    if result.is_warning:
        st.warning(f"{field_label}: {result.message}")
    elif not result.ok:
        st.error(f"{field_label}: {result.message}")
    else:
        st.info(f"{field_label}: {result.message}")


def _blocking(result) -> bool:
    """A check is blocking only when it is a hard failure (not a warning)."""
    return (not result.ok) and (not result.is_warning)


def _int_or_none(value: str):
    """Parse an optional integer field; '' -> None; bad input -> 'error'."""
    s = str(value).strip()
    if s == "":
        return None
    try:
        return int(s)
    except ValueError:
        return "error"


def render_builder() -> None:
    _init_state()
    st.subheader("Rule Builder")
    st.caption(
        "Pre-flight checks only. A rule that passes here is **well-formed**, "
        "not validated by the Snort engine. Run `snort -c <conf> -T` against the "
        "exported .rules file for true validation."
    )

    # --- Templates -------------------------------------------------------------
    tc1, tc2 = st.columns([4, 1.4])
    with tc1:
        template_choice = st.selectbox(
            "📋 Start from a template",
            [TEMPLATE_NONE] + list(TEMPLATES.keys()),
            index=0,
            help="Lab-aligned starter rules. Loading one overwrites the form.",
        )
    with tc2:
        st.markdown("<div style='height:1.75rem'></div>", unsafe_allow_html=True)
        if st.button("Load template", type="secondary", use_container_width=True,
                     disabled=(template_choice == TEMPLATE_NONE)):
            _apply_template(template_choice)
            st.rerun()

    # --- Header --------------------------------------------------------------
    c1, c2, c3 = st.columns(3)
    with c1:
        action = st.selectbox("Action", ACTIONS, key="b_action")
        if action in BLOCKING_ACTIONS:
            st.markdown(
                f"<span style='color:{FORGE_AMBER};font-weight:700;'>"
                f"⚠ '{action}' blocks traffic</span>",
                unsafe_allow_html=True,
            )
    with c2:
        protocol = st.selectbox("Protocol", PROTOCOLS, key="b_protocol")
    with c3:
        direction = st.selectbox("Direction", ["->", "<>"], key="b_direction")

    if protocol == "icmp":
        st.info(
            "ICMP has no ports — keep both port fields as `any`. Use **itype** "
            "and **icode** (in Advanced options below) to match echo requests: "
            "itype 8 = ping, itype 0 = ping reply."
        )

    c4, c5, c6, c7 = st.columns(4)
    with c4:
        src_ip = st.text_input("Source IP", key="b_src_ip")
    with c5:
        src_port = st.text_input("Source port", key="b_src_port")
    with c6:
        dst_ip = st.text_input("Destination IP", key="b_dst_ip")
    with c7:
        dst_port = st.text_input("Destination port", key="b_dst_port")

    ip_src_res, ip_dst_res = validate_ip(src_ip), validate_ip(dst_ip)
    port_src_res, port_dst_res = validate_port(src_port), validate_port(dst_port)
    _inline(ip_src_res, "Source IP")
    _inline(ip_dst_res, "Destination IP")
    _inline(port_src_res, "Source port")
    _inline(port_dst_res, "Destination port")

    msg = st.text_input("Message (msg)", key="b_msg")

    # --- Content rows --------------------------------------------------------
    st.markdown("##### Content matches")
    rows = st.session_state.content_rows
    remove_idx = None
    content_int_errors = []
    for i, row in enumerate(rows):
        with st.container(border=True):
            rc1, rc2, rc3, rc4, rc5 = st.columns([3.4, 2.6, 2.3, 2.7, 0.9])
            with rc1:
                row["content"] = st.text_input(
                    f"Content #{i + 1}", value=row["content"], key=f"content_{i}"
                )
            with rc2:
                cur = row.get("buffer", BUFFER_NONE)
                options = [BUFFER_NONE] + BUILDER_STICKY_BUFFERS
                row["buffer"] = st.selectbox(
                    "Sticky buffer",
                    options,
                    index=options.index(cur) if cur in options else 0,
                    key=f"buffer_{i}",
                )
            with rc3:
                row["nocase"] = st.toggle(
                    "nocase", value=row["nocase"], key=f"nocase_{i}"
                )
            with rc4:
                row["fast_pattern"] = st.toggle(
                    "fast_pattern", value=row["fast_pattern"], key=f"fp_{i}"
                )
            with rc5:
                st.markdown("<div style='height:1.9rem'></div>", unsafe_allow_html=True)
                if st.button(
                    "✖",
                    key=f"rm_{i}",
                    type="secondary",
                    help="Remove content match",
                    use_container_width=True,
                ):
                    remove_idx = i

            # Positional sub-options (lab notes: payload options depth/offset).
            pc1, pc2, pc3, pc4 = st.columns(4)
            for col, key, hint in (
                (pc1, "offset", "Start searching this many bytes in"),
                (pc2, "depth", "Search at most this many bytes"),
                (pc3, "distance", "Bytes after the previous match"),
                (pc4, "within", "Window after the previous match"),
            ):
                with col:
                    row[key] = st.text_input(
                        key, value=str(row.get(key, "") or ""),
                        key=f"{key}_{i}", placeholder="optional", help=hint,
                    )
                    parsed = _int_or_none(row[key])
                    if parsed == "error":
                        content_int_errors.append(
                            f"Content #{i + 1} {key} — '{row[key]}' is not a whole number."
                        )

    if remove_idx is not None and len(rows) > 1:
        rows.pop(remove_idx)
        st.rerun()

    if st.button("➕ Add Content Match", type="secondary"):
        rows.append(dict(_EMPTY_ROW))
        st.rerun()

    # --- PCRE ----------------------------------------------------------------
    st.markdown("##### PCRE (optional)")
    pcre = st.text_input("PCRE pattern", placeholder="/admin/i", key="b_pcre")
    pcre_result = validate_pcre(pcre)
    if pcre:
        _inline(pcre_result, "PCRE")

    # --- Advanced options ------------------------------------------------------
    with st.expander("⚙ Advanced options (flow, non-payload, classtype, reference)"):
        flow = st.selectbox(
            "flow", FLOW_PRESETS, key="b_flow",
            format_func=lambda v: v or "(none)",
            help="Restrict matching to a session direction/state. TCP only.",
        )
        a1, a2, a3 = st.columns(3)
        with a1:
            dsize = st.text_input("dsize", key="b_dsize", placeholder="e.g. >1000",
                                  help="Payload size test: 100, >100, <5, 300<>400")
        with a2:
            ttl = st.text_input("ttl", key="b_ttl", placeholder="e.g. <5",
                                help="IP time-to-live test — handy for traceroute detection")
        with a3:
            flags = st.text_input("flags", key="b_flags", placeholder="e.g. S",
                                  help="TCP flags: F,S,R,P,A,U,C,E,0 with optional +, * or !")
        a4, a5 = st.columns(2)
        with a4:
            itype = st.text_input("itype (ICMP)", key="b_itype", placeholder="e.g. 8",
                                  help="ICMP type: 8 = echo request (ping), 0 = echo reply")
        with a5:
            icode = st.text_input("icode (ICMP)", key="b_icode", placeholder="e.g. 0",
                                  help="ICMP code qualifying the type")
        classtype = st.selectbox(
            "classtype", [CLASSTYPE_NONE] + KNOWN_CLASSTYPES, key="b_classtype",
            help="Categorises the attack and sets the alert priority.",
        )
        references_raw = st.text_area(
            "reference (one per line, system,id)", key="b_references",
            placeholder="cve,2021-44228\nurl,attack.mitre.org/techniques/T1071",
            height=80,
        )

    dsize_res = validate_dsize(dsize)
    ttl_res = validate_ttl(ttl)
    flags_res = validate_flags(flags)
    itype_res = validate_icmp_field(itype, "itype")
    icode_res = validate_icmp_field(icode, "icode")
    classtype_val = None if classtype == CLASSTYPE_NONE else classtype
    classtype_res = validate_classtype(classtype_val or "")
    references = [ln.strip() for ln in (references_raw or "").splitlines() if ln.strip()]
    ref_results = [(ref, validate_reference(ref)) for ref in references]
    for res, label in ((dsize_res, "dsize"), (ttl_res, "ttl"), (flags_res, "flags"),
                       (itype_res, "itype"), (icode_res, "icode"),
                       (classtype_res, "classtype")):
        _inline(res, label)
    for ref, res in ref_results:
        _inline(res, f"reference '{ref}'")
    if flags and protocol != "tcp":
        st.warning("flags: TCP flags only make sense with the tcp protocol.")
    if (itype or icode) and protocol != "icmp":
        st.warning("itype/icode: these only make sense with the icmp protocol.")

    # --- MITRE ---------------------------------------------------------------
    st.markdown("##### MITRE ATT&CK mapping")
    selected_labels = st.multiselect("Techniques", technique_labels())
    mitre_ids = [label_to_id(lbl) for lbl in selected_labels]

    # --- SID / rev -----------------------------------------------------------
    sc1, sc2 = st.columns(2)
    with sc1:
        sid = st.number_input("SID", step=1, format="%d", key="b_sid")
    with sc2:
        rev = st.number_input("rev", min_value=1, step=1, format="%d", key="b_rev")
    sid_result = validate_sid(int(sid))
    _inline(sid_result, "SID")

    # --- Assemble & gate -----------------------------------------------------
    contents = []
    for r in rows:
        if not r["content"].strip():
            continue
        entry = {
            "content": r["content"],
            "nocase": r["nocase"],
            "fast_pattern": r["fast_pattern"],
            "buffer": None if r["buffer"] == BUFFER_NONE else r["buffer"],
        }
        for key in ("offset", "depth", "distance", "within"):
            parsed = _int_or_none(r.get(key, ""))
            entry[key] = None if parsed == "error" else parsed
        contents.append(entry)

    rule_dict = {
        "action": action,
        "protocol": protocol,
        "src_ip": src_ip,
        "src_port": src_port,
        "direction": direction,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "msg": msg,
        "contents": contents,
        "pcre": pcre or None,
        "flow": flow or None,
        "dsize": dsize.strip() or None,
        "ttl": ttl.strip() or None,
        "flags": flags.strip() or None,
        "itype": itype.strip() or None,
        "icode": icode.strip() or None,
        "references": references,
        "classtype": classtype_val,
        "mitre": mitre_ids,
        "sid": int(sid),
        "rev": int(rev),
    }

    # Collect blocking issues (hard failures only; warnings do not block).
    issues = []
    if _blocking(ip_src_res):
        issues.append(f"Source IP — {ip_src_res.message}")
    if _blocking(ip_dst_res):
        issues.append(f"Destination IP — {ip_dst_res.message}")
    if _blocking(port_src_res):
        issues.append(f"Source port — {port_src_res.message}")
    if _blocking(port_dst_res):
        issues.append(f"Destination port — {port_dst_res.message}")
    if pcre and _blocking(pcre_result):
        issues.append(f"PCRE — {pcre_result.message}")
    for res, label in ((dsize_res, "dsize"), (ttl_res, "ttl"), (flags_res, "flags"),
                       (itype_res, "itype"), (icode_res, "icode"),
                       (classtype_res, "classtype")):
        if _blocking(res):
            issues.append(f"{label} — {res.message}")
    for ref, res in ref_results:
        if _blocking(res):
            issues.append(f"reference '{ref}' — {res.message}")
    issues.extend(content_int_errors)
    can_generate = not issues

    st.markdown("---")
    st.markdown("### Generated Snort 3 rule")

    # B2: single consolidated verdict line.
    if not can_generate:
        st.error(
            "**Not well-formed — fix these blocking issues:**\n\n"
            + "\n".join(f"- {m}" for m in issues)
        )
        return

    rule_text = build_rule(rule_dict)
    st.code(rule_text, language="text")
    st.success(
        "✓ Well-formed — passes SnortForge pre-flight checks "
        "(syntax shape only, not validated by the Snort engine)."
    )
    st.caption("Use the copy icon in the code block's top-right to copy.")

    # --- Explain this rule -----------------------------------------------------
    with st.expander("🎓 Explain this rule (line by line)"):
        st.caption(
            "Reads the rule the way the lab notes do: header components first, "
            "then each option grouped by category."
        )
        for fragment, explanation in explain_rule(rule_dict):
            fc, ec = st.columns([1.6, 4])
            with fc:
                st.code(fragment, language="text")
            with ec:
                st.markdown(explanation)

    st.session_state["current_rule_text"] = rule_text
    st.session_state["current_rule_dict"] = rule_dict
    st.session_state["current_rule_meta"] = {
        "sid": int(sid),
        "rev": int(rev),
        "title": msg,
        "mitre_tags": mitre_ids,
    }

    st.download_button(
        "⬇ Download .rules",
        data=rule_text + "\n",
        file_name=f"snortforge_{int(sid)}.rules",
        mime="text/plain",
        type="primary",
    )

    # --- Save to team library ------------------------------------------------
    with st.expander("💾 Save to team library"):
        title = st.text_input("Title", value=msg, key="save_title")
        author = st.text_input("Author", value="Abdulbaset Al-Saidy", key="save_author")
        notes = st.text_area("Notes", value="", key="save_notes")
        if st.button("Save rule", type="primary"):
            repo = get_repository()
            now = datetime.now(timezone.utc)
            model = SavedRuleModel(
                sid=int(sid),
                rev=int(rev),
                title=title,
                author=author,
                raw_rule_text=rule_text,
                mitre_tags=mitre_ids,
                created_at=now,
                updated_at=now,
                notes=notes or None,
            )
            duplicates = repo.search(sid=int(sid))
            saved = repo.save(model)
            st.success(f"Saved to library with id {saved.id}.")
            if duplicates:
                st.warning(
                    f"Heads-up: SID {int(sid)} already exists in the library "
                    f"({len(duplicates)} other entr"
                    f"{'y' if len(duplicates) == 1 else 'ies'}). Snort requires "
                    "unique SIDs in a deployed rules file — bump the SID (or "
                    "the rev, if this is a new revision of the same rule) "
                    "before deploying them together."
                )
