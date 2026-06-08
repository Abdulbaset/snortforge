"""Phase 1 + 2 UI: the visual Snort 3 rule builder with inline validation."""

from __future__ import annotations

from datetime import datetime, timezone

import streamlit as st

from data.mitre_techniques import label_to_id, technique_labels
from engine.rules_engine import STICKY_BUFFERS, build_rule
from engine.validators import (
    CUSTOM_SID_MIN,
    validate_ip,
    validate_pcre,
    validate_port,
    validate_sid,
)
from storage.models import SavedRuleModel
from storage.repository import get_repository
from ui.branding import FORGE_AMBER

ACTIONS = ["alert", "log", "drop", "reject", "pass"]
PROTOCOLS = ["tcp", "udp", "icmp", "ip", "http", "ftp", "tls", "ssh"]
BLOCKING_ACTIONS = {"drop", "reject"}
BUFFER_NONE = "(none)"


def _init_state() -> None:
    if "content_rows" not in st.session_state:
        st.session_state.content_rows = [
            {"content": "", "nocase": False, "fast_pattern": False, "buffer": BUFFER_NONE}
        ]
    if "next_sid" not in st.session_state:
        st.session_state.next_sid = CUSTOM_SID_MIN + 1


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


def render_builder() -> None:
    _init_state()
    st.subheader("Rule Builder")
    st.caption(
        "Pre-flight checks only. A rule that passes here is **well-formed**, "
        "not validated by the Snort engine. Run `snort -c <conf> -T` against the "
        "exported .rules file for true validation."
    )

    # --- Header --------------------------------------------------------------
    c1, c2, c3 = st.columns(3)
    with c1:
        action = st.selectbox("Action", ACTIONS, index=0)
        if action in BLOCKING_ACTIONS:
            st.markdown(
                f"<span style='color:{FORGE_AMBER};font-weight:700;'>"
                f"⚠ '{action}' blocks traffic</span>",
                unsafe_allow_html=True,
            )
    with c2:
        protocol = st.selectbox("Protocol", PROTOCOLS, index=0)
    with c3:
        direction = st.selectbox("Direction", ["->", "<>"], index=0)

    c4, c5, c6, c7 = st.columns(4)
    with c4:
        src_ip = st.text_input("Source IP", value="$HOME_NET")
    with c5:
        src_port = st.text_input("Source port", value="any")
    with c6:
        dst_ip = st.text_input("Destination IP", value="$EXTERNAL_NET")
    with c7:
        dst_port = st.text_input("Destination port", value="443")

    _inline(validate_ip(src_ip), "Source IP")
    _inline(validate_ip(dst_ip), "Destination IP")
    _inline(validate_port(src_port), "Source port")
    _inline(validate_port(dst_port), "Destination port")

    msg = st.text_input("Message (msg)", value="SnortForge custom rule")

    # --- Content rows --------------------------------------------------------
    st.markdown("##### Content matches")
    rows = st.session_state.content_rows
    remove_idx = None
    for i, row in enumerate(rows):
        card = st.container(border=True)
        with card:
            rc1, rc2, rc3, rc4, rc5 = st.columns([4, 3, 2, 2, 1])
        with rc1:
            row["content"] = st.text_input(
                f"Content #{i + 1}", value=row["content"], key=f"content_{i}"
            )
        with rc2:
            buffers = [BUFFER_NONE] + STICKY_BUFFERS
            cur = row.get("buffer", BUFFER_NONE)
            row["buffer"] = st.selectbox(
                "Sticky buffer",
                buffers,
                index=buffers.index(cur) if cur in buffers else 0,
                key=f"buffer_{i}",
            )
        with rc3:
            row["nocase"] = st.checkbox("nocase", value=row["nocase"], key=f"nocase_{i}")
        with rc4:
            row["fast_pattern"] = st.checkbox(
                "fast_pattern", value=row["fast_pattern"], key=f"fp_{i}"
            )
        with rc5:
            st.write("")
            if st.button("✖", key=f"rm_{i}", help="Remove this row"):
                remove_idx = i

    if remove_idx is not None and len(rows) > 1:
        rows.pop(remove_idx)
        st.rerun()

    if st.button("➕ Add Content Match"):
        rows.append(
            {"content": "", "nocase": False, "fast_pattern": False, "buffer": BUFFER_NONE}
        )
        st.rerun()

    # --- PCRE ----------------------------------------------------------------
    st.markdown("##### PCRE (optional)")
    pcre = st.text_input("PCRE pattern", value="", placeholder="/admin/i")
    pcre_result = validate_pcre(pcre)
    if pcre:
        _inline(pcre_result, "PCRE")

    # --- MITRE ---------------------------------------------------------------
    st.markdown("##### MITRE ATT&CK mapping")
    selected_labels = st.multiselect("Techniques", technique_labels())
    mitre_ids = [label_to_id(lbl) for lbl in selected_labels]

    # --- SID / rev -----------------------------------------------------------
    sc1, sc2 = st.columns(2)
    with sc1:
        sid = st.number_input(
            "SID", value=int(st.session_state.next_sid), step=1, format="%d"
        )
    with sc2:
        rev = st.number_input("rev", value=1, min_value=1, step=1, format="%d")
    sid_result = validate_sid(int(sid))
    _inline(sid_result, "SID")

    # --- Assemble & gate -----------------------------------------------------
    contents = [
        {
            "content": r["content"],
            "nocase": r["nocase"],
            "fast_pattern": r["fast_pattern"],
            "buffer": None if r["buffer"] == BUFFER_NONE else r["buffer"],
        }
        for r in rows
        if r["content"].strip()
    ]
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
        "mitre": mitre_ids,
        "sid": int(sid),
        "rev": int(rev),
    }

    hard_errors = [
        not validate_ip(src_ip).ok,
        not validate_ip(dst_ip).ok,
        not validate_port(src_port).ok,
        not validate_port(dst_port).ok,
        bool(pcre) and not pcre_result.ok,
    ]
    can_generate = not any(hard_errors)

    st.markdown("---")
    st.markdown("### Generated Snort 3 rule")
    if not can_generate:
        st.error("Fix the errors above before generating the rule.")
        return

    rule_text = build_rule(rule_dict)
    st.code(rule_text, language="text")
    st.caption("Use the copy icon in the code block's top-right to copy.")

    dc1, dc2 = st.columns(2)
    with dc1:
        st.download_button(
            "⬇ Download .rules",
            data=rule_text + "\n",
            file_name=f"snortforge_{int(sid)}.rules",
            mime="text/plain",
        )
    with dc2:
        st.session_state["current_rule_text"] = rule_text
        st.session_state["current_rule_meta"] = {
            "sid": int(sid),
            "rev": int(rev),
            "title": msg,
            "mitre_tags": mitre_ids,
        }

    # --- Save to team library ------------------------------------------------
    with st.expander("💾 Save to team library"):
        title = st.text_input("Title", value=msg, key="save_title")
        author = st.text_input("Author", value="Abdulbaset Al-Saidy", key="save_author")
        notes = st.text_area("Notes", value="", key="save_notes")
        if st.button("Save rule"):
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
            saved = repo.save(model)
            st.success(f"Saved to library with id {saved.id}.")
