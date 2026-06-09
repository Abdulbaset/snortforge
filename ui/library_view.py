"""Phase 3 UI: team library tab (search, sort, list, load into builder)."""

from __future__ import annotations

import streamlit as st

from storage.repository import get_repository

_SORT_RECENT = "Most recent"
_SORT_SID = "SID"


def render_library() -> None:
    st.subheader("Team Library")
    st.caption("Saved rules in the shared library (SQLite by default).")

    repo = get_repository()
    all_rules = repo.list_all()

    # B6: when the library is empty, show only the empty-state message and hide
    # the search/sort controls. They appear once at least one rule exists.
    if not all_rules:
        st.info("No rules saved yet. Build one and save it from the Rule Builder tab.")
        return

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        sid_q = st.text_input("Search by SID", value="")
    with c2:
        title_q = st.text_input("Search by title", value="")
    with c3:
        tag_q = st.text_input("Search by MITRE tag", value="")
    with c4:
        sort_by = st.selectbox("Sort by", [_SORT_RECENT, _SORT_SID], index=0)

    sid_val = None
    if sid_q.strip():
        try:
            sid_val = int(sid_q.strip())
        except ValueError:
            st.warning("SID search must be a number; ignoring it.")

    if sid_val is not None or title_q.strip() or tag_q.strip():
        results = repo.search(
            sid=sid_val,
            title=title_q.strip() or None,
            mitre_tag=tag_q.strip() or None,
        )
    else:
        results = list(all_rules)

    if sort_by == _SORT_SID:
        results.sort(key=lambda r: r.sid)
    else:
        results.sort(key=lambda r: r.updated_at, reverse=True)

    if not results:
        st.info("No rules match your search.")
        return

    for rule in results:
        with st.expander(
            f"SID {rule.sid} · rev {rule.rev} · {rule.title}  "
            f"({', '.join(rule.mitre_tags) or 'no tags'})"
        ):
            st.code(rule.raw_rule_text, language="text")
            st.caption(
                f"Author: {rule.author} · Updated: {rule.updated_at:%Y-%m-%d %H:%M UTC}"
            )
            if rule.notes:
                st.write(rule.notes)
            cc1, cc2 = st.columns(2)
            with cc1:
                if st.button("Load into builder", key=f"load_{rule.id}", type="secondary"):
                    st.session_state["loaded_rule"] = rule.raw_rule_text
                    st.success("Loaded. See the Rule Builder tab (raw text in session).")
            with cc2:
                st.download_button(
                    "⬇ .rules",
                    data=rule.raw_rule_text + "\n",
                    file_name=f"snortforge_{rule.sid}.rules",
                    mime="text/plain",
                    key=f"dl_{rule.id}",
                    type="primary",
                )
