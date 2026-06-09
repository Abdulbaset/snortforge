"""Phase 3 UI: Snort 2 -> Snort 3 converter tab (two-pane)."""

from __future__ import annotations

import streamlit as st

from engine.converter import convert_snort2_to_snort3

_EXAMPLE = (
    'alert tcp $HOME_NET any -> $EXTERNAL_NET 80 '
    '(msg:"legacy"; flow:to_server,established; '
    'content:"GET"; http_uri; nocase; content:"/admin"; http_uri; '
    'sid:1000001; rev:1;)'
)


def render_converter() -> None:
    st.subheader("Snort 2 → Snort 3 Converter")
    st.caption(
        "Groups each content with its trailing modifiers and emits sticky "
        "buffers on their own line, once per change. Output is well-formed, not "
        "engine-validated."
    )

    left, right = st.columns(2)

    with left:
        src = st.text_area(
            "Paste a Snort 2 rule", value=_EXAMPLE, height=320, key="conv_src"
        )
        if st.button("Convert", type="primary"):
            st.session_state["conv_result"] = convert_snort2_to_snort3(src)

    with right:
        result = st.session_state.get("conv_result")
        if result is None:
            st.info("Converted Snort 3 output will appear here.")
        elif result.startswith("Error:"):
            st.error(result)
        else:
            st.success("Converted (well-formed, not engine-validated).")
            st.code(result, language="text")
            st.caption("Use the copy icon in the code block's top-right to copy.")
            st.download_button(
                "⬇ Download .rules",
                data=result + "\n",
                file_name="converted.rules",
                mime="text/plain",
                type="primary",
            )
