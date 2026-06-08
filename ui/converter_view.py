"""Phase 3 UI: Snort 2 -> Snort 3 converter tab."""

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
    src = st.text_area("Paste a Snort 2 rule", value=_EXAMPLE, height=160)
    if st.button("Convert"):
        result = convert_snort2_to_snort3(src)
        if result.startswith("Error:"):
            st.error(result)
        else:
            st.success("Converted (well-formed).")
            st.code(result, language="text")
            st.download_button(
                "⬇ Download .rules",
                data=result + "\n",
                file_name="converted.rules",
                mime="text/plain",
            )
