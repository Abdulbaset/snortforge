"""SnortForge — Streamlit entrypoint. Page config, banner, and tab routing only.

All real work lives in ui/ (views) and engine/ + storage/ (logic). This module
imports nothing from engine internals beyond the documented view functions.
"""

from __future__ import annotations

import os

import streamlit as st

from ui.branding import (
    TAGLINE,
    render_footer,
    render_global_styles,
    render_snortforge_logo,
)
from ui.builder_view import render_builder
from ui.converter_view import render_converter
from ui.library_view import render_library
from ui.pcap_view import render_pcap

st.set_page_config(page_title="SnortForge", page_icon="🛡", layout="wide")


# On Streamlit Community Cloud the database URL is supplied via App Secrets, not
# OS env. Bridge it into the environment so storage.get_repository() (which is
# deliberately Streamlit-agnostic) selects Postgres without any change to the
# storage layer. Falls back silently to SQLite when no secret is set.
try:
    _db_url = st.secrets.get("SNORTFORGE_DB_URL")
except Exception:
    _db_url = None
if _db_url:
    os.environ.setdefault("SNORTFORGE_DB_URL", str(_db_url))


def main() -> None:
    render_global_styles()
    render_snortforge_logo()
    st.markdown(
        f"<p style='letter-spacing:3px;color:#00D2FF;font-family:monospace;"
        f"margin-top:-10px;'>{TAGLINE}</p>",
        unsafe_allow_html=True,
    )

    tab_build, tab_convert, tab_pcap, tab_lib = st.tabs(
        ["🔨 Rule Builder", "🔁 Snort 2→3 Converter", "📦 PCAP Synth", "📚 Team Library"]
    )
    with tab_build:
        render_builder()
    with tab_convert:
        render_converter()
    with tab_pcap:
        render_pcap()
    with tab_lib:
        render_library()

    render_footer()


if __name__ == "__main__":
    main()
