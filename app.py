"""SnortForge — Streamlit entrypoint. Page config, auth gate, and tab routing.

All real work lives in ui/ (views) and engine/ + storage/ (logic). This module
imports nothing from engine internals beyond the documented view functions.

Authentication: SnortForge has no auth of its own, so when an OIDC provider is
configured (an ``[auth]`` block in Streamlit secrets) this entrypoint gates the
whole app behind ``st.login()``. When no provider is configured — local dev,
Docker, and the test harness — the gate is skipped and the app is open, exactly
as before. This keeps the tool usable locally while letting a public deployment
require sign-in.
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


def _auth_configured() -> bool:
    """True when an OIDC provider is configured via an [auth] secrets block."""
    try:
        return "auth" in st.secrets
    except Exception:
        return False


def _user_ns():
    """Return Streamlit's user namespace across versions (st.user / experimental)."""
    return getattr(st, "user", None) or getattr(st, "experimental_user", None)


def _is_logged_in() -> bool:
    """Safe login check; returns False if auth isn't wired up."""
    user = _user_ns()
    try:
        return bool(user.is_logged_in)
    except Exception:
        return False


def _render_login_screen() -> None:
    """Branded sign-in gate shown when auth is required but the user is not in."""
    render_global_styles()
    render_snortforge_logo()
    st.info(
        "SnortForge is a restricted internal tool. Please sign in to continue."
    )
    st.button("🔐 Log in", type="primary", on_click=st.login)
    render_footer()


def main() -> None:
    # Gate the app behind sign-in only when an auth provider is configured.
    if _auth_configured() and not _is_logged_in():
        _render_login_screen()
        return

    # Light/dark mode toggle (top-right). Default dark. Generous column width so
    # the label never clips against the container edge.
    spacer, toggle_col = st.columns([4, 1.6])
    with toggle_col:
        light = st.toggle(
            "Light mode",
            value=(st.session_state.get("theme", "dark") == "light"),
            key="theme_toggle",
            help="Switch between light and dark mode",
        )
    st.session_state["theme"] = "light" if light else "dark"

    # Defensive: if a stale/older branding module (no mode parameter) is ever
    # loaded by the host, fall back to the no-arg call so the app still renders.
    try:
        render_global_styles(st.session_state["theme"])
    except TypeError:
        render_global_styles()
    render_snortforge_logo()
    st.markdown(
        f"<p style='letter-spacing:3px;color:#00D2FF;font-family:monospace;"
        f"margin-top:-10px;'>{TAGLINE}</p>",
        unsafe_allow_html=True,
    )

    # When signed in, offer a logout control and show who is signed in.
    if _auth_configured() and _is_logged_in():
        user = _user_ns()
        who = getattr(user, "email", None) or getattr(user, "name", None) or "user"
        with st.sidebar:
            st.caption(f"Signed in as {who}")
            st.button("Log out", on_click=st.logout)

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
