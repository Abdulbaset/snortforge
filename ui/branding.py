"""SnortForge branding: design tokens and the code-drawn logo banner.

Dark mode only. The visual identity is a defensive shield crossed with a forge.
No external image assets are used; the banner is rendered via inline CSS.
"""

import streamlit as st

# --- Colour tokens (section 6) -------------------------------------------------
ACCENT_CYAN = "#00D2FF"   # primary accent, borders, active state, data nodes
FORGE_AMBER = "#FF5722"   # alerts, glowing core, destructive actions (drop/reject)
CANVAS_DARK = "#171C24"   # panel and banner background
TEXT_MUTED = "#8A99AD"    # secondary labels, tag lines
TEXT_PRIMARY = "#FFFFFF"  # headings

# --- Copy ---------------------------------------------------------------------
TAGLINE = "DETECT. FORGE. DEFEND."
SUB_LABEL = "Next-Gen Signature Synthesizer"
DEVELOPER = "Abdulbaset Al-Saidy"

# Actions that block traffic; the UI styles these in amber as a warning.
BLOCKING_ACTIONS = {"drop", "reject"}


def render_snortforge_logo() -> None:
    """Render the SnortForge banner via inline CSS. No external assets."""
    logo_html = f"""
    <div style="display:flex; align-items:center; background-color:{CANVAS_DARK};
         padding:20px; border-radius:10px; border-left:5px solid {ACCENT_CYAN};
         margin-bottom:25px;">
      <div style="position:relative; width:50px; height:50px; margin-right:20px;
           display:flex; align-items:center; justify-content:center;">
        <div style="position:absolute; width:44px; height:44px;
             border:3px solid {ACCENT_CYAN}; border-radius:8px; transform:rotate(45deg);"></div>
        <div style="position:absolute; width:14px; height:14px;
             background-color:{FORGE_AMBER}; border-radius:50%; box-shadow:0 0 12px {FORGE_AMBER};"></div>
        <div style="position:absolute; width:6px; height:6px; background-color:{ACCENT_CYAN};
             border-radius:50%; top:5px; left:22px;"></div>
        <div style="position:absolute; width:6px; height:6px; background-color:{ACCENT_CYAN};
             border-radius:50%; bottom:5px; left:22px;"></div>
      </div>
      <div>
        <h1 style="font-family:'Courier New', monospace; color:{TEXT_PRIMARY}; margin:0;
            font-size:28px; font-weight:800; letter-spacing:1px;">
          SNORT<span style="color:{ACCENT_CYAN};">FORGE</span>
        </h1>
        <p style="font-family:sans-serif; color:{TEXT_MUTED}; margin:2px 0 0 0;
           font-size:12px; text-transform:uppercase; letter-spacing:2px;">
          {SUB_LABEL}
        </p>
      </div>
    </div>
    """
    st.markdown(logo_html, unsafe_allow_html=True)


def render_footer() -> None:
    """Render the developer credit footer shown at the bottom of the app."""
    footer_html = f"""
    <hr style="border:none; border-top:1px solid #2A3340; margin-top:30px;">
    <p style="text-align:center; color:{TEXT_MUTED}; font-family:sans-serif;
       font-size:12px; letter-spacing:1px; margin-top:8px;">
      SnortForge &middot; Developed by <span style="color:{ACCENT_CYAN};
      font-weight:600;">{DEVELOPER}</span>
    </p>
    """
    st.markdown(footer_html, unsafe_allow_html=True)


# Extra surface colours derived from the core tokens, used by the global theme.
PANEL_DARK = "#1F2630"   # cards / inputs sit slightly above the canvas
BORDER_DIM = "#2A3340"   # hairline borders


def render_global_styles() -> None:
    """Inject a global CSS theme that lifts the app above Streamlit defaults.

    All colours come from the design tokens (section 6). Selectors use stable
    ``data-testid`` hooks where possible so the theme survives minor Streamlit
    version changes; if a selector ever stops matching, the app still works and
    simply falls back to the base dark theme.
    """
    css = f"""
    <style>
      /* Canvas: subtle radial glow from the top, forge-dark base. */
      .stApp {{
        background:
          radial-gradient(1200px 500px at 50% -200px,
                          rgba(0,210,255,0.07), transparent 70%),
          {CANVAS_DARK};
      }}

      /* Headings in the monospace identity font. */
      h1, h2, h3, .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 {{
        font-family: 'Courier New', monospace !important;
        letter-spacing: 0.5px;
      }}

      /* Tabs: pill bar with a glowing cyan active state. */
      .stTabs [data-baseweb="tab-list"] {{
        gap: 6px;
        background: {PANEL_DARK};
        padding: 6px;
        border-radius: 12px;
        border: 1px solid {BORDER_DIM};
      }}
      .stTabs [data-baseweb="tab"] {{
        border-radius: 8px;
        padding: 8px 16px;
        color: {TEXT_MUTED};
        font-family: 'Courier New', monospace;
        font-weight: 600;
      }}
      .stTabs [aria-selected="true"] {{
        background: rgba(0,210,255,0.12) !important;
        color: {ACCENT_CYAN} !important;
        box-shadow: inset 0 0 0 1px rgba(0,210,255,0.5),
                    0 0 12px rgba(0,210,255,0.25);
      }}
      .stTabs [data-baseweb="tab-highlight"] {{ background: {ACCENT_CYAN}; }}

      /* Inputs: panel background, cyan focus glow. */
      .stTextInput input, .stNumberInput input, .stTextArea textarea,
      [data-baseweb="select"] > div {{
        background-color: {PANEL_DARK} !important;
        border: 1px solid {BORDER_DIM} !important;
        border-radius: 8px !important;
      }}
      .stTextInput input:focus, .stNumberInput input:focus,
      .stTextArea textarea:focus {{
        border-color: {ACCENT_CYAN} !important;
        box-shadow: 0 0 0 2px rgba(0,210,255,0.25) !important;
      }}

      /* Buttons: cyan outline that fills + glows on hover. */
      .stButton > button, .stDownloadButton > button {{
        background: transparent;
        color: {ACCENT_CYAN};
        border: 1px solid {ACCENT_CYAN};
        border-radius: 8px;
        font-family: 'Courier New', monospace;
        font-weight: 700;
        transition: all 0.15s ease-in-out;
      }}
      .stButton > button:hover, .stDownloadButton > button:hover {{
        background: rgba(0,210,255,0.15);
        box-shadow: 0 0 14px rgba(0,210,255,0.35);
        color: {TEXT_PRIMARY};
      }}
      .stDownloadButton > button {{
        border-color: {FORGE_AMBER};
        color: {FORGE_AMBER};
      }}
      .stDownloadButton > button:hover {{
        background: rgba(255,87,34,0.15);
        box-shadow: 0 0 14px rgba(255,87,34,0.35);
        color: {TEXT_PRIMARY};
      }}

      /* Bordered containers (content-row cards) and expanders. */
      [data-testid="stExpander"], div[data-testid="stVerticalBlockBorderWrapper"] {{
        border: 1px solid {BORDER_DIM} !important;
        border-radius: 10px !important;
        background: rgba(31,38,48,0.5);
      }}

      /* Code blocks: cyan left rule to match the banner. */
      [data-testid="stCode"], .stCode {{
        border-left: 3px solid {ACCENT_CYAN};
        border-radius: 8px;
      }}

      /* Slightly tighten the top padding now the banner carries the header. */
      .block-container {{ padding-top: 2.2rem; }}
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)
