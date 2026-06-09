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


def render_global_styles(mode: str = "dark") -> None:
    """Inject the consolidated global CSS theme (single <style> block).

    Theme-aware: ``mode`` is "dark" (default) or "light". All surfaces are driven
    from CSS variables so switching modes only swaps the token block below; the
    accent palette is shared. Combines the original SnortForge refinements with
    the UI-improvement brief (constrained width, centered accent label bars on
    field labels, solid bordered dropdown, accent primary buttons, red-hover
    remove control, hidden chrome). Version-sensitive selectors have fallbacks;
    if a rule ever stops matching, the app still works.
    """
    if mode == "light":
        tokens = (
            "--sf-bg-app:#eef3f9;--sf-bg-card:#ffffff;--sf-bg-menu:#ffffff;"
            "--sf-text:#0b1524;--sf-text-muted:#51657a;"
            "--sf-border:#cfdbe8;--sf-border-soft:#dfe8f2;"
        )
    else:
        tokens = (
            "--sf-bg-app:#0b1524;--sf-bg-card:#0f1b2d;--sf-bg-menu:#0a1320;"
            "--sf-text:#e5edf5;--sf-text-muted:#9fb3c8;"
            "--sf-border:#24364f;--sf-border-soft:#1e2f47;"
        )

    rules = """
      /* Canvas + base text colour. */
      .stApp{
        background:
          radial-gradient(1200px 500px at 50% -200px, rgba(56,189,248,0.08), transparent 70%),
          var(--sf-bg-app);
        color:var(--sf-text);
      }
      .stApp p, .stApp li, .stApp label, .stMarkdown,
      [data-testid="stMarkdownContainer"]{ color:var(--sf-text); }

      /* Headings in the monospace identity font. */
      h1,h2,h3,.stMarkdown h1,.stMarkdown h2,.stMarkdown h3{
        font-family:'Courier New',monospace !important;
        letter-spacing:0.5px;color:var(--sf-text);
      }

      /* Constrain + center content so fields are not edge-to-edge on big screens. */
      .block-container{ max-width:1180px;margin-left:auto;margin-right:auto;padding-top:2rem; }

      /* Tabs: pill bar with a glowing accent active state. */
      .stTabs [data-baseweb="tab-list"]{
        gap:6px;background:var(--sf-bg-card);padding:6px;border-radius:12px;
        border:1px solid var(--sf-border-soft);
      }
      .stTabs [data-baseweb="tab"]{
        border-radius:8px;padding:8px 16px;color:var(--sf-text-muted);
        font-family:'Courier New',monospace;font-weight:600;
      }
      .stTabs [aria-selected="true"]{
        background:rgba(56,189,248,0.14)!important;color:var(--sf-accent)!important;
        box-shadow:inset 0 0 0 1px rgba(56,189,248,0.5),0 0 12px rgba(56,189,248,0.22);
      }
      .stTabs [data-baseweb="tab-highlight"]{background:var(--sf-accent);}

      /* Inputs: card background, dark/light text, accent focus ring. */
      .stTextInput input,.stNumberInput input,.stTextArea textarea,
      [data-baseweb="select"] > div{
        background-color:var(--sf-bg-card)!important;
        border:1px solid var(--sf-border)!important;border-radius:8px!important;
        color:var(--sf-text)!important;
      }
      .stTextInput input:focus,.stNumberInput input:focus,.stTextArea textarea:focus{
        border-color:var(--sf-accent)!important;box-shadow:0 0 0 2px rgba(56,189,248,0.25)!important;
      }

      /* Field labels: centered, uppercase, with an accent bar.
         label[...] not div[...]: text/select/number/textarea labels are <label>
         elements; checkbox/toggle labels are <div>, so this keeps the bar on
         field labels and leaves toggle labels (nocase/fast_pattern) plain. */
      label[data-testid="stWidgetLabel"] p{
        text-align:center;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;
        color:var(--sf-accent)!important;background:rgba(56,189,248,0.10);
        border-bottom:2px solid var(--sf-accent);border-radius:6px 6px 0 0;
        padding:6px 10px;margin-bottom:4px;width:100%;
      }

      /* Open dropdown menu: solid, bordered, visible (version-sensitive + fallback). */
      ul[data-testid="stSelectboxVirtualDropdown"],
      div[data-baseweb="popover"] ul[role="listbox"]{
        background-color:var(--sf-bg-menu)!important;border:1px solid var(--sf-accent)!important;
        border-radius:8px!important;box-shadow:0 8px 24px rgba(0,0,0,0.35)!important;padding:4px!important;
      }
      li[role="option"]{color:var(--sf-text)!important;border-radius:6px!important;margin:2px 0!important;}
      li[role="option"]:hover,li[role="option"][aria-selected="true"]{
        background-color:rgba(56,189,248,0.18)!important;color:var(--sf-accent-strong)!important;
      }

      /* Lift low-contrast helper / caption text. */
      div[data-testid="stCaptionContainer"],.stCaption,small{color:var(--sf-text-muted)!important;}

      /* Primary actions: accent fill (not red). Secondary: ghost accent. */
      .stButton>button[kind="primary"],.stDownloadButton>button[kind="primary"]{
        background:var(--sf-accent)!important;border:1px solid var(--sf-accent)!important;
        color:#04121f!important;font-weight:700;border-radius:8px;font-family:'Courier New',monospace;
      }
      .stButton>button[kind="primary"]:hover,.stDownloadButton>button[kind="primary"]:hover{
        background:var(--sf-accent-strong)!important;border-color:var(--sf-accent-strong)!important;
        box-shadow:0 0 14px rgba(56,189,248,0.4)!important;color:#04121f!important;
      }
      .stButton>button[kind="secondary"],.stDownloadButton>button[kind="secondary"]{
        border:1px solid var(--sf-accent)!important;color:var(--sf-accent)!important;
        background:transparent!important;border-radius:8px;font-family:'Courier New',monospace;font-weight:700;
      }
      .stButton>button[kind="secondary"]:hover{background:rgba(56,189,248,0.12)!important;}

      /* Remove-row control (st.button key="rm_*"): red on hover. */
      [class*="st-key-rm_"] button:hover{
        border-color:var(--sf-danger)!important;color:var(--sf-danger)!important;
        background:rgba(248,113,113,0.12)!important;box-shadow:0 0 10px rgba(248,113,113,0.3)!important;
      }

      /* Cards / expanders. */
      [data-testid="stExpander"]{
        border:1px solid var(--sf-border-soft)!important;border-radius:10px!important;background:var(--sf-bg-card);
      }
      div[data-testid="stVerticalBlockBorderWrapper"]{border-radius:10px!important;}

      /* Code blocks: accent left rule to match the banner. */
      [data-testid="stCode"],.stCode{border-left:3px solid var(--sf-accent);border-radius:8px;}

      /* Hide leftover Streamlit chrome (our own footer is plain markdown and stays). */
      #MainMenu{visibility:hidden;}
      footer{visibility:hidden;}
    """
    css = "<style>:root{--sf-accent:#38bdf8;--sf-accent-strong:#0ea5e9;" \
          "--sf-success:#34d399;--sf-danger:#f87171;" + tokens + "}" + rules + "</style>"
    st.markdown(css, unsafe_allow_html=True)
