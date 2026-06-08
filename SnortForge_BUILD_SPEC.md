# SnortForge — Build Specification for Claude Code

**Project:** Snort 3 Rule Generation, Migration and Validation Suite
**Codename:** SnortForge
**Builder:** Claude Code (agentic)
**Author of spec:** Abdulbaset Al-Saidy
**Status:** Ready to build

---

## 0. How to read this document

This is a build brief, not a wish list. Build it phase by phase. Do not skip ahead. Each phase has acceptance criteria. A phase is done only when every criterion passes and you have run the app and confirmed it. Treat the acceptance criteria as the contract.

Read section 1 (rules of engagement) before writing any code. It tells you what to build, what to test, and what you must never fake.

---

## 1. Rules of engagement (read first)

These bind every phase.

1. **Build incrementally and keep it running.** After each phase the app must launch with `streamlit run app.py` and load without errors. Never leave the tree in a broken state at a phase boundary.
2. **Do not fabricate validation.** The app does pre-flight checks only (well-formed IP, valid port range, compilable regex, SID in range). A rule that passes these checks is *well-formed*, not *validated by Snort*. Label it that way in the UI. The only true validator is the Snort engine itself. Never print "valid Snort rule" when you only checked syntax shape.
3. **Do not invent MITRE technique IDs.** Use the supplied seed list (section 7.3) and the live ATT&CK Enterprise matrix. Do not guess IDs. `T1043` is deprecated; do not use it.
4. **Write real tests.** Every engine function (converter, pcap synth, validators) needs unit tests with named cases, including the failure cases listed here. The build is not done until `pytest` is green.
5. **No silent stubs.** If you cannot finish a feature, leave a clearly labelled `# TODO(SnortForge): <what and why>` and surface it in the run notes. Do not return a stub that pretends to work.
6. **Keep modules decoupled.** UI never imports raw engine internals beyond the documented function signatures. Engines never import Streamlit except the pcap engine, which only needs it for the download buffer (and even there, prefer to return bytes and let the UI handle `st.download_button`).
7. **UK English in all user-facing copy.**

---

## 1A. Build environment (read before running anything)

This project is built on a **Windows desktop using Claude Cowork**, and run and tested **inside Docker**. The host OS does not matter because the app runs on `python:3.11-slim`, which is Linux, and the Dockerfile already provides `tcpdump` and `libpcap-dev` for Scapy.

**Hard rule for this build:** do not run `streamlit run app.py` directly on Windows to test. Scapy on bare Windows needs Npcap and is unreliable. Always verify the running app through Docker so Scapy never touches the Windows networking stack and the test environment matches production exactly.

Workflow:
1. Cowork writes and edits the code on Windows.
2. Build the image: `docker build -t snortforge .`
3. Run it: `docker run -d -p 8501:8501 snortforge`
4. Open `http://localhost:8501` and confirm the phase acceptance criteria.
5. For Phase 3, download a `.pcap` and confirm it opens in Wireshark with the crafted packet and payload bytes present. This is the step most likely to expose a Scapy problem, so do it early.

Prerequisites on the Windows machine:
- Docker Desktop with the **WSL2 backend** enabled. Docker runs far better on WSL2, and WSL2 gives a real Linux shell as a fallback if you ever want to run outside the container.
- `pytest` can run either inside the container or in a local Python 3.11 venv. Running it inside the container is preferred so it matches the runtime.

If a Linux host or the Ugreen NAS is available later, Docker is native there and slightly smoother, but it is not required. Windows plus Cowork plus Docker is the supported v1 path.

---

## 2. Objective and audience

A fast, visual web layer for cyber security engineers, SOC analysts and incident responders to build, validate, convert and test Snort 3 rules without hand-writing syntax. It removes syntax errors and shortens rule deployment time during live incidents.

It is a desktop-class internal tool, run locally or in Docker. It is not public-facing and has no auth in v1.

---

## 3. Tech stack (pinned)

- Python 3.11+
- Streamlit (UI)
- Scapy (packet synthesis)
- Pydantic v2 (validation models)
- `regex` module (PCRE-style checking)
- SQLite for local and Docker staging, PostgreSQL for production (same schema, swap the connection string)

Pinned versions live in `requirements.txt` (section 9). Do not float them.

---

## 4. Repository structure

Build to this layout exactly. It is what keeps the modules decoupled.

```
snortforge/
├── app.py                      # Streamlit entrypoint, page + tab routing only
├── ui/
│   ├── __init__.py
│   ├── branding.py             # render_snortforge_logo() + theme constants
│   ├── builder_view.py         # Phase 1 rule builder form
│   ├── converter_view.py       # Phase 3 Snort 2 -> 3 tab
│   ├── pcap_view.py            # Phase 3 pcap synthesis tab
│   └── library_view.py         # Phase 3 team library tab
├── engine/
│   ├── __init__.py
│   ├── rules_engine.py         # dict -> Snort 3 rule string
│   ├── converter.py            # convert_snort2_to_snort3()
│   ├── pcap_engine.py          # generate_mock_pcap()
│   └── validators.py           # Pydantic models + regex/SID/IP/port checks
├── storage/
│   ├── __init__.py
│   ├── models.py               # SavedRuleModel + DB schema
│   └── repository.py           # save/load/search, SQLite + Postgres backends
├── data/
│   └── mitre_techniques.py     # seed technique list
├── tests/
│   ├── test_converter.py
│   ├── test_pcap_engine.py
│   ├── test_validators.py
│   └── test_rules_engine.py
├── requirements.txt
├── Dockerfile
├── .dockerignore
└── README.md
```

---

## 5. Architecture

```
[ UI Layer ]        Streamlit views + state  (ui/)
      |
[ Core Engine ]     Rules Engine  <-->  Validation Engine  (engine/)
      |
[ Security Core ]   Scapy Packet Crafter + Converter        (engine/)
      |
[ Storage ]         SQLite / PostgreSQL team library         (storage/)
```

Data flows one way for building: form inputs in the UI become a plain dict, the validators sanitise the dict, the rules engine turns the clean dict into a Snort 3 string. The converter and pcap engine are independent utilities the UI calls on demand. Storage sits behind a repository interface so the SQLite and Postgres backends are interchangeable.

---

## 6. Branding and design tokens

Dark mode only. The visual identity is a defensive shield crossed with a forge.

**Colour tokens** (use these names as constants in `ui/branding.py`):

| Token | Hex | Use |
|---|---|---|
| `ACCENT_CYAN` | `#00D2FF` | primary accent, borders, active state, data nodes |
| `FORGE_AMBER` | `#FF5722` | alerts, the glowing core, destructive actions (drop/reject) |
| `CANVAS_DARK` | `#171C24` | panel and banner background |
| `TEXT_MUTED` | `#8A99AD` | secondary labels, tag lines |
| `TEXT_PRIMARY` | `#FFFFFF` | headings |

Set the Streamlit theme to match (`.streamlit/config.toml`: dark base, primary colour `#00D2FF`, background near `#171C24`).

Tag line: **DETECT. FORGE. DEFEND.** Sub-label under the wordmark: **Next-Gen Signature Synthesizer**.

**Logo banner.** Render this at the top of every view via `ui/branding.py`. It is a code-drawn banner, no image files needed.

```python
import streamlit as st

ACCENT_CYAN = "#00D2FF"
FORGE_AMBER = "#FF5722"
CANVAS_DARK = "#171C24"
TEXT_MUTED = "#8A99AD"

def render_snortforge_logo():
    """Render the SnortForge banner via inline CSS. No external assets."""
    logo_html = """
    <div style="display:flex; align-items:center; background-color:#171C24;
         padding:20px; border-radius:10px; border-left:5px solid #00D2FF;
         margin-bottom:25px;">
      <div style="position:relative; width:50px; height:50px; margin-right:20px;
           display:flex; align-items:center; justify-content:center;">
        <div style="position:absolute; width:44px; height:44px;
             border:3px solid #00D2FF; border-radius:8px; transform:rotate(45deg);"></div>
        <div style="position:absolute; width:14px; height:14px;
             background-color:#FF5722; border-radius:50%; box-shadow:0 0 12px #FF5722;"></div>
        <div style="position:absolute; width:6px; height:6px; background-color:#00D2FF;
             border-radius:50%; top:5px; left:22px;"></div>
        <div style="position:absolute; width:6px; height:6px; background-color:#00D2FF;
             border-radius:50%; bottom:5px; left:22px;"></div>
      </div>
      <div>
        <h1 style="font-family:'Courier New', monospace; color:#FFFFFF; margin:0;
            font-size:28px; font-weight:800; letter-spacing:1px;">
          SNORT<span style="color:#00D2FF;">FORGE</span>
        </h1>
        <p style="font-family:sans-serif; color:#8A99AD; margin:2px 0 0 0;
           font-size:12px; text-transform:uppercase; letter-spacing:2px;">
          Next-Gen Signature Synthesizer
        </p>
      </div>
    </div>
    """
    st.markdown(logo_html, unsafe_allow_html=True)
```

---

## 7. Feature specification by phase

### Phase 1 — Core engine and visual Snort 3 builder

Build the Streamlit shell, the rule header form, and the dict-to-string rules engine.

**7.1 Rule header engine**
- Action dropdown: `alert`, `log`, `drop`, `reject`, `pass`. Style `drop` and `reject` in amber to signal they block traffic.
- Protocol dropdown: `tcp`, `udp`, `icmp`, `ip`, `http`, `ftp`, `tls`, `ssh`.
- Source and destination IP fields. Accept CIDR (`192.168.1.0/24`), single IP, `any`, and variables `$HOME_NET`, `$EXTERNAL_NET`. Validate before compiling.
- Source and destination port fields. Accept single (`80`), list (`80,443`), range (`1024:65535`), `any`, and `$HTTP_PORTS`.
- Direction selector: `->` and `<>`.

**7.2 Content field array**
- A repeatable row interface. "Add Content Match" appends a row; each row is removable.
- Each row has the content string plus per-row modifier checkboxes `nocase` and `fast_pattern`. Emit Snort 3 form: `content:"<str>", nocase, fast_pattern;`.

**7.3 Sticky buffer dropdowns**
- Per content row, an optional sticky buffer selector: `http_uri`, `http_header`, `http_client_body`, `dns_query` (extensible list).
- **Hard requirement:** the rules engine must emit the sticky buffer on its own line *before* the content it applies to. In Snort 3 a sticky buffer applies to all following content until another buffer changes it, so only emit the buffer line when it differs from the currently active buffer. Do not repeat the same buffer line for consecutive content rows that share it.

**7.4 Output and SID**
- Auto-suggest a SID in the custom range (see 8.2) and a `rev:1;`.
- Render the assembled multi-line rule in a read-only code block with a copy control.
- "Download .rules" writes the rule to a downloadable file.

**Acceptance criteria, Phase 1**
- App launches and shows the branded banner.
- A user can build `alert tcp $HOME_NET any -> $EXTERNAL_NET 443` with two content matches and a `http_uri` buffer, and the output places `http_uri;` above the matching content line.
- Changing any field updates the output live.
- The `.rules` download produces a file containing exactly the rendered rule.
- `tests/test_rules_engine.py` covers: single content, multi content, buffer ordering, buffer de-duplication, and variable + CIDR headers.

---

### Phase 2 — Validation, guardrails and MITRE tracking

**8.1 Pydantic guard layer**
- Model the rule with Pydantic v2. Validate on every change. Surface a clear inline error next to the offending field, not a stack trace.
- IP/CIDR: validate with `ipaddress`. Accept the variables and `any` as valid literals.
- Ports: validate single, list and range forms; reject out-of-range (>65535) and inverted ranges.

**8.2 SID validation**
- Enforce `sid >= 1000000` for custom rules. If a user enters a SID below that, show an inline warning that the range is reserved. Warn, do not hard-block, but make the warning unmissable (amber).

**8.3 PCRE checking**
- A dedicated regex textbox. Test-compile the pattern with the `regex` module before allowing rule generation. On failure, show the compile error inline. Make clear this checks pattern compilability, not Snort PCRE2 semantics.

**8.4 MITRE ATT&CK mapping**
- Multi-select populated from `data/mitre_techniques.py`. Seed with current, valid Enterprise techniques, for example:
  - `T1071 — Application Layer Protocol`
  - `T1071.001 — Web Protocols`
  - `T1571 — Non-Standard Port`
  - `T1190 — Exploit Public-Facing Application`
  - `T1041 — Exfiltration Over C2 Channel`
- Do not use `T1043`; it is deprecated. Verify any added IDs against the live ATT&CK matrix.
- Selected techniques format into the rule `metadata:` block, for example `metadata:policy security-ips drop, mitre_attack T1071;` (follow the team's metadata convention; keep keys lowercase, comma-separated).

**Acceptance criteria, Phase 2**
- Malformed IP, inverted port range, and SID below 1000000 each produce a clear inline message.
- A broken regex shows its compile error and blocks generation until fixed.
- Selected MITRE techniques appear correctly in the metadata block.
- `tests/test_validators.py` covers each failure case above by name.

---

### Phase 3 — Migration, traffic simulation and team library

**9.1 Legacy Snort 2 to Snort 3 converter**

This is the highest-risk component. The original draft converter was wrong: it used `list.insert(-1, ...)`, which only places the buffer correctly when the content happens to be the last appended option. Rebuild it properly.

Behaviour:
- Split header from the options block.
- Walk options in order and group each `content:` with the modifiers that trail it in Snort 2 (`nocase`, `offset`, `depth`, `distance`, `within`, `fast_pattern`, and buffer modifiers like `http_uri`, `http_header`, `http_client_body`, `http_method`, `pcre` association).
- For each group: if a buffer modifier trailed the content, emit the matching sticky buffer line *before* the content line. Fold content modifiers into the Snort 3 comma form on the content line (`content:"x", nocase;`).
- Only emit a buffer line when the active buffer changes, matching Phase 1 behaviour.
- Preserve other options (`msg`, `sid`, `rev`, `flow`, `reference`, `metadata`) in place.
- On unparsable input, return a clear error string, never a half-converted rule.

Reference starting point (finish and harden it, then test against real rules):

```python
import re

BUFFER_MODIFIERS = {
    "http_uri", "http_header", "http_client_body", "http_method",
    "http_cookie", "http_raw_uri", "dns_query",
}
CONTENT_MODIFIERS = {"nocase", "offset", "depth", "distance", "within", "fast_pattern", "rawbytes"}

def convert_snort2_to_snort3(snort2_rule: str) -> str:
    rule = " ".join(snort2_rule.split())
    m = re.match(r"(.*?)\((.*)\)\s*$", rule)
    if not m:
        return "Error: invalid rule format. Could not separate header from options."
    header = m.group(1).strip()
    raw = [o.strip() for o in m.group(2).split(";") if o.strip()]

    out_lines, active_buffer = [], None
    i = 0
    while i < len(raw):
        opt = raw[i]
        if opt.startswith("content:"):
            content = opt
            mods, buffer_for_this = [], None
            j = i + 1
            while j < len(raw):
                nxt = raw[j]
                key = nxt.split(":", 1)[0].split(",", 1)[0].strip()
                if key in BUFFER_MODIFIERS:
                    buffer_for_this = key
                    j += 1
                elif key in CONTENT_MODIFIERS:
                    mods.append(nxt)
                    j += 1
                else:
                    break
            if buffer_for_this and buffer_for_this != active_buffer:
                out_lines.append(f"{buffer_for_this};")
                active_buffer = buffer_for_this
            body = content if not mods else f"{content}, " + ", ".join(mods)
            out_lines.append(f"{body};")
            i = j
        else:
            out_lines.append(f"{opt};")
            i += 1

    formatted = "\n    ".join(out_lines)
    return f"{header} (\n    {formatted}\n)"
```

Required test cases (`tests/test_converter.py`):
- Single content with trailing `http_uri; nocase;` -> buffer line above, modifiers folded.
- Two content matches sharing `http_uri` -> buffer emitted once.
- Content with no buffer -> no buffer line, content unchanged in form.
- A rule with `msg`, `flow`, `sid`, `rev` preserved and ordered.
- Garbage input -> clean error string, no exception.

**9.2 Scapy pcap synthesis**
- Inputs: protocol, source/dest IP, source/dest port, payload string or hex.
- Substitute sane defaults for variables and `any` (the draft uses `192.168.1.50`, `10.0.0.99`, ports `12345`/`80`). Keep that.
- Build `Ether/IP/(TCP|UDP)/payload`, write to an in-memory buffer with `wrpcap`, return bytes.
- Support a hex payload mode (`bytes.fromhex`) in addition to UTF-8 string.
- The UI offers a dual download: the `.rules` file and the matching `.pcap`.

Reference (extend with hex support and validation):

```python
import io
from scapy.all import IP, TCP, UDP, Ether, wrpcap

def generate_mock_pcap(proto, src_ip, dst_ip, src_port, dst_port,
                       payload, is_hex=False) -> bytes:
    buf = io.BytesIO()
    s_ip = "192.168.1.50" if "$" in str(src_ip) or src_ip == "any" else src_ip
    d_ip = "10.0.0.99" if "$" in str(dst_ip) or dst_ip == "any" else dst_ip
    s_port = 12345 if "$" in str(src_port) or src_port == "any" else int(src_port)
    d_port = 80 if "$" in str(dst_port) or dst_port == "any" else int(dst_port)

    pkt = Ether() / IP(src=s_ip, dst=d_ip)
    pkt = pkt / (UDP(sport=s_port, dport=d_port) if proto.lower() == "udp"
                 else TCP(sport=s_port, dport=d_port, flags="PA"))
    if payload:
        pkt = pkt / (bytes.fromhex(payload) if is_hex else payload.encode("utf-8"))
    wrpcap(buf, [pkt])
    return buf.getvalue()
```

**9.3 Team library (storage)**
- Pydantic model `SavedRuleModel` with: `id`, `sid`, `rev`, `title`, `author`, `raw_rule_text`, `mitre_tags: List[str]`, `created_at`, `updated_at`, `notes: Optional[str]`.
- Repository interface with two backends behind one API: SQLite (default, file in `data/`) and PostgreSQL (via env var connection string). The UI must not know which backend is active.
- Operations: save, update (bumps `rev` and `updated_at`), search by SID / title / MITRE tag, list, load into the builder.

```python
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel

class SavedRuleModel(BaseModel):
    id: Optional[int] = None
    sid: int
    rev: int
    title: str
    author: str
    raw_rule_text: str
    mitre_tags: List[str]
    created_at: datetime
    updated_at: datetime
    notes: Optional[str] = None
```

**Acceptance criteria, Phase 3**
- Converter passes all listed test cases.
- Pcap downloads open in Wireshark and show the crafted packet with the payload bytes present.
- A rule saves to SQLite, is found by SID and by MITRE tag, loads back into the builder, and an edit bumps the rev.
- Switching to Postgres needs only a connection-string change, no code change in the UI.

---

## 9. Packaging

### requirements.txt

```
streamlit==1.42.0
scapy==2.6.1
pydantic==2.10.6
regex==2024.11.6
psycopg[binary]==3.2.3
```

(Add `pytest` as a dev dependency; keep it out of the production image or in a separate `requirements-dev.txt`.)

### Dockerfile

```dockerfile
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    tcpdump \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl --fail http://localhost:8501/_stcore/health || exit 1

ENTRYPOINT ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

Note: the original Dockerfile called `curl` in the healthcheck but never installed it. It is added above. Add a `.dockerignore` for `__pycache__`, `*.db`, `.git`, `tests/`.

### Run commands

```bash
docker build -t snortforge .
docker run -d -p 8501:8501 snortforge
```

The earlier draft passed `--cap-add=NET_ADMIN`. That capability is needed only to send or sniff live traffic. SnortForge only *crafts and writes* pcap files to disk, which needs no special privilege, so drop the flag. Add it back only if you later add live capture.

---

## 10. Testing and validation

- `pytest` must pass before any phase is called done.
- Manual smoke test after each phase: launch, build a rule, read the output, confirm acceptance criteria.
- Be honest about validation scope in the UI. The app guarantees *well-formed* rules. It does not run the Snort engine. If you want true validation, document for the user how to run `snort -c <conf> -T` or `snort --rule-path` against the exported `.rules` file. Do not claim engine-level validation the app does not perform.

---

## 11. Do-not-repeat list (carried from the source drafts)

1. Converter buffer placement via `insert(-1, ...)` is broken. Use the ordered grouping logic in 9.1.
2. Healthcheck `curl` must be installed in the image.
3. Drop `--cap-add=NET_ADMIN` unless live capture is added.
4. `T1043` is deprecated. Do not seed it.
5. Never present "syntax-shape checks" as "Snort validation".

---

## 12. Out of scope for v1

Authentication, multi-user accounts, live packet capture, direct Snort engine integration, and rule performance profiling. Note them in the README as future work. Do not build them now.

---

## 13. Deliverables

1. The full module tree in section 4, working.
2. `requirements.txt` and `requirements-dev.txt`.
3. `Dockerfile` and `.dockerignore`, building and running on port 8501.
4. A `README.md` with local and Docker run steps, the validation caveat from section 10, and the out-of-scope list.
5. A passing `pytest` suite covering the cases named in each phase.
