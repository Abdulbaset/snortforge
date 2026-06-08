# SnortForge

**Next-Gen Signature Synthesizer** — *DETECT. FORGE. DEFEND.*

A fast, visual web layer for cyber security engineers, SOC analysts and incident
responders to build, validate, convert and test Snort 3 rules without
hand-writing syntax. It removes syntax errors and shortens rule deployment time
during live incidents.

SnortForge is a desktop-class **internal** tool, run locally or in Docker. It is
not public-facing and has no authentication in v1.

---

## ⚠ Validation scope — read this

SnortForge performs **pre-flight checks only**: well-formed IP/CIDR, valid port
ranges, compilable regex (syntax only, not Snort PCRE2 semantics), and SID range.
A rule that passes these checks is **well-formed**, *not* validated by the Snort
engine. The UI labels it as such.

**The only true validator is the Snort engine itself.** To truly validate an
exported `.rules` file, run it through Snort:

```bash
snort -c /path/to/snort.lua -R snortforge_1000001.rules -T
```

SnortForge never claims engine-level validation it does not perform.

---

## Features

- **Rule Builder** — visual Snort 3 header + content builder. Repeatable content
  rows with per-row `nocase` / `fast_pattern` and sticky-buffer selectors. The
  engine emits each sticky buffer on its own line *before* the content it applies
  to, and only when the active buffer changes (no duplicate buffer lines).
- **Validation & guardrails** — Pydantic v2 models plus inline field errors for
  malformed IPs, inverted/out-of-range ports, broken regex, and a reserved-range
  SID warning (`sid < 1000000`).
- **MITRE ATT&CK mapping** — multi-select of current Enterprise techniques,
  folded into the rule `metadata:` block. (T1043 is deprecated and not seeded.)
- **Snort 2 → Snort 3 converter** — ordered grouping of content + modifiers with
  correct sticky-buffer placement; returns a clean error string on bad input.
- **PCAP synthesis** — Scapy-crafted single packet (UTF-8 or hex payload),
  downloadable as `.pcap` for Wireshark inspection.
- **Team library** — save/search/load rules. SQLite by default, PostgreSQL in
  production via one connection-string change.

---

## How to use

The app opens on four tabs: **Rule Builder**, **Snort 2 → 3 Converter**,
**PCAP Synth**, and **Team Library**.

### Rule Builder — build a Snort 3 rule

1. **Set the header.** Choose the action (`drop`/`reject` are flagged amber
   because they block traffic), protocol, and direction (`->` one-way, `<>`
   bidirectional). Fill in source/destination IP and port. These accept single
   values, CIDR (`192.168.1.0/24`), lists (`80,443`), ranges (`1024:65535`),
   `any`, and Snort variables (`$HOME_NET`, `$HTTP_PORTS`). Bad values show a red
   error directly under the field.
2. **Add content matches.** Each row is one `content:` match. Type the string,
   optionally pick a **sticky buffer** (e.g. `http_uri`) to say *where* to look,
   and tick `nocase` / `fast_pattern`. Use **➕ Add Content Match** for more rows
   and the **✖** at the end of a row to remove it (the last row is kept).
3. **Optional PCRE.** Enter a regex (e.g. `/admin/i`). It is test-compiled live;
   a compile error blocks generation until fixed.
4. **Map MITRE techniques.** Pick from the multi-select; they fold into the
   rule's `metadata:` block.
5. **Set SID and rev.** Use a SID `>= 1000000` (the custom range). A lower SID
   shows an amber warning but does not block you.
6. **Use the output.** The assembled rule renders live in the code block. Copy it
   with the code block's copy icon, or click **⬇ Download .rules**.
7. **Save it (optional).** Expand **💾 Save to team library**, set a title/author/
   notes, and click **Save rule** to store it in the library.

> The builder guarantees a *well-formed* rule, not an engine-validated one. See
> the validation note above.

### Snort 2 → 3 Converter — migrate a legacy rule

Paste a Snort 2 rule into the box and click **Convert**. The converter groups
each `content:` with its trailing modifiers, lifts buffer modifiers (`http_uri`,
etc.) onto their own sticky-buffer line above the content, and preserves the rest
(`msg`, `flow`, `sid`, `rev`, …) in order. Bad input returns a clear error
instead of a half-converted rule. Download the result with **⬇ Download .rules**.

### PCAP Synth — craft a test packet

Pick TCP/UDP, set source/destination IP and port, and enter a payload (toggle
**Payload is hex** for raw bytes like `41424344`). Variables/`any` fall back to
sane defaults. Click **Generate .pcap**, then **⬇ Download .pcap** and open it in
Wireshark to confirm the crafted packet and payload bytes. No live traffic is
ever sent.

### Team Library — find and reuse rules

Leave the search boxes empty to list everything, or filter by **SID**, **title**,
or **MITRE tag**. Expand any rule to view its text, download it as `.rules`, or
click **Load into builder**. Editing a saved rule bumps its `rev`.

### A typical workflow

Build a rule in **Rule Builder** → craft a matching packet in **PCAP Synth** →
run `snort` against the exported `.rules` with that `.pcap` to confirm it fires →
**Save to team library** so the team can reuse it.

---

## Run locally (Python 3.11+)

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

Open http://localhost:8501.

> Note: Scapy on bare Windows needs Npcap and is unreliable. The supported path
> is Docker (below), which matches the production runtime exactly. On Windows,
> the `streamlit` command may not be on PATH — use `python -m streamlit run app.py`.

## Run in Docker (recommended)

```bash
docker build -t snortforge .
docker run -d -p 8501:8501 snortforge
```

Open http://localhost:8501. For PCAP synthesis, download a `.pcap` and confirm it
opens in Wireshark with the crafted packet and payload bytes present.

`--cap-add=NET_ADMIN` is **not** required: SnortForge only crafts and writes pcap
files, it does not send or sniff live traffic. Add it back only if live capture
is ever added.

---

## Deploy online — Streamlit Community Cloud (private)

SnortForge has **no built-in authentication** (v1 is an internal tool). Deploy it
as a **private** app so only people you allowlist can reach it. Community Cloud
does not use the `Dockerfile`; it installs from `requirements.txt` plus
`packages.txt` (already included for Scapy's `libpcap`/`tcpdump`).

1. **Push to a private GitHub repo.** From `D:\SnortForge\SnortForge`:
   ```powershell
   git init
   git add .
   git commit -m "SnortForge v1"
   git branch -M main
   git remote add origin https://github.com/<you>/snortforge.git
   git push -u origin main
   ```
   The included `.gitignore` keeps `secrets.toml`, `*.db`, and caches out of git.

2. **Provision a free Postgres** (Neon or Supabase). Copy its connection string.
   Without this, the app falls back to SQLite, which is **ephemeral** on Community
   Cloud and resets on every redeploy.

3. **Create the app** at https://share.streamlit.io → "New app" → pick your repo,
   branch `main`, main file `app.py`.

4. **Add the secret.** App settings → **Secrets**, paste (see
   `.streamlit/secrets.toml.example`):
   ```toml
   SNORTFORGE_DB_URL = "postgresql://USER:PASSWORD@HOST:5432/DBNAME?sslmode=require"
   ```
   `app.py` bridges this secret into the environment, so the storage layer selects
   Postgres automatically.

5. **Lock down access.** App settings → **Sharing** → keep it private and add
   viewer emails. Allowlisted users sign in with Google or a one-time emailed
   link; nobody else can open the app.

> Want stronger auth later? Add Streamlit's native OIDC login (`st.login`) or put
> Cloudflare Access in front. Both are out of scope for v1.

### Require sign-in (recommended, especially for a public repo)

A public repo means a Community Cloud app deployed from it is **publicly
viewable**, and SnortForge has no auth of its own. To gate it, the app supports
Streamlit's native OpenID Connect login (`st.login`). When an `[auth]` block is
present in secrets, `app.py` requires sign-in before anything renders; without
it, the app stays open (local/dev/tests).

1. Register an OAuth client with an OIDC provider (Google, Microsoft Entra,
   Auth0, Okta, …). Set the redirect URI to
   `https://YOUR-APP.streamlit.app/oauth2callback`.
2. Add an `[auth]` block to your Streamlit secrets (see
   `.streamlit/secrets.toml.example`):
   ```toml
   [auth]
   redirect_uri = "https://YOUR-APP.streamlit.app/oauth2callback"
   cookie_secret = "GENERATE_A_LONG_RANDOM_STRING"
   client_id = "YOUR_OAUTH_CLIENT_ID"
   client_secret = "YOUR_OAUTH_CLIENT_SECRET"
   server_metadata_url = "https://accounts.google.com/.well-known/openid-configuration"
   ```
   `Authlib` (in `requirements.txt`) is required for this to work.
3. Redeploy. Users now hit a sign-in screen; only authenticated users reach the
   app. Restrict *which* accounts further at the provider (e.g. limit to your
   Google Workspace domain), since `st.login` authenticates but does not itself
   maintain an allowlist.

### Alternative: Railway / Render (Docker + managed Postgres)

If you prefer running the actual Docker image with a managed database, Railway or
Render both deploy this repo's `Dockerfile` and provision a Postgres you wire to
`SNORTFORGE_DB_URL`. Put authentication (Cloudflare Access or `st.login`) in front
either way, since the app has none of its own.

---

## Storage backends

The UI talks only to `storage.repository.get_repository()`. By default this is a
SQLite file at `data/library.db`. To use PostgreSQL in production, set:

```bash
export SNORTFORGE_DB_URL="postgresql://user:pass@host:5432/snortforge"
```

No UI code changes are needed — the same schema and repository API serve both.

### Exercise the Postgres backend with Docker Compose

`docker-compose.yml` brings up the app plus a PostgreSQL container. Credentials
come from a local `.env` file (not committed), and `SNORTFORGE_DB_URL` is
assembled from them automatically. Copy the example once, then run:

```bash
cp .env.example .env        # Windows: copy .env.example .env
docker compose up --build
```

Open http://localhost:8501. The library tab now reads and writes Postgres. Data
persists in the `snortforge_pgdata` volume. To wipe it: `docker compose down -v`.
To go back to SQLite, run the plain image instead (`docker run -p 8501:8501
snortforge`).

---

## Testing

```bash
pip install -r requirements-dev.txt
pytest
```

The suite covers the rules engine (content, multi-content, buffer ordering and
de-duplication, variable + CIDR headers), validators (malformed IP, inverted
port range, sub-1,000,000 SID, broken regex, deprecated MITRE), the converter
(buffer placement, shared-buffer de-dup, option preservation, garbage input),
the pcap engine (payload bytes present, hex mode, default substitution), and the
team-library repository (save, search by SID/title/tag, load, rev bump on edit).

---

## Out of scope for v1 (future work)

Authentication, multi-user accounts, live packet capture, direct Snort engine
integration, and rule performance profiling. These are intentionally not built.

---

## Credits

**Developed by Abdulbaset Al-Saidy.**

*Author & developer: Abdulbaset Al-Saidy*
