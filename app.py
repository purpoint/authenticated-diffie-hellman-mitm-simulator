"""Streamlit interface for the Diffie-Hellman MITM mini project."""

from __future__ import annotations

from datetime import datetime
from html import escape

import streamlit as st

from audit_database import AuditDatabase
from crypto_simulator import benchmark_protocols
from report_generator import generate_run_report, history_to_csv
from simulation_service import SimulationService


st.set_page_config(
    page_title="Diffie-Hellman MITM Demonstration",
    page_icon=":material/lock:",
    layout="wide",
    initial_sidebar_state="collapsed",
)

dark_mode = bool(st.session_state.get("dark_mode", False))
theme = (
    {
        "page": "#101417",
        "surface": "#171d21",
        "surface_soft": "#20272c",
        "input": "#1d2428",
        "border": "#364047",
        "border_strong": "#465158",
        "text": "#e5e7e2",
        "heading": "#f1f3ee",
        "muted": "#aab3b5",
        "accent": "#6ea9a4",
        "accent_soft": "#233b3b",
        "header": "rgba(16,20,23,.94)",
        "safe_bg": "#193129",
        "safe_border": "#355d4d",
        "safe_text": "#b8ddc9",
        "danger_bg": "#3b2424",
        "danger_border": "#70413a",
        "danger_text": "#f0c3bb",
        "caution_bg": "#3a3321",
        "caution_border": "#6c5c32",
        "caution_text": "#ead99b",
    }
    if dark_mode
    else {
        "page": "#f7f5f0",
        "surface": "#fffdf8",
        "surface_soft": "#ebe8df",
        "input": "#efede6",
        "border": "#ddd8cd",
        "border_strong": "#d7d2c7",
        "text": "#263238",
        "heading": "#1f3035",
        "muted": "#647176",
        "accent": "#2f6f73",
        "accent_soft": "#dce9e7",
        "header": "rgba(247,245,240,.94)",
        "safe_bg": "#e8f3ed",
        "safe_border": "#bad5c7",
        "safe_text": "#285b43",
        "danger_bg": "#f8e9e6",
        "danger_border": "#e4bbb2",
        "danger_text": "#7c362d",
        "caution_bg": "#faf2dc",
        "caution_border": "#e2d09e",
        "caution_text": "#765d1e",
    }
)

theme_variables = ":root{" + ";".join(
    f"--{name.replace('_', '-')}:{value}" for name, value in theme.items()
) + ";}"

st.markdown(
    "<style>"
    + theme_variables
    + """
    .stApp {background: var(--page); color: var(--text);}
    .block-container {max-width: 1160px; padding-top: 2.2rem; padding-bottom: 4rem;}
    [data-testid="stHeader"] {background: var(--header); height: 1.5rem;}
    [data-testid="stToolbar"] {display: none;}
    [data-testid="stSidebar"] {display: none;}
    h1, h2, h3, h4 {letter-spacing: -.025em; color: var(--heading) !important;}
    p, li, label, [data-testid="stCaptionContainer"] {color: var(--text);}
    h1 {font-family: Georgia, 'Times New Roman', serif; font-weight: 600 !important;}
    .project-header {
        border-top: 5px solid var(--accent);
        border-bottom: 1px solid var(--border-strong);
        padding: 1.6rem 0 1.4rem;
        margin-bottom: 1.5rem;
    }
    .course-line {color: var(--muted); font-size: .82rem; font-weight: 650; letter-spacing: .055em;}
    .project-header h1 {font-size: 2.3rem; line-height: 1.13; margin: .5rem 0 .55rem; color: var(--heading);}
    .project-header p {max-width: 790px; color: var(--muted); font-size: 1.02rem; line-height: 1.65; margin: 0;}
    .project-meta {margin-top: .85rem; color: var(--muted); font-size: .86rem;}
    .problem-box {
        background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--accent);
        border-radius: 5px; padding: 1rem 1.15rem; margin: .4rem 0 1.1rem;
    }
    .problem-box strong {display: block; margin-bottom: .3rem; color: var(--heading);}
    .problem-box p {margin: 0; color: var(--muted); line-height: 1.55;}
    .step-card {
        min-height: 175px; background: var(--surface); border: 1px solid var(--border);
        border-radius: 7px; padding: 1.05rem 1.1rem;
    }
    .step-number {
        display: inline-flex; width: 28px; height: 28px; border-radius: 50%;
        align-items: center; justify-content: center; background: var(--accent-soft);
        color: var(--accent); font-weight: 700; font-size: .82rem; margin-bottom: .7rem;
    }
    .step-card h4 {margin: 0 0 .4rem; color: var(--heading); font-size: 1rem;}
    .step-card p {margin: 0; color: var(--muted); line-height: 1.5; font-size: .9rem;}
    .result-box {border-radius: 6px; padding: .9rem 1.05rem; margin: .4rem 0 1rem;}
    .result-box strong {display: block; margin-bottom: .2rem;}
    .result-safe {background: var(--safe-bg); border: 1px solid var(--safe-border); color: var(--safe-text);}
    .result-danger {background: var(--danger-bg); border: 1px solid var(--danger-border); color: var(--danger-text);}
    .result-caution {background: var(--caution-bg); border: 1px solid var(--caution-border); color: var(--caution-text);}
    .party-card {background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; min-height: 138px;}
    .party-name {font-family: Georgia, serif; font-size: 1.1rem; color: var(--heading); margin-bottom: .35rem;}
    .party-role {color: var(--muted); font-size: .86rem; line-height: 1.45;}
    .party-note {margin-top: .7rem; color: var(--danger-text); font-size: .82rem; font-weight: 600;}
    .party-alert {border-top: 3px solid #b65c4b;}
    .party-ok {border-top: 3px solid #4c8271;}
    .plain-note {color: var(--muted); font-size: .88rem; line-height: 1.55;}
    .small-label {color: var(--muted); font-size: .76rem; font-weight: 700; letter-spacing: .04em; text-transform: uppercase;}
    .message-panel {background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: .9rem 1rem; min-height: 95px;}
    .message-panel p {margin: .35rem 0 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--heading);}
    div[data-testid="stMetric"] {background: var(--surface); border: 1px solid var(--border); padding: .75rem .9rem; border-radius: 6px;}
    .stTabs [data-baseweb="tab-list"] {gap: 1.4rem; border-bottom: 1px solid var(--border);}
    .stTabs [data-baseweb="tab"] {padding: .7rem .1rem; background: transparent;}
    .stTabs [aria-selected="true"] {color: var(--accent); border-bottom-color: var(--accent);}
    div.stButton > button[kind="primary"] {background: var(--accent); border-color: var(--accent); border-radius: 5px; color: white;}
    div.stButton > button {border-radius: 5px; background: var(--surface); color: var(--text); border-color: var(--border);}
    div[data-baseweb="input"] > div, div[data-baseweb="textarea"] > div,
    div[data-baseweb="select"] > div {background: var(--input) !important; border-color: var(--border) !important;}
    input, textarea {color: var(--text) !important; -webkit-text-fill-color: var(--text) !important;}
    [data-testid="stExpander"], [data-testid="stDataFrame"] {border-color: var(--border) !important;}
    code {color: var(--text) !important; background: var(--surface-soft) !important;}
    .log-summary {background: var(--surface-soft); border: 1px solid var(--border); border-radius: 6px; padding: .9rem 1rem; color: var(--text); margin-bottom: 1rem;}
    .log-entry {display: grid; grid-template-columns: 105px 1fr 100px; gap: 1rem; align-items: center; padding: .85rem .2rem; border-bottom: 1px solid var(--border);}
    .log-entry:last-child {border-bottom: 0;}
    .run-number {font-weight: 700; color: var(--heading);}
    .run-time {font-size: .75rem; color: var(--muted);}
    .run-case {font-weight: 650; color: var(--heading); margin-bottom: .2rem;}
    .run-note {font-size: .86rem; color: var(--muted); line-height: 1.4;}
    .run-status {justify-self: end; font-size: .76rem; font-weight: 700; padding: .25rem .5rem; border-radius: 999px;}
    .status-delivered {background: var(--caution-bg); color: var(--caution-text);}
    .status-intercepted {background: var(--danger-bg); color: var(--danger-text);}
    .status-blocked {background: var(--safe-bg); color: var(--safe-text);}
    .math-card {background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; min-height: 165px;}
    .math-card h4 {margin: 0 0 .65rem; font-family: Georgia, serif;}
    .math-line {font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--text); margin: .4rem 0;}
    .math-muted {color: var(--muted); font-size: .84rem; line-height: 1.45;}
    .calculation-box {background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: .85rem 1rem; color: var(--text);}
    .calculation-box strong {display: block; margin-bottom: .35rem; color: var(--heading);}
    .calculation-box span {font-family: ui-monospace, SFMono-Regular, Menlo, monospace;}
    .comparison-list {border: 1px solid var(--border); border-radius: 6px; overflow: hidden;}
    .comparison-row {display: grid; grid-template-columns: 160px 125px 85px minmax(0, 1fr); gap: .75rem; padding: .8rem .9rem; border-bottom: 1px solid var(--border); align-items: start;}
    .comparison-row:last-child {border-bottom: 0;}
    .comparison-heading {font-size: .73rem; color: var(--muted); font-weight: 700; text-transform: uppercase; letter-spacing: .04em;}
    .comparison-value {color: var(--text); line-height: 1.45; overflow-wrap: anywhere;}
    .trace-list {border: 1px solid var(--border); border-radius: 6px; overflow: hidden;}
    .trace-row {display: grid; grid-template-columns: 38px minmax(0, 1fr) 82px; gap: .8rem; padding: .78rem .85rem; border-bottom: 1px solid var(--border); align-items: start;}
    .trace-row:last-child {border-bottom: 0;}
    .trace-step {width: 28px; height: 28px; border-radius: 50%; background: var(--accent-soft); color: var(--accent); display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: .78rem;}
    .trace-title {color: var(--heading); font-weight: 700; margin-bottom: .18rem; overflow-wrap: anywhere;}
    .trace-actor {color: var(--accent); font-size: .78rem; font-weight: 650; margin-left: .35rem;}
    .trace-detail {color: var(--muted); font-size: .86rem; line-height: 1.45; overflow-wrap: anywhere;}
    .trace-state {font-size: .7rem; font-weight: 700; border-radius: 999px; padding: .22rem .42rem; text-align: center; justify-self: end;}
    .trace-info {background: var(--surface-soft); color: var(--muted);}
    .trace-warning {background: var(--caution-bg); color: var(--caution-text);}
    .trace-danger {background: var(--danger-bg); color: var(--danger-text);}
    .trace-success {background: var(--safe-bg); color: var(--safe-text);}
    .mode-note {background: var(--surface-soft); border: 1px solid var(--border); border-radius: 6px; padding: .9rem 1rem; min-height: 100px; color: var(--muted); line-height: 1.5;}
    @media (max-width: 760px) {
        .comparison-row {grid-template-columns: 1fr 1fr;}
        .comparison-row > div:last-child {grid-column: 1 / -1;}
        .trace-row {grid-template-columns: 38px minmax(0, 1fr);}
        .trace-state {grid-column: 2; justify-self: start;}
    }
    .secret-box {background: var(--safe-bg); border: 1px solid var(--safe-border); border-radius: 6px; padding: 1rem; color: var(--safe-text); text-align: center; margin: 1rem 0;}
    .secret-value {font-family: Georgia, serif; font-size: 1.9rem; font-weight: 700; margin-top: .2rem;}
    hr {border-color: var(--border);}
    </style>
    """,
    unsafe_allow_html=True,
)

theme_left, theme_right = st.columns([8, 2])
with theme_right:
    st.toggle("Dark theme", key="dark_mode")


@st.cache_resource
def get_service() -> SimulationService:
    return SimulationService(AuditDatabase())


service = get_service()


def run_selected(mode: str, message: str, replacement: str) -> dict[str, object]:
    if mode == "Normal exchange":
        return service.run_normal(message)
    if mode == "MITM attack":
        return service.run_mitm(message, replacement)
    return service.run_authenticated(message, replacement)


def outcome_box(result: dict[str, object]) -> None:
    outcome = result["outcome"]
    if outcome == "ATTACK SUCCEEDED":
        css_class = "result-danger"
        heading = "The attack worked"
        detail = "Mallory read Alice's message and sent a different message to Bob."
    elif outcome == "ATTACK BLOCKED":
        css_class = "result-safe"
        heading = "The attack was stopped"
        detail = "Bob rejected Mallory's substituted key because the Ed25519 signature did not match."
    else:
        css_class = "result-caution"
        heading = "The message arrived, but identity was not checked"
        detail = "Alice and Bob created the same key, although this exchange would still accept a substituted public key."
    st.markdown(
        f'<div class="result-box {css_class}"><strong>{heading}</strong>{detail}</div>',
        unsafe_allow_html=True,
    )


def party_card(
    column,
    name: str,
    role: str,
    *,
    alert: bool = False,
    note: str | None = None,
) -> None:
    state_class = "party-alert" if alert else "party-ok"
    note_html = f'<div class="party-note">{escape(note)}</div>' if note else ""
    column.markdown(
        f'<div class="party-card {state_class}"><div class="party-name">{escape(name)}</div>'
        f'<div class="party-role">{escape(role)}</div>{note_html}</div>',
        unsafe_allow_html=True,
    )


def show_message_comparison(result: dict[str, object]) -> None:
    left, right = st.columns(2)
    if result["scenario_label"] == "MITM Attack":
        before = result["alice_sent"]
        after = result["bob_received"]
    else:
        before = result["sent_message"]
        after = result["received_message"]
    left.markdown(
        f'<div class="message-panel"><div class="small-label">Alice sent</div>'
        f'<p>{escape(str(before))}</p></div>',
        unsafe_allow_html=True,
    )
    right.markdown(
        f'<div class="message-panel"><div class="small-label">Bob received</div>'
        f'<p>{escape(str(after))}</p></div>',
        unsafe_allow_html=True,
    )


def show_network(result: dict[str, object]) -> None:
    alice, middle, bob = st.columns(3)
    if result["scenario_label"] == "MITM Attack":
        party_card(alice, "Alice", "Encrypted her message using a key that she believed belonged to Bob.")
        party_card(
            middle,
            "Mallory",
            "Created two separate encrypted channels, then read and changed the message.",
            alert=True,
            note=f"Intercepted: {result['mallory_read']}",
        )
        party_card(bob, "Bob", "Received a valid AES-GCM message, but it came from Mallory rather than Alice.", alert=True)
    elif result["scenario_label"] == "Authenticated Defense":
        party_card(alice, "Alice", "Signed her temporary X25519 key using her Ed25519 identity key.")
        party_card(
            middle,
            "Mallory's attempt",
            "Mallory substitutes a public key, but cannot forge Alice's signature.",
            alert=True,
            note=(
                "Attempted message: "
                f"{result.get('mallory_attempted_message', 'blocked before delivery')}"
            ),
        )
        party_card(bob, "Bob", "Verified the signature before deriving and using the session key.")
    else:
        party_card(alice, "Alice", "Generated a temporary X25519 key and encrypted the message.")
        party_card(middle, "Network", "Only public keys and ciphertext travelled across the network.")
        party_card(bob, "Bob", "Derived the same session key and recovered the original message.")


def transcript_table(result: dict[str, object]) -> None:
    transcript = result.get("transcript", [])
    rows: list[str] = []
    for entry in transcript:
        state = str(entry["State"]).lower()
        state_class = state if state in {"info", "warning", "danger", "success"} else "info"
        rows.append(
            '<div class="trace-row">'
            f'<div class="trace-step">{int(entry["Step"])}</div>'
            '<div>'
            f'<div class="trace-title">{escape(str(entry["Operation"]))}'
            f'<span class="trace-actor">{escape(str(entry["Actor"]))}</span></div>'
            f'<div class="trace-detail">{escape(str(entry["Detail"]))}</div>'
            '</div>'
            f'<div class="trace-state trace-{state_class}">{escape(str(entry["State"]))}</div>'
            '</div>'
        )
    st.markdown('<div class="trace-list">' + "".join(rows) + "</div>", unsafe_allow_html=True)


def render_comparison(results: list[dict[str, object]]) -> None:
    header = (
        '<div class="comparison-row comparison-heading">'
        '<div>Case</div><div>Result</div><div>Time</div><div>What it showed</div></div>'
    )
    rows: list[str] = []
    for result in results:
        rows.append(
            '<div class="comparison-row comparison-value">'
            f'<div><strong>{escape(str(result["scenario_label"]))}</strong></div>'
            f'<div>{escape(str(result["outcome"]).title())}</div>'
            f'<div>{float(result["duration_ms"]):.4f} ms</div>'
            f'<div>{escape(str(result["security_result"]))}</div>'
            '</div>'
        )
    st.markdown('<div class="comparison-list">' + header + "".join(rows) + "</div>", unsafe_allow_html=True)


def history_description(row: dict[str, object]) -> tuple[str, str, str]:
    scenario = str(row["scenario"])
    if scenario == "MITM Attack":
        return (
            "Intercepted",
            "status-intercepted",
            "Mallory established two channel keys and replaced Alice's message.",
        )
    if scenario == "Authenticated Defense":
        return (
            "Blocked",
            "status-blocked",
            "The signature check rejected the substituted ephemeral key.",
        )
    return (
        "Delivered",
        "status-delivered",
        "Alice and Bob completed an encrypted exchange without authenticating identity.",
    )


def format_run_time(raw_timestamp: object) -> str:
    try:
        parsed = datetime.fromisoformat(str(raw_timestamp))
        return parsed.strftime("%d %b, %H:%M UTC")
    except ValueError:
        return str(raw_timestamp)


def render_result(result: dict[str, object], report_key: str) -> None:
    outcome_box(result)
    show_network(result)
    st.markdown("#### Message comparison")
    show_message_comparison(result)
    st.markdown("#### What this result means")
    st.write(result["security_result"])
    with st.expander("Technical details and protocol transcript"):
        transcript_table(result)
        st.markdown("**Message fingerprint (SHA-256)**")
        st.code(str(result["message_sha256"]), language=None)
        st.caption(
            f"Audit record {result['audit_id']} · Completed in {result['duration_ms']} ms · "
            "Private and session keys are never stored."
        )
    slug = str(result["scenario_label"]).lower().replace(" ", "-")
    st.download_button(
        "Download this result",
        data=generate_run_report(result),
        file_name=f"{slug}-{result['audit_id']}.txt",
        mime="text/plain",
        key=report_key,
    )


st.markdown(
    """
    <div class="project-header">
      <div class="course-line">BCS703 · CRYPTOGRAPHY AND NETWORK SECURITY · MINI PROJECT</div>
      <h1>Diffie–Hellman Key Exchange and the Man-in-the-Middle Problem</h1>
      <p>This project shows a simple but important security lesson: an encrypted connection
      is not automatically a trusted connection. We first reproduce the attack, then add
      identity verification and run the same test again.</p>
      <div class="project-meta">Implemented with Python · X25519 · Ed25519 · HKDF-SHA-256 · AES-256-GCM</div>
    </div>
    """,
    unsafe_allow_html=True,
)

overview_tab, demo_tab, log_tab, playground_tab = st.tabs(
    ["Project overview", "Live demonstration", "Experiment log", "Key exchange playground"]
)

with overview_tab:
    st.markdown(
        """
        <div class="problem-box">
          <strong>Question investigated</strong>
          <p>Can Alice and Bob communicate safely if Diffie–Hellman creates a shared key,
          but neither person checks who supplied the public key?</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("### The experiment")
    columns = st.columns(3)
    steps = (
        ("1", "Start with a normal exchange", "Alice and Bob derive the same key and use AES-GCM to send a message."),
        ("2", "Put Mallory in the middle", "Mallory replaces both public keys and creates a separate encrypted channel with each person."),
        ("3", "Authenticate the keys", "Alice and Bob sign their temporary keys. Mallory's replacement no longer passes verification."),
    )
    for column, (number, heading, text) in zip(columns, steps):
        column.markdown(
            f'<div class="step-card"><div class="step-number">{number}</div>'
            f'<h4>{heading}</h4><p>{text}</p></div>',
            unsafe_allow_html=True,
        )

    st.write("")
    st.markdown("### Run the complete comparison")
    st.write("This runs the same message through all three cases and records each result.")
    left, right = st.columns(2)
    comparison_message = left.text_input("Original message", "Transfer ₹5,000 to Bob", key="comparison_message")
    comparison_replacement = right.text_input("Mallory changes it to", "Transfer ₹50,000 to Mallory", key="comparison_replacement")
    if st.button("Run all three cases", type="primary", key="run_comparison"):
        try:
            st.session_state["comparison_results"] = service.run_complete_demo(
                comparison_message, comparison_replacement
            )
            st.session_state["last_result"] = st.session_state["comparison_results"][-1]
            st.rerun()
        except ValueError as exc:
            st.error(str(exc))
    if st.session_state.get("comparison_results"):
        st.markdown("#### Comparison")
        render_comparison(st.session_state["comparison_results"])

with demo_tab:
    st.markdown("### Try one case at a time")
    st.write("Use the same message in different modes and compare what Bob finally receives.")
    mode = st.radio(
        "Choose a case",
        ["Normal exchange", "MITM attack", "Authenticated defense"],
        horizontal=True,
        key="demo_mode",
    )
    left, right = st.columns(2)
    message = left.text_area("Alice's message", "The meeting is at 10:00 AM", height=100, key="demo_message")
    if mode == "Normal exchange":
        replacement = ""
        right.markdown("**Mallory's message**")
        right.markdown(
            '<div class="mode-note"><strong>Not used in this case.</strong><br>'
            'The normal exchange contains only Alice and Bob, so there is no attacker '
            'trying to replace the message.</div>',
            unsafe_allow_html=True,
        )
    elif mode == "MITM attack":
        replacement = right.text_area(
            "Mallory's replacement message",
            "The meeting is cancelled",
            height=100,
            key="mitm_replacement",
        )
    else:
        replacement = right.text_area(
            "Mallory's attempted replacement",
            "The meeting is cancelled",
            height=100,
            help="You can change this text, but authentication stops it before Bob receives it.",
            key="authenticated_replacement",
        )
        right.caption("This is Mallory's intended message. The signature failure prevents it from being delivered.")
    if st.button("Run simulation", type="primary", key="run_simulation"):
        try:
            st.session_state["last_result"] = run_selected(mode, message, replacement)
        except ValueError as exc:
            st.error(str(exc))
    if st.session_state.get("last_result"):
        st.divider()
        result = st.session_state["last_result"]
        render_result(result, f"result_{result['audit_id']}")

with log_tab:
    stats = service.database.get_statistics()
    st.markdown("### Experiment log")
    st.markdown(
        f'<div class="log-summary">This local notebook contains <strong>{stats["total_runs"]}</strong> '
        f'runs: {stats["attacks_exposed"]} successful interception demonstrations and '
        f'{stats["attacks_blocked"]} rejected substitution attempts. Message text is not '
        'stored in the log; only its SHA-256 fingerprint is saved.</div>',
        unsafe_allow_html=True,
    )
    filter_column, limit_column = st.columns([2, 1])
    scenario_filter = filter_column.selectbox(
        "Show runs from",
        ["All", "Normal Exchange", "MITM Attack", "Authenticated Defense"],
    )
    history_limit = limit_column.number_input("Maximum entries", 10, 500, 50, 10)
    history = service.database.get_history(scenario=scenario_filter, limit=int(history_limit))
    if history:
        st.markdown("#### Recent observations")
        recent_html: list[str] = []
        for row in history[:10]:
            status, status_class, observation = history_description(row)
            recent_html.append(
                '<div class="log-entry">'
                f'<div><div class="run-number">Run {int(row["id"]):03d}</div>'
                f'<div class="run-time">{escape(format_run_time(row["created_at"]))}</div></div>'
                f'<div><div class="run-case">{escape(str(row["scenario"]))}</div>'
                f'<div class="run-note">{escape(observation)} Completed in '
                f'{float(row["duration_ms"]):.3f} ms.</div></div>'
                f'<div class="run-status {status_class}">{status}</div></div>'
            )
        st.markdown("".join(recent_html), unsafe_allow_html=True)

        display_rows = [
            {
                "Run": row["id"],
                "Recorded (UTC)": row["created_at"],
                "Case": row["scenario"],
                "Outcome": row["outcome"].title(),
                "Time (ms)": row["duration_ms"],
                "Message hash": row["message_sha256"][:14] + "…",
            }
            for row in history
        ]
        with st.expander("Open the complete audit table"):
            st.dataframe(display_rows, width="stretch", hide_index=True)
        st.download_button(
            "Export log as CSV",
            history_to_csv(history),
            file_name=f"experiment-log-{datetime.now():%Y%m%d-%H%M%S}.csv",
            mime="text/csv",
        )
    else:
        st.info("No runs match this filter. Run a case from the demonstration tab first.")

    st.divider()
    st.markdown("### Timing study")
    st.write("Repeat each case several times and compare its average running time on this computer.")
    left, right = st.columns([1, 2])
    rounds = left.slider("Repetitions per case", 5, 200, 30, 5)
    if left.button("Measure running time", key="run_benchmark"):
        with st.spinner("Running the three cases..."):
            st.session_state["benchmark"] = benchmark_protocols(rounds)
    right.markdown(
        '<p class="plain-note">This is a small local experiment, not a universal benchmark. '
        'The result changes with the computer and other processes running at the same time.</p>',
        unsafe_allow_html=True,
    )
    if st.session_state.get("benchmark"):
        benchmark = st.session_state["benchmark"]
        st.dataframe(benchmark, width="stretch", hide_index=True)
        st.bar_chart(
            {str(row["Scenario"]): float(row["Average time (ms)"]) for row in benchmark},
            horizontal=True,
        )
        normal_time = next(
            float(row["Average time (ms)"])
            for row in benchmark
            if row["Scenario"] == "Normal exchange"
        )
        protected_time = next(
            float(row["Average time (ms)"])
            for row in benchmark
            if row["Scenario"] == "Authenticated defense"
        )
        difference = protected_time - normal_time
        st.caption(
            f"Observation from this run: authentication added approximately {difference:.4f} ms "
            "to the complete exchange."
        )

with playground_tab:
    st.markdown("### Key exchange playground")
    st.write(
        "The real project uses X25519, whose numbers are far too large to follow by hand. "
        "This smaller example uses the same Diffie–Hellman idea so you can see why both sides "
        "arrive at one shared secret."
    )

    prime = st.select_slider(
        "Public prime number (p)",
        options=[23, 47, 59, 83],
        value=23,
        key="toy_prime",
    )
    base = 5
    slider_left, slider_right = st.columns(2)
    alice_private = slider_left.slider(
        "Alice's private number (a)", 2, prime - 2, 6, key="alice_private"
    )
    bob_private = slider_right.slider(
        "Bob's private number (b)", 2, prime - 2, 15, key="bob_private"
    )

    alice_public = pow(base, alice_private, prime)
    bob_public = pow(base, bob_private, prime)
    alice_shared = pow(bob_public, alice_private, prime)
    bob_shared = pow(alice_public, bob_private, prime)

    public_column, alice_column, bob_column = st.columns(3)
    public_column.markdown(
        f'<div class="math-card"><h4>Public information</h4>'
        f'<div class="math-line">p = {prime}</div><div class="math-line">g = {base}</div>'
        '<p class="math-muted">Everyone, including Mallory, is allowed to know these two values.</p></div>',
        unsafe_allow_html=True,
    )
    alice_column.markdown(
        f'<div class="math-card"><h4>Alice</h4>'
        f'<div class="math-line">private a = {alice_private}</div>'
        f'<div class="math-line">public A = {base}<sup>{alice_private}</sup> mod {prime} = {alice_public}</div>'
        f'<p class="math-muted">Alice sends only A = {alice_public}.</p></div>',
        unsafe_allow_html=True,
    )
    bob_column.markdown(
        f'<div class="math-card"><h4>Bob</h4>'
        f'<div class="math-line">private b = {bob_private}</div>'
        f'<div class="math-line">public B = {base}<sup>{bob_private}</sup> mod {prime} = {bob_public}</div>'
        f'<p class="math-muted">Bob sends only B = {bob_public}.</p></div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        f'<div class="secret-box"><div>Both sides independently calculate</div>'
        f'<div class="secret-value">shared secret = {alice_shared}</div></div>',
        unsafe_allow_html=True,
    )
    proof_left, proof_right = st.columns(2)
    proof_left.markdown(
        f'<div class="calculation-box"><strong>Alice calculates</strong>'
        f'<span>B<sup>a</sup> mod p = {bob_public}<sup>{alice_private}</sup> mod '
        f'{prime} = {alice_shared}</span></div>',
        unsafe_allow_html=True,
    )
    proof_right.markdown(
        f'<div class="calculation-box"><strong>Bob calculates</strong>'
        f'<span>A<sup>b</sup> mod p = {alice_public}<sup>{bob_private}</sup> mod '
        f'{prime} = {bob_shared}</span></div>',
        unsafe_allow_html=True,
    )
    if alice_shared == bob_shared:
        st.markdown(
            '<div class="result-box result-safe"><strong>The calculations match.</strong>'
            'Alice and Bob can now derive the same encryption key.</div>',
            unsafe_allow_html=True,
        )
    st.caption(
        "This is a teaching example with deliberately small values. It is not secure for real use; "
        "the application uses X25519 for the actual simulation."
    )

st.divider()
st.caption(
    "Educational mini project. Identity keys are generated in memory for each run; "
    "production systems require certificate or key-distribution infrastructure."
)

