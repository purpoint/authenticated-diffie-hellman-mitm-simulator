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

st.markdown(
    """
    <style>
    .block-container {max-width: 1160px; padding-top: 2.2rem; padding-bottom: 4rem;}
    [data-testid="stHeader"] {background: rgba(247,245,240,.92); height: 1.5rem;}
    [data-testid="stToolbar"] {display: none;}
    [data-testid="stSidebar"] {display: none;}
    h1, h2, h3 {letter-spacing: -.025em;}
    h1 {font-family: Georgia, 'Times New Roman', serif; font-weight: 600 !important;}
    .project-header {
        border-top: 5px solid #2f6f73;
        border-bottom: 1px solid #d7d2c7;
        padding: 1.6rem 0 1.4rem;
        margin-bottom: 1.5rem;
    }
    .course-line {color: #52636a; font-size: .82rem; font-weight: 650; letter-spacing: .055em;}
    .project-header h1 {font-size: 2.3rem; line-height: 1.13; margin: .5rem 0 .55rem; color: #1f3035;}
    .project-header p {max-width: 790px; color: #566469; font-size: 1.02rem; line-height: 1.65; margin: 0;}
    .project-meta {margin-top: .85rem; color: #657278; font-size: .86rem;}
    .problem-box {
        background: #fffdf8; border: 1px solid #d9d4c8; border-left: 4px solid #2f6f73;
        border-radius: 5px; padding: 1rem 1.15rem; margin: .4rem 0 1.1rem;
    }
    .problem-box strong {display: block; margin-bottom: .3rem; color: #24383d;}
    .problem-box p {margin: 0; color: #536166; line-height: 1.55;}
    .step-card {
        min-height: 175px; background: #fffdf8; border: 1px solid #ddd8cd;
        border-radius: 7px; padding: 1.05rem 1.1rem;
    }
    .step-number {
        display: inline-flex; width: 28px; height: 28px; border-radius: 50%;
        align-items: center; justify-content: center; background: #dce9e7;
        color: #245b5f; font-weight: 700; font-size: .82rem; margin-bottom: .7rem;
    }
    .step-card h4 {margin: 0 0 .4rem; color: #283c41; font-size: 1rem;}
    .step-card p {margin: 0; color: #647176; line-height: 1.5; font-size: .9rem;}
    .result-box {border-radius: 6px; padding: .9rem 1.05rem; margin: .4rem 0 1rem;}
    .result-box strong {display: block; margin-bottom: .2rem;}
    .result-safe {background: #e8f3ed; border: 1px solid #bad5c7; color: #285b43;}
    .result-danger {background: #f8e9e6; border: 1px solid #e4bbb2; color: #7c362d;}
    .result-caution {background: #faf2dc; border: 1px solid #e2d09e; color: #765d1e;}
    .party-card {background: #fffdf8; border: 1px solid #ddd8cd; border-radius: 6px; padding: 1rem; min-height: 138px;}
    .party-name {font-family: Georgia, serif; font-size: 1.1rem; color: #263b40; margin-bottom: .35rem;}
    .party-role {color: #687579; font-size: .86rem; line-height: 1.45;}
    .party-note {margin-top: .7rem; color: #7c362d; font-size: .82rem; font-weight: 600;}
    .party-alert {border-top: 3px solid #b65c4b;}
    .party-ok {border-top: 3px solid #4c8271;}
    .plain-note {color: #667378; font-size: .88rem; line-height: 1.55;}
    .small-label {color: #6a767a; font-size: .76rem; font-weight: 700; letter-spacing: .04em; text-transform: uppercase;}
    .message-panel {background: #fffdf8; border: 1px solid #ddd8cd; border-radius: 6px; padding: .9rem 1rem; min-height: 95px;}
    .message-panel p {margin: .35rem 0 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #27393e;}
    div[data-testid="stMetric"] {background: #fffdf8; border: 1px solid #ddd8cd; padding: .75rem .9rem; border-radius: 6px;}
    .stTabs [data-baseweb="tab-list"] {gap: 1.4rem; border-bottom: 1px solid #d9d4c8;}
    .stTabs [data-baseweb="tab"] {padding: .7rem .1rem; background: transparent;}
    .stTabs [aria-selected="true"] {color: #245f63; border-bottom-color: #2f6f73;}
    div.stButton > button[kind="primary"] {background: #2f6f73; border-color: #2f6f73; border-radius: 5px;}
    div.stButton > button {border-radius: 5px;}
    hr {border-color: #ded9ce;}
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_service() -> SimulationService:
    return SimulationService(AuditDatabase())


service = get_service()


def run_selected(mode: str, message: str, replacement: str) -> dict[str, object]:
    if mode == "Normal exchange":
        return service.run_normal(message)
    if mode == "MITM attack":
        return service.run_mitm(message, replacement)
    return service.run_authenticated(message)


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
        party_card(middle, "Untrusted network", "Mallory may intercept traffic, but cannot forge Alice's signature.")
        party_card(bob, "Bob", "Verified the signature before deriving and using the session key.")
    else:
        party_card(alice, "Alice", "Generated a temporary X25519 key and encrypted the message.")
        party_card(middle, "Network", "Only public keys and ciphertext travelled across the network.")
        party_card(bob, "Bob", "Derived the same session key and recovered the original message.")


def transcript_table(result: dict[str, object]) -> None:
    transcript = result.get("transcript", [])
    st.dataframe(
        transcript,
        width="stretch",
        hide_index=True,
        column_config={
            "Step": st.column_config.NumberColumn(width="small"),
            "Actor": st.column_config.TextColumn(width="medium"),
            "Operation": st.column_config.TextColumn(width="medium"),
            "Detail": st.column_config.TextColumn(width="large"),
            "State": st.column_config.TextColumn(width="small"),
        },
    )


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

overview_tab, demo_tab, results_tab, notes_tab = st.tabs(
    ["Project overview", "Live demonstration", "Results and history", "Project notes"]
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
        rows = [
            {
                "Case": result["scenario_label"],
                "Result": result["outcome"].title(),
                "Time (ms)": result["duration_ms"],
                "Explanation": result["security_result"],
            }
            for result in st.session_state["comparison_results"]
        ]
        st.dataframe(rows, width="stretch", hide_index=True)

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
    replacement = right.text_area(
        "Mallory's replacement message",
        "The meeting is cancelled",
        height=100,
        disabled=mode != "MITM attack",
        key="demo_replacement",
    )
    if st.button("Run simulation", type="primary", key="run_simulation"):
        try:
            st.session_state["last_result"] = run_selected(mode, message, replacement)
        except ValueError as exc:
            st.error(str(exc))
    if st.session_state.get("last_result"):
        st.divider()
        result = st.session_state["last_result"]
        render_result(result, f"result_{result['audit_id']}")

with results_tab:
    stats = service.database.get_statistics()
    metric_columns = st.columns(4)
    metric_columns[0].metric("Simulations run", stats["total_runs"])
    metric_columns[1].metric("MITM attacks shown", stats["attacks_exposed"])
    metric_columns[2].metric("Attacks prevented", stats["attacks_blocked"])
    metric_columns[3].metric("Normal deliveries", stats["secure_deliveries"])

    st.markdown("### Saved experiment history")
    filter_column, limit_column = st.columns([2, 1])
    scenario_filter = filter_column.selectbox(
        "Show",
        ["All", "Normal Exchange", "MITM Attack", "Authenticated Defense"],
    )
    history_limit = limit_column.number_input("Number of records", 10, 500, 50, 10)
    history = service.database.get_history(scenario=scenario_filter, limit=int(history_limit))
    if history:
        display_rows = [
            {
                "ID": row["id"],
                "Date (UTC)": row["created_at"],
                "Case": row["scenario"],
                "Result": row["outcome"].title(),
                "Time (ms)": row["duration_ms"],
                "Message hash": row["message_sha256"][:14] + "…",
            }
            for row in history
        ]
        st.dataframe(display_rows, width="stretch", hide_index=True)
        st.download_button(
            "Download history as CSV",
            history_to_csv(history),
            file_name=f"simulation-history-{datetime.now():%Y%m%d-%H%M%S}.csv",
            mime="text/csv",
        )
    else:
        st.info("No experiment records are available yet.")

    st.markdown("### Performance comparison")
    left, right = st.columns([1, 2])
    rounds = left.slider("Runs per case", 5, 200, 30, 5)
    if left.button("Run timing test", key="run_benchmark"):
        with st.spinner("Running the three cases..."):
            st.session_state["benchmark"] = benchmark_protocols(rounds)
    right.markdown(
        '<p class="plain-note">The authenticated case does extra signature work. '
        'The timing test measures that added cost on this computer.</p>',
        unsafe_allow_html=True,
    )
    if st.session_state.get("benchmark"):
        benchmark = st.session_state["benchmark"]
        st.dataframe(benchmark, width="stretch", hide_index=True)
        st.bar_chart(
            {str(row["Scenario"]): float(row["Average time (ms)"]) for row in benchmark},
            horizontal=True,
        )

with notes_tab:
    st.markdown("### How the four cryptographic parts fit together")
    st.markdown(
        """
        | Part | Purpose in this project |
        |---|---|
        | **X25519** | Lets Alice and Bob calculate the same shared secret. |
        | **HKDF-SHA-256** | Converts that secret into a key suitable for AES. |
        | **AES-256-GCM** | Encrypts the message and detects ciphertext modification. |
        | **Ed25519** | Proves who supplied each temporary X25519 public key. |
        """
    )
    st.markdown("### The point to remember")
    st.markdown(
        """
        <div class="problem-box">
          <strong>Mallory does not break the encryption.</strong>
          <p>The attack works because Alice and Bob encrypt with keys that they unknowingly
          established with Mallory. Authentication must therefore happen before the encrypted
          channel is trusted.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    with st.expander("Questions you may be asked in the viva"):
        st.markdown(
            """
            **Why is AES-GCM not enough?**

            AES-GCM protects a channel after its key has been established. It cannot identify
            the person who participated in the key exchange.

            **Why is HKDF used?**

            The raw X25519 output is key material. HKDF derives a fixed-length, protocol-specific
            AES key from it.

            **What is the difference between X25519 and Ed25519?**

            X25519 is used for key agreement. Ed25519 is used for digital signatures.

            **What is the main limitation of this simulation?**

            It assumes Alice and Bob already trust each other's Ed25519 public identity keys.
            Real systems distribute that trust through certificates or verified fingerprints.
            """
        )
    with st.expander("Assignment rubric coverage"):
        st.markdown(
            """
            - **Problem definition:** unauthenticated key exchange permits public-key substitution.
            - **Cryptographic concepts:** X25519, Ed25519, HKDF-SHA-256 and AES-GCM.
            - **Design:** three controlled cases using the same input message.
            - **Implementation:** working interface, CLI, SQLite history and report export.
            - **Analysis:** attack outcome, prevention result and timing comparison.
            - **Documentation:** architecture, project report, test suite and viva notes.
            """
        )

st.divider()
st.caption(
    "Educational mini project. Identity keys are generated in memory for each run; "
    "production systems require certificate or key-distribution infrastructure."
)

