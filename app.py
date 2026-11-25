"""Professional Streamlit dashboard for the authenticated key-exchange project."""

from __future__ import annotations

from datetime import datetime

import streamlit as st

from audit_database import AuditDatabase
from crypto_simulator import benchmark_protocols
from report_generator import generate_run_report, history_to_csv
from simulation_service import SimulationService


st.set_page_config(
    page_title="ADH Security Lab",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    :root {--panel:#0f1d2e;--border:#253b52;--cyan:#22d3ee;--green:#34d399;
    --red:#fb7185;--amber:#fbbf24;--text:#eef6ff;--muted:#93a8bd;}
    .stApp {background:radial-gradient(circle at 85% 0%,rgba(34,211,238,.08),transparent 30rem),linear-gradient(180deg,#07111f 0%,#0a1625 100%);}
    [data-testid="stSidebar"] {background:linear-gradient(180deg,#0b1727 0%,#08121f 100%);border-right:1px solid var(--border);}
    [data-testid="stHeader"] {background:transparent;}
    .block-container {max-width:1440px;padding-top:1.5rem;}
    .hero {padding:1.5rem 1.65rem;border:1px solid var(--border);border-radius:18px;background:linear-gradient(135deg,rgba(20,38,58,.96),rgba(10,25,42,.96));box-shadow:0 18px 60px rgba(0,0,0,.22);margin-bottom:1rem;}
    .hero-kicker {color:var(--cyan);font-weight:750;letter-spacing:.12em;font-size:.78rem;}
    .hero h1 {color:var(--text);margin:.35rem 0 .25rem;font-size:2.15rem;letter-spacing:-.035em;}
    .hero p {color:var(--muted);margin:0;max-width:900px;font-size:1.02rem;}
    .chip {display:inline-block;margin:.85rem .38rem 0 0;padding:.28rem .6rem;border-radius:999px;border:1px solid #31506d;color:#cbeafe;background:rgba(59,130,246,.09);font-size:.76rem;font-weight:650;}
    .status-card {min-height:92px;padding:1rem 1.1rem;border:1px solid var(--border);border-radius:14px;background:linear-gradient(145deg,#122338,#0c1a2a);}
    .status-card .label {color:var(--muted);font-size:.72rem;font-weight:750;letter-spacing:.08em;}
    .status-card .value {color:var(--text);font-size:1.75rem;font-weight:780;margin-top:.25rem;}
    .section-card {border:1px solid var(--border);border-radius:14px;padding:1rem 1.1rem;background:rgba(15,29,46,.88);margin:.4rem 0 .8rem;}
    .actor-card {border:1px solid var(--border);border-radius:14px;padding:1rem;background:linear-gradient(160deg,#14263a,#0e1b2b);min-height:132px;}
    .actor-card h4 {margin:0 0 .4rem;color:var(--text);}.actor-card p {color:var(--muted);margin:.25rem 0;}
    .outcome-good {border-left:4px solid var(--green);}.outcome-bad {border-left:4px solid var(--red);}.outcome-warn {border-left:4px solid var(--amber);}
    div[data-testid="stMetric"] {background:linear-gradient(145deg,#122338,#0c1a2a);border:1px solid var(--border);padding:.8rem 1rem;border-radius:14px;}
    div[data-testid="stMetricLabel"] {color:var(--muted);}
    .stTabs [data-baseweb="tab-list"] {gap:.35rem;border-bottom:1px solid var(--border);}
    .stTabs [data-baseweb="tab"] {border-radius:9px 9px 0 0;padding:.55rem .85rem;}
    .stTabs [aria-selected="true"] {background:rgba(34,211,238,.1);color:var(--cyan);}
    code {color:#c4f1ff !important;}
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_service() -> SimulationService:
    return SimulationService(AuditDatabase())


service = get_service()


def metric_cards() -> None:
    stats = service.database.get_statistics()
    cards = (
        ("TOTAL LAB RUNS", stats["total_runs"], "#eef6ff"),
        ("ATTACKS EXPOSED", stats["attacks_exposed"], "#fb7185"),
        ("ATTACKS BLOCKED", stats["attacks_blocked"], "#34d399"),
        ("SECURE DELIVERIES", stats["secure_deliveries"], "#22d3ee"),
    )
    for column, (label, value, color) in zip(st.columns(4), cards):
        column.markdown(
            f'<div class="status-card"><div class="label">{label}</div>'
            f'<div class="value" style="color:{color}">{value}</div></div>',
            unsafe_allow_html=True,
        )


def outcome_banner(result: dict[str, object]) -> None:
    outcome = str(result["outcome"])
    if outcome == "ATTACK SUCCEEDED":
        st.error("🔴 ATTACK SUCCEEDED — Mallory obtained plaintext and changed the message.")
    elif outcome == "ATTACK BLOCKED":
        st.success("🟢 ATTACK BLOCKED — the substituted public key failed identity verification.")
    else:
        st.warning("🟡 MESSAGE DELIVERED — encrypted, but peer identity was not authenticated.")


def transcript_table(result: dict[str, object]) -> None:
    transcript = result.get("transcript", [])
    if transcript:
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
    else:
        st.info("No transcript is available for this run.")


def download_report(result: dict[str, object], key: str) -> None:
    slug = str(result["scenario_label"]).lower().replace(" ", "-")
    st.download_button(
        "Download evidence report",
        data=generate_run_report(result),
        file_name=f"{slug}-audit-{result['audit_id']}.txt",
        mime="text/plain",
        key=key,
    )


def render_result(result: dict[str, object], *, report_key: str) -> None:
    outcome_banner(result)
    metrics = st.columns(3)
    metrics[0].metric("Audit ID", f"#{result['audit_id']}")
    metrics[1].metric("Execution", f"{result['duration_ms']} ms")
    metrics[2].metric("Transcript", f"{len(result.get('transcript', []))} steps")

    if result["scenario_label"] == "MITM Attack":
        alice, mallory, bob = st.columns(3)
        alice.markdown('<div class="actor-card outcome-warn"><h4>👩 Alice</h4><p>Believes Mallory\'s key belongs to Bob.</p></div>', unsafe_allow_html=True)
        alice.write(f"**Sent:** {result['alice_sent']}")
        mallory.markdown('<div class="actor-card outcome-bad"><h4>🕵️ Mallory</h4><p>Owns both channel keys and can decrypt and re-encrypt.</p></div>', unsafe_allow_html=True)
        mallory.write(f"**Read:** {result['mallory_read']}")
        mallory.write(f"**Forwarded:** {result['mallory_forwarded']}")
        bob.markdown('<div class="actor-card outcome-bad"><h4>👨 Bob</h4><p>Valid AES-GCM does not prove Alice sent it.</p></div>', unsafe_allow_html=True)
        bob.write(f"**Received:** {result['bob_received']}")
    else:
        left, right = st.columns(2)
        left.markdown('<div class="section-card"><b>Original message</b></div>', unsafe_allow_html=True)
        left.write(result["sent_message"])
        right.markdown('<div class="section-card"><b>Delivered message</b></div>', unsafe_allow_html=True)
        right.write(result["received_message"])

    st.subheader("Protocol event transcript")
    transcript_table(result)
    with st.expander("Inspect cryptographic evidence"):
        st.write("**Message SHA-256:**", result["message_sha256"])
        st.write("**Security conclusion:**", result["security_result"])
        ciphertext = result.get("ciphertext_hex", result.get("first_ciphertext_hex", ""))
        if ciphertext:
            st.code(str(ciphertext), language=None, wrap_lines=True)
        st.caption("Private keys and raw session keys are intentionally never displayed or stored.")
    download_report(result, report_key)


with st.sidebar:
    st.markdown("## 🛡️ ADH Security Lab")
    st.caption("Authenticated key exchange · MITM red-team simulation")
    st.divider()
    st.markdown("**Cryptographic stack**")
    st.code("X25519\nEd25519\nHKDF-SHA-256\nAES-256-GCM", language=None)
    st.markdown("**Security goals**")
    st.markdown("- Confidentiality\n- Integrity\n- Peer authentication\n- Forward-secrecy model")
    st.divider()
    st.caption("Academic simulation · BCS703 Cryptography and Network Security")

st.markdown(
    """
    <div class="hero">
      <div class="hero-kicker">CRYPTOGRAPHY & NETWORK SECURITY · ATTACK/DEFENSE LAB</div>
      <h1>Authenticated Diffie-Hellman MITM Simulator</h1>
      <p>Observe how an encrypted connection can still be compromised, inspect every protocol event,
      then stop the attack by binding trusted Ed25519 identities to fresh X25519 keys.</p>
      <span class="chip">X25519 KEY AGREEMENT</span><span class="chip">ACTIVE MITM ATTACK</span>
      <span class="chip">ED25519 AUTHENTICATION</span><span class="chip">AES-256-GCM</span>
    </div>
    """,
    unsafe_allow_html=True,
)
metric_cards()
st.write("")

command_tab, attack_tab, inspector_tab, audit_tab, learning_tab = st.tabs(
    ["⚡ Mission Control", "🎯 Attack & Defense Lab", "🔬 Protocol Inspector", "📋 Audit & Experiments", "🎓 Learn & Viva"]
)

with command_tab:
    st.subheader("One-click end-to-end demonstration")
    st.write("Run the presentation sequence: honest encryption, successful active attack, then authenticated prevention.")
    left, right = st.columns([1.2, 1])
    with left:
        demo_message = st.text_input("Original instruction", "Transfer ₹5,000 to Bob", key="command_message")
        demo_replacement = st.text_input("Mallory's replacement", "Transfer ₹50,000 to Mallory", key="command_replacement")
        if st.button("Run complete attack/defense mission", type="primary", width="stretch"):
            try:
                st.session_state["demo_results"] = service.run_complete_demo(demo_message, demo_replacement)
                st.session_state["last_result"] = st.session_state["demo_results"][-1]
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
    with right:
        st.markdown("""<div class="section-card"><b>Mission sequence</b><br><br>
        01 · Establish an unauthenticated encrypted channel<br>
        02 · Insert Mallory and expose the identity gap<br>
        03 · Sign ephemeral keys and reject substitution<br>
        04 · Save audit evidence and compare results</div>""", unsafe_allow_html=True)
    if st.session_state.get("demo_results"):
        titles = ("Phase 1 · Honest but unauthenticated", "Phase 2 · Mallory succeeds", "Phase 3 · Authentication blocks Mallory")
        st.divider()
        for index, (title, result) in enumerate(zip(titles, st.session_state["demo_results"]), start=1):
            with st.expander(title, expanded=index == 2):
                render_result(result, report_key=f"mission_{index}_{result['audit_id']}")

with attack_tab:
    st.subheader("Interactive red-team scenario")
    left, right = st.columns(2)
    lab_message = left.text_area("Alice's plaintext", "The launch code is DELTA-7", height=100, key="lab_message")
    lab_replacement = right.text_area("Mallory's modified plaintext", "The launch code is OMEGA-9", height=100, key="lab_replacement")
    mode = st.radio("Protocol mode", ["Normal Exchange", "MITM Attack", "Authenticated Defense"], horizontal=True, key="lab_mode")
    if st.button("Execute selected protocol", type="primary", key="execute_lab"):
        try:
            if mode == "Normal Exchange":
                result = service.run_normal(lab_message)
            elif mode == "MITM Attack":
                result = service.run_mitm(lab_message, lab_replacement)
            else:
                result = service.run_authenticated(lab_message)
            st.session_state["last_result"] = result
        except ValueError as exc:
            st.error(str(exc))
    if st.session_state.get("last_result"):
        result = st.session_state["last_result"]
        st.divider()
        render_result(result, report_key=f"lab_{result['audit_id']}")

with inspector_tab:
    st.subheader("Protocol inspector")
    result = st.session_state.get("last_result")
    if not result:
        st.info("Execute a protocol in Mission Control or the Attack & Defense Lab first.")
    else:
        metrics = st.columns(3)
        metrics[0].metric("Selected run", f"Audit #{result['audit_id']}")
        metrics[1].metric("Raw private keys shown", "NEVER")
        metrics[2].metric("Threat model", "ACTIVE NETWORK")
        transcript_table(result)
        st.markdown("#### Why each primitive is present")
        st.markdown("""
        | Primitive | Job | What fails without it |
        |---|---|---|
        | X25519 | Establish a shared secret | No efficient ephemeral key agreement |
        | HKDF-SHA-256 | Derive a context-specific AES key | Raw ECDH material is used unsafely |
        | AES-256-GCM | Encrypt and authenticate each message | Content can be read or altered |
        | Ed25519 | Prove who owns an ephemeral X25519 key | Public-key substitution enables MITM |
        """)
        st.warning("AES-GCM does not fail during MITM: Mallory legitimately knows both fraudulent channel keys. Authentication must occur first.")

with audit_tab:
    st.subheader("Persistent audit trail and performance evidence")
    left, right = st.columns([2, 1])
    scenario_filter = left.selectbox("Filter scenario", ["All", "Normal Exchange", "MITM Attack", "Authenticated Defense"])
    history_limit = right.number_input("Maximum records", 10, 500, 100, 10)
    history = service.database.get_history(scenario=scenario_filter, limit=int(history_limit))
    if history:
        display_rows = [{"ID": row["id"], "Time (UTC)": row["created_at"], "Scenario": row["scenario"], "Outcome": row["outcome"], "Duration (ms)": row["duration_ms"], "Message digest": row["message_sha256"][:16] + "…"} for row in history]
        st.dataframe(display_rows, width="stretch", hide_index=True)
        st.download_button("Export audit history as CSV", history_to_csv(history), file_name=f"protocol-audit-{datetime.now():%Y%m%d-%H%M%S}.csv", mime="text/csv")
    else:
        st.info("No audit records match the current filter.")
    st.divider()
    st.markdown("#### Controlled performance experiment")
    left, right = st.columns([1, 2])
    rounds = left.slider("Trials per scenario", 5, 200, 30, 5)
    if left.button("Run benchmark", key="benchmark_button"):
        with st.spinner("Executing cryptographic trials..."):
            st.session_state["benchmark"] = benchmark_protocols(rounds)
    right.caption("Signatures add a small measurable cost in exchange for protection against identity substitution.")
    if st.session_state.get("benchmark"):
        benchmark = st.session_state["benchmark"]
        st.dataframe(benchmark, width="stretch", hide_index=True)
        st.bar_chart({str(row["Scenario"]): float(row["Average time (ms)"]) for row in benchmark}, horizontal=True)

with learning_tab:
    st.subheader("Understand the project before presenting it")
    left, right = st.columns(2)
    left.markdown("""<div class="section-card outcome-warn"><b>What Diffie-Hellman solves</b><br><br>
    Alice and Bob calculate the same secret without transmitting it. X25519 is the modern elliptic-curve version.</div>""", unsafe_allow_html=True)
    right.markdown("""<div class="section-card outcome-bad"><b>What plain Diffie-Hellman does not solve</b><br><br>
    It does not prove that a received public key belongs to the intended person. That identity gap is where Mallory enters.</div>""", unsafe_allow_html=True)
    with st.expander("The complete story in six sentences", expanded=True):
        st.markdown("""
        1. Alice and Bob generate temporary X25519 key pairs.
        2. Without authentication, Mallory replaces both transmitted public keys.
        3. Mallory now shares one valid key with Alice and another valid key with Bob.
        4. Mallory decrypts, changes and re-encrypts traffic without breaking AES.
        5. Ed25519 signatures bind trusted identities to the exact temporary keys and session.
        6. A substituted key changes the signed data, so verification fails before encryption begins.
        """)
    with st.expander("High-value viva questions"):
        st.markdown("""
        **Why is AES-GCM not enough?**

        AES protects whichever key was established. During MITM, Mallory owns both keys.

        **Why use HKDF?**

        Raw X25519 output is key material, not a protocol-separated AES key. HKDF safely derives one.

        **X25519 versus Ed25519?**

        X25519 performs key agreement; Ed25519 authenticates the public key through signatures.

        **Main limitation?**

        The simulator assumes Alice and Bob already trust each other's Ed25519 identity public keys.
        """)
    st.markdown("#### Assignment evaluation evidence")
    st.markdown("""
    | Rubric area | Demonstrable evidence |
    |---|---|
    | Problem and objectives | Identity gap in unauthenticated ECDH is explicitly defined |
    | Cryptographic concept | Four correctly separated modern primitives |
    | Design and methodology | Three scenarios, active attacker model and event transcript |
    | Implementation | Dashboard, service layer, SQLite audit and exports |
    | Security analysis | Attack success, blocked substitution and timing comparison |
    | Documentation | Architecture, report draft, tests and viva guide |
    | Presentation | One-click mission plus interactive red-team lab |
    """)

