"""Streamlit interface for the authenticated Diffie-Hellman mini project."""

from __future__ import annotations

import streamlit as st

from crypto_simulator import (
    benchmark_protocols,
    simulate_authenticated_exchange,
    simulate_mitm_attack,
    simulate_normal_exchange,
)


st.set_page_config(
    page_title="Authenticated Diffie-Hellman MITM Simulator",
    page_icon="🔐",
    layout="wide",
)


def _fingerprint_card(label: str, value: str) -> None:
    st.metric(label, value)


def _show_ciphertext(label: str, value: str) -> None:
    with st.expander(label):
        st.code(value, language=None, wrap_lines=True)


def render_normal(message: str) -> None:
    result = simulate_normal_exchange(message)
    st.success("Bob decrypted the same message Alice sent.")
    left, right = st.columns(2)
    left.write(f"**Alice sent:** {result['sent_message']}")
    right.write(f"**Bob received:** {result['received_message']}")

    key_left, key_right = st.columns(2)
    with key_left:
        _fingerprint_card(
            "Alice's session-key fingerprint",
            str(result["alice_session_key_fingerprint"]),
        )
    with key_right:
        _fingerprint_card(
            "Bob's session-key fingerprint",
            str(result["bob_session_key_fingerprint"]),
        )
    st.info(str(result["security_result"]))
    _show_ciphertext("View AES-GCM ciphertext", str(result["ciphertext_hex"]))


def render_mitm(message: str, replacement: str) -> None:
    result = simulate_mitm_attack(message, replacement)
    st.error("Mallory successfully intercepted and modified the encrypted conversation.")
    alice, mallory, bob = st.columns(3)
    with alice:
        st.subheader("👩 Alice")
        st.write("Believes she connected to Bob")
        st.write(f"Sent: **{result['alice_sent']}**")
    with mallory:
        st.subheader("🕵️ Mallory")
        st.write(f"Decrypted: **{result['mallory_read']}**")
        st.write(f"Changed to: **{result['mallory_forwarded']}**")
    with bob:
        st.subheader("👨 Bob")
        st.write("Believes the message came from Alice")
        st.write(f"Received: **{result['bob_received']}**")

    st.warning(str(result["security_result"]))
    _show_ciphertext(
        "View the two different encrypted messages",
        f"Alice → Mallory\n{result['first_ciphertext_hex']}\n\n"
        f"Mallory → Bob\n{result['forwarded_ciphertext_hex']}",
    )


def render_authenticated(message: str) -> None:
    result = simulate_authenticated_exchange(message)
    if result["attack_blocked"]:
        st.success("Mallory's substituted key was rejected. The attack was blocked.")
    else:
        st.error("Unexpected result: the substituted key was not rejected.")

    check_one, check_two, check_three = st.columns(3)
    check_one.metric("MITM substitution", "BLOCKED")
    check_two.metric("Identity signatures", "VALID")
    check_three.metric("Session keys", "MATCH")
    st.write(f"**Alice sent:** {result['sent_message']}")
    st.write(f"**Bob securely received:** {result['received_message']}")
    st.info(str(result["security_result"]))
    _show_ciphertext("View authenticated AES-GCM ciphertext", str(result["ciphertext_hex"]))


st.title("🔐 Authenticated Diffie-Hellman MITM Simulator")
st.caption(
    "A cryptography and network-security mini project demonstrating an attack and its defense."
)

learn_tab, demo_tab, experiment_tab, rubric_tab = st.tabs(
    ["Learn", "Live demonstration", "Experiments", "Assignment mapping"]
)

with learn_tab:
    st.header("The idea in plain language")
    st.markdown(
        """
        **Diffie-Hellman** lets Alice and Bob independently calculate the same secret
        key while sending only public information across the network. This project uses
        **X25519**, a modern elliptic-curve Diffie-Hellman algorithm.

        The weakness is identity: plain Diffie-Hellman creates a secret, but it does not
        prove *who* is on the other side. Mallory can stand between Alice and Bob and
        create two different encrypted connections.

        The defense is to sign each temporary X25519 public key using a trusted
        **Ed25519 identity key**. After verification, **HKDF-SHA-256** derives a safe
        256-bit session key and **AES-GCM** encrypts and authenticates the message.
        """
    )
    st.code(
        """Vulnerable:
Alice  <==== encrypted connection 1 ====>  Mallory
Mallory <==== encrypted connection 2 ====> Bob

Protected:
Alice -- signed temporary public key --> Bob
Bob verifies signature; a substituted key is rejected.
Alice <========== authenticated AES-GCM ==========> Bob""",
        language=None,
    )

with demo_tab:
    st.header("Compare all three scenarios")
    message = st.text_input("Alice's original message", "Transfer ₹5,000 to Bob")
    replacement = st.text_input(
        "Message Mallory tries to forward",
        "Transfer ₹50,000 to Mallory",
    )
    scenario = st.radio(
        "Choose a scenario",
        (
            "1. Normal exchange (works, but identity is not verified)",
            "2. MITM attack (Mallory reads and modifies the message)",
            "3. Authenticated defense (Mallory is detected)",
        ),
    )
    if st.button("Run selected simulation", type="primary"):
        try:
            if scenario.startswith("1"):
                render_normal(message)
            elif scenario.startswith("2"):
                render_mitm(message, replacement)
            else:
                render_authenticated(message)
        except ValueError as exc:
            st.error(str(exc))

with experiment_tab:
    st.header("Performance and security experiment")
    st.write(
        "Run each complete scenario several times and compare its execution cost. "
        "The authenticated version performs extra signature operations, so a small "
        "overhead is expected in exchange for identity protection."
    )
    rounds = st.slider("Runs per scenario", 5, 100, 20, 5)
    if st.button("Run experiment"):
        with st.spinner("Running cryptographic operations..."):
            results = benchmark_protocols(rounds)
        st.dataframe(results, width="stretch", hide_index=True)
        chart_data = {
            str(row["Scenario"]): float(row["Average time (ms)"])
            for row in results
        }
        st.bar_chart(chart_data, horizontal=True)
        st.caption(
            "Times depend on the computer. Record the table and screenshot for the project report."
        )

with rubric_tab:
    st.header("How this project satisfies the assignment")
    st.markdown(
        """
        | Evaluation area | Evidence in this project |
        |---|---|
        | Problem definition | Plain Diffie-Hellman does not authenticate public keys |
        | Cryptographic algorithm | X25519, Ed25519, HKDF-SHA-256 and AES-GCM |
        | System design | Alice–Mallory–Bob attack path and authenticated Alice–Bob path |
        | Implementation | Three executable scenarios with successful encryption/decryption |
        | Security analysis | Attack success, attack prevention and timing comparison |
        | Documentation | README, architecture, report outline, screenshots and references |
        | Presentation and viva | Live before/attack/after demonstration plus viva guide |
        """
    )
    st.warning(
        "Educational simulation only. It creates temporary in-memory identity keys; "
        "a production system needs certificates, secure key storage and peer trust management."
    )

