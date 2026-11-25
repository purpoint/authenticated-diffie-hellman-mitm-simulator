# Authenticated Diffie-Hellman MITM Simulator

An educational cryptography and network-security mini project that demonstrates:

1. a normal but unauthenticated Diffie-Hellman key exchange;
2. a successful man-in-the-middle (MITM) attack; and
3. prevention of that attack by authenticating ephemeral keys with digital signatures.

The implementation uses modern, real cryptographic primitives:

- **X25519** for elliptic-curve Diffie-Hellman key exchange;
- **Ed25519** for identity signatures;
- **HKDF-SHA-256** for session-key derivation; and
- **AES-256-GCM** for authenticated message encryption.

## Project highlights

- **Clean academic interface** organized around the problem, experiment and conclusion.
- **Instant light/dark theme switch** with matching contrast for cards, forms and results.
- **One-click three-case comparison** presenting the complete story in the correct viva order.
- **Interactive demonstration** for changing Alice's and Mallory's messages.
- **Detailed protocol transcript** showing every actor, operation, security state and outcome.
- **Persistent SQLite audit history** with scenario filters and CSV export.
- **Privacy-conscious auditing:** only SHA-256 message digests are stored, never message plaintext.
- **Downloadable evidence reports** containing algorithms, timings, conclusions and transcripts.
- **Controlled benchmark lab** comparing normal, attacked and authenticated protocol costs.
- **Command-line interface** plus an automated eight-step demonstration walkthrough.
- **22 automated tests** covering cryptography, attack behavior, persistence, reports and UI flows.

## Beginner explanation

Alice and Bob want the same secret encryption key without sending the key itself.
Diffie-Hellman makes that possible. However, basic Diffie-Hellman does not tell Alice
whether a received public key really belongs to Bob. Mallory can replace the public
keys and secretly create one encrypted connection with Alice and another with Bob.

The protected version makes Alice and Bob sign their temporary X25519 public keys.
A changed public key no longer matches its signature, so the MITM substitution is
detected before any sensitive message is sent.

## Application screens

The Streamlit application contains four sections:

- **Learn:** the concepts in simple language;
- **Live demonstration:** all three protocol scenarios;
- **Experiments:** repeated performance measurements and a chart; and
- **Assignment mapping:** direct evidence for each evaluation criterion.

## Run locally

Python 3.10 or newer is recommended.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run app.py
```

Streamlit will display a local URL, normally `http://localhost:8501`.

## Command-line and automated demonstration

Run the complete guided demonstration:

```bash
python main.py --demo
```

Run individual scenarios:

```bash
python main.py --scenario normal --message "Confidential message"
python main.py --scenario mitm --message "Pay Bob" --replacement "Pay Mallory"
python main.py --scenario protected --message "Authenticated message"
```

Inspect the persistent audit history or run a benchmark:

```bash
python main.py --history
python main.py --benchmark 50
```

## Run tests

```bash
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
pytest -q
```

## Recommended classroom demonstration

1. Enter a message in the **Live demonstration** tab.
2. Run the normal scenario and point out the matching session-key fingerprints.
3. Run the MITM scenario and show that Mallory reads and modifies the message.
4. Run the authenticated scenario and show that the substituted key is rejected.
5. Run 20 experiment rounds and capture the table and chart for the report.

Do not display real private keys. The application intentionally shows only short
SHA-256 fingerprints for comparison.

## Project structure

```text
.
├── app.py                         # Professional Streamlit security dashboard
├── main.py                        # CLI entry point
├── demo_walkthrough.py            # Automated eight-step presentation
├── audit_database.py              # SQLite audit persistence
├── simulation_service.py          # Timing, orchestration and safe audit recording
├── report_generator.py            # TXT evidence and CSV audit exports
├── crypto_simulator/
│   ├── __init__.py
│   └── protocol.py                # Cryptographic protocol and simulations
├── data/                           # Runtime SQLite database (ignored by Git)
├── reports/                        # Runtime report exports (ignored by Git)
├── docs/
│   ├── ARCHITECTURE.md
│   ├── PROJECT_REPORT.md
│   └── VIVA_GUIDE.md
├── tests/
│   ├── test_protocol.py
│   ├── test_simulation_service.py
│   ├── test_audit_database.py
│   ├── test_report_generator.py
│   └── test_app.py
├── requirements.txt
└── requirements-dev.txt
```

## Security scope

This is a controlled educational simulation. Identity and session keys exist only in memory and
are regenerated for each run. A production system additionally needs certificates or
a trusted key directory, secure persistent key storage, replay protection across
sessions, protocol version negotiation, audit logging, and independent security review.

The SQLite audit database does not store submitted plaintext. It stores only a SHA-256
digest, scenario, timing, outcome and non-secret metadata. Raw private keys and session
keys are never rendered in the interface, written to logs or persisted.

## Technical references

- RFC 7748: Elliptic Curves for Security (X25519)
- RFC 8032: Edwards-Curve Digital Signature Algorithm (Ed25519)
- RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- NIST SP 800-38D: Galois/Counter Mode (GCM)
- `cryptography` Python library documentation

