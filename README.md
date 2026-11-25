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
├── app.py                         # Streamlit user interface
├── crypto_simulator/
│   ├── __init__.py
│   └── protocol.py                # Cryptographic protocol and simulations
├── docs/
│   ├── ARCHITECTURE.md
│   ├── PROJECT_REPORT.md
│   └── VIVA_GUIDE.md
├── tests/
│   └── test_protocol.py
├── requirements.txt
└── requirements-dev.txt
```

## Security scope

This is a controlled educational simulation. Identity keys exist only in memory and
are regenerated for each run. A production system additionally needs certificates or
a trusted key directory, secure persistent key storage, replay protection across
sessions, protocol version negotiation, audit logging, and independent security review.

## Technical references

- RFC 7748: Elliptic Curves for Security (X25519)
- RFC 8032: Edwards-Curve Digital Signature Algorithm (Ed25519)
- RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- NIST SP 800-38D: Galois/Counter Mode (GCM)
- `cryptography` Python library documentation

