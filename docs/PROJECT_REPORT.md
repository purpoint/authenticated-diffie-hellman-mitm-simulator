# Mini Project Report Draft

## Title

**Authenticated Diffie-Hellman Key Exchange with Man-in-the-Middle Attack Simulation and Prevention**

## Abstract

Diffie-Hellman key exchange allows two parties to establish a shared secret across an
untrusted network, but an unauthenticated exchange is vulnerable to a man-in-the-middle
attack. This project implements a controlled Alice-Mallory-Bob simulation using X25519.
It first demonstrates honest key establishment, then shows Mallory replacing public
keys, decrypting Alice's message, modifying it and re-encrypting it for Bob. The defense
authenticates temporary X25519 public keys with Ed25519 digital signatures. HKDF-SHA-256
derives 256-bit session keys and AES-GCM protects message confidentiality and integrity.
Repeated timing experiments compare the operational cost of the three scenarios. The
result demonstrates that encryption without peer authentication is insufficient and
that signed ephemeral keys prevent public-key substitution with modest overhead.

## 1. Problem statement

An unauthenticated Diffie-Hellman exchange establishes a key but does not prove the
identity of the peer. An active attacker can intercept the public values and create two
independent secure channels, allowing confidential messages to be read or modified.

## 2. Objectives

1. Implement modern Diffie-Hellman key exchange using X25519.
2. Demonstrate successful confidential communication using HKDF and AES-GCM.
3. Simulate an active MITM public-key-substitution attack.
4. Authenticate ephemeral keys using Ed25519 signatures and block the attack.
5. Compare correctness, security properties and execution time.

## 3. Literature and algorithm background

### 3.1 X25519

X25519 is an elliptic-curve Diffie-Hellman function standardized in RFC 7748. Each
participant combines their private key with the peer's public key. In an honest exchange,
both participants obtain the same shared secret without transmitting that secret.

### 3.2 Ed25519

Ed25519 is a digital-signature scheme standardized in RFC 8032. The signer uses a private
identity key; a verifier uses the corresponding public key to detect any change to the
signed data and verify its origin.

### 3.3 HKDF-SHA-256

The raw X25519 shared secret is passed to the RFC 5869 HKDF construction. A fresh salt
and protocol-specific information produce a separate, fixed-length AES key.

### 3.4 AES-GCM

AES-GCM is an authenticated-encryption mode specified by NIST SP 800-38D. It provides
confidentiality and detects changes to the ciphertext and associated context. A fresh
96-bit nonce is generated for each encryption.

## 4. System design

Insert the three diagrams and threat model from `docs/ARCHITECTURE.md` here. Include a
screen capture of each application scenario.

## 5. Implementation

The project is implemented in Python. The `cryptography` package supplies X25519,
Ed25519, HKDF-SHA-256 and AES-GCM. `crypto_simulator/protocol.py` contains independent
functions for normal exchange, MITM attack and authenticated exchange. A service layer
coordinates timing and audit persistence. The Streamlit dashboard provides mission
control, an interactive attack lab, protocol inspection, persistent history, CSV/TXT
exports, benchmarks and integrated viva preparation. A separate CLI and automated
walkthrough allow headless demonstrations.

Private keys remain in memory. The interface displays only short SHA-256 fingerprints,
not the actual shared secrets or AES keys. SQLite audit rows store message hashes instead
of plaintext. The automated suite contains 22 cryptographic, integration, persistence,
reporting and user-interface tests.

## 6. Experimental procedure

1. Run the application and enter a test message.
2. Execute the normal exchange and record whether key fingerprints match.
3. Execute the MITM scenario and record Alice's message, Mallory's plaintext and Bob's
   received plaintext.
4. Execute the authenticated scenario and record whether substitution was rejected.
5. Run 20 or more timing trials in the Experiments tab.
6. Repeat on the same computer to keep performance comparison fair.

## 7. Results

Complete this table using the live application:

| Scenario | Message delivered correctly? | Mallory reads plaintext? | Substitution detected? | Average time (ms) |
|---|---:|---:|---:|---:|
| Normal unauthenticated exchange | Yes | Not attempted | No | ___ |
| MITM attack | Message modified | Yes | No | ___ |
| Authenticated defense | Yes | No | Yes | ___ |

Add the experiment chart and screenshots below the table. Do not invent timing results;
record values produced on the demonstration computer.

## 8. Security analysis and discussion

- Plain X25519 provides secrecy against passive observation but not peer authentication.
- AES-GCM protects a channel only after the correct parties establish its key. During the
  MITM attack, Mallory legitimately holds both channel keys, so AES-GCM alone cannot help.
- Signing the complete session-bound ephemeral-key payload detects substitution.
- Including sender, receiver and salt in the signature limits identity/context confusion
  and simple replay between sessions.
- Authentication adds computation, visible in the timing experiment, but prevents the
  confidentiality and integrity failure demonstrated in the attack scenario.
- Compromised identity private keys, unsafe trust distribution and denial of service are
  outside the simulator's protection and remain important production risks.

## 9. Conclusion

The project shows that successful encryption is not proof of peer identity. An
unauthenticated Diffie-Hellman exchange permits an active attacker to establish separate
keys with both victims. Ed25519 signatures bind trusted identities to fresh X25519 public
keys, causing substituted keys to fail verification. X25519, HKDF-SHA-256, AES-GCM and
Ed25519 together provide a clear implementation of confidential, integrity-protected and
authenticated communication within the stated threat model.

## 10. References

1. A. Langley, M. Hamburg and S. Turner, “Elliptic Curves for Security,” RFC 7748, 2016.
2. S. Josefsson and I. Liusvaara, “Edwards-Curve Digital Signature Algorithm (EdDSA),”
   RFC 8032, 2017.
3. H. Krawczyk and P. Eronen, “HMAC-based Extract-and-Expand Key Derivation Function,”
   RFC 5869, 2010.
4. M. Dworkin, “Recommendation for Block Cipher Modes of Operation: GCM and GMAC,”
   NIST Special Publication 800-38D, 2007.
5. Python Cryptographic Authority, `cryptography` documentation.

