# Viva and Demonstration Guide

## One-minute project explanation

“My project demonstrates that Diffie-Hellman encryption is vulnerable when public keys
are not authenticated. Alice and Bob can normally derive the same key using X25519. In
the attack simulation, Mallory replaces their public keys, creates two separate encrypted
connections, reads Alice's message and changes it before Bob receives it. The defense
signs each temporary X25519 key using an Ed25519 identity key. A substituted key fails
signature verification. After authentication, HKDF derives an AES-256 key and AES-GCM
encrypts the message and verifies its integrity.”

## Suggested live-demo order

1. Explain Alice, Bob and Mallory.
2. Run **Normal exchange** and show matching key fingerprints.
3. Say: “These keys match, but Alice still has no proof that the key belongs to Bob.”
4. Run **MITM attack** and show the original, intercepted, modified and received texts.
5. Run **Authenticated defense** and show `BLOCKED`, `VALID` and `MATCH`.
6. Open **Experiments**, run 20 trials and discuss the security/performance trade-off.

## Likely questions and answers

### What is Diffie-Hellman?

A key-agreement method that allows two participants to calculate the same shared secret
using their private key and the other participant's public key. The secret is never sent.

### What is X25519?

A modern elliptic-curve Diffie-Hellman function. It is used here instead of implementing
the older modular-arithmetic form manually.

### Why does the MITM attack succeed even though AES-GCM is secure?

Mallory does not break AES. Mallory tricks each victim into creating a valid encrypted
channel with Mallory. Therefore, Mallory legitimately knows both session keys.

### How do digital signatures stop the attack?

The signature covers the exact temporary public key and session context. Mallory can
replace the key, but cannot create a matching signature without the victim's Ed25519
private identity key.

### What is the difference between X25519 and Ed25519?

X25519 performs key agreement. Ed25519 creates and verifies digital signatures. They
have related curve families but serve different purposes and use separate keys.

### Why is HKDF required?

The raw shared secret should not be used directly as an AES key. HKDF extracts and
expands it into a fixed-length, protocol-specific cryptographic key.

### What security does AES-GCM provide?

Confidentiality plus integrity/authenticity of the encrypted data. Decryption fails if
the ciphertext or associated data changes without the correct key.

### What is a nonce?

A value that must be unique for each AES-GCM encryption under a given key. This project
generates a fresh random 96-bit nonce for every encrypted message.

### Are the fingerprints the real keys?

No. A fingerprint is a short SHA-256-based identifier used to compare keys safely. The
application deliberately does not print private or session keys.

### What are the project's limitations?

It is an educational simulator. Identity keys are generated in memory, and prior trust
is assumed. Production systems need certificates or another trust mechanism, secure key
storage, replay/state management, error handling and formal security review.

### Why not create the cryptographic algorithms manually?

Real cryptographic implementation is error-prone. The project demonstrates correct
protocol use with established primitives from the maintained `cryptography` library.

### Which assignment outcomes does this satisfy?

It implements public-key cryptography and key exchange, builds a working secure protocol,
simulates an attack and defense, analyzes security and performance, and uses a real Python
cryptographic library.

