# System Architecture and Methodology

## 1. Participants

- **Alice:** initiates a confidential message.
- **Bob:** intended recipient.
- **Mallory:** active network attacker who can intercept and replace traffic.

## 2. Cryptographic components

| Component | Purpose |
|---|---|
| X25519 | Produces a shared secret from a private key and the peer's public key |
| Ed25519 | Authenticates ownership of each temporary X25519 public key |
| HKDF-SHA-256 | Derives a uniformly distributed 256-bit AES session key |
| AES-GCM | Encrypts the message and detects unauthorized ciphertext modification |
| SHA-256 fingerprint | Displays a safe identifier for comparison without revealing a key |

The implementation relies on the audited primitives exposed by Python's
`cryptography` library. It does not implement cryptographic mathematics manually.

## 3. Scenario A: normal unauthenticated exchange

```text
Alice                                           Bob
  |-- Alice's temporary X25519 public key ------->|
  |<---------- Bob's temporary X25519 public key--|
  |                                               |
  |  Both derive the same key using X25519+HKDF   |
  |-- AES-GCM ciphertext ------------------------>|
```

This protects against a passive observer. It does not authenticate the public keys.

## 4. Scenario B: successful MITM attack

```text
Alice                   Mallory                    Bob
  |-- Alice public key --->|                        |
  |<-- Mallory key A ------|                        |
  |                        |-- Mallory key B ------>|
  |                        |<------ Bob public key--|
  |                        |                        |
  | key shared with M      | key shared with A     |
  |                        | key shared with B      | Bob shares with M
  |-- encrypted message -->|                        |
  |                        | decrypts and modifies  |
  |                        |-- new ciphertext ----->|
```

Alice and Bob both see valid encryption, but neither has verified the identity behind
the received public key.

## 5. Scenario C: authenticated defense

Before the exchange, Alice and Bob trust each other's Ed25519 identity public keys.
Each signs a payload containing:

- the protocol/version context;
- sender and intended receiver names;
- a fresh session salt; and
- the exact temporary X25519 public key.

```text
Alice                  Untrusted network                Bob
  |-- X25519 public key + Ed25519 signature ------------->|
  |<------------- X25519 public key + Ed25519 signature --|
  |                                                       |
  | verify signature                         verify signature
  | derive X25519 + HKDF session key                      |
  |-- AES-GCM ciphertext -------------------------------->|
```

If Mallory changes the X25519 public key, the signed payload changes and Ed25519
verification fails. The application stops the attack before key derivation.

## 6. Methodology

1. Generate fresh temporary X25519 keys for each scenario.
2. Demonstrate successful key agreement without interference.
3. Give Mallory two key pairs and replace both transmitted public keys.
4. Prove that Mallory derives a different shared key with each victim.
5. Use Ed25519 signatures to bind identity and session context to each temporary key.
6. Attempt the same substitution and record the signature-verification failure.
7. Compare execution times across all scenarios over repeated trials.

## 7. Threat model and limitations

Mallory can read, delay, modify and replace network messages but cannot steal Alice's
or Bob's Ed25519 private identity key or break the underlying algorithms. Denial of
service is not prevented: an attacker can still drop messages. The simulator uses
in-memory identity keys and models prior trust; it does not implement a certificate
authority or persistent key store.

