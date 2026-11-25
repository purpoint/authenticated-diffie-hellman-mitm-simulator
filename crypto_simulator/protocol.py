"""Core protocol simulations used by the Streamlit application.

The module intentionally keeps the three scenarios separate:

1. Plain X25519 key exchange succeeds when nobody interferes.
2. An active attacker can replace unauthenticated public keys.
3. Ed25519 signatures authenticate the ephemeral X25519 keys and block that attack.

X25519 is a modern elliptic-curve form of Diffie-Hellman. AES-GCM provides
authenticated encryption after HKDF turns the shared secret into an AES key.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from statistics import mean
from time import perf_counter_ns

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


PROTOCOL_INFO = b"CNS-ADH-MITM-SIMULATOR-v1"
SIGNATURE_CONTEXT = b"CNS-ADH-SIGNED-EPHEMERAL-v1"


@dataclass(frozen=True)
class EphemeralKeyPair:
    """One temporary X25519 private/public key pair."""

    private: X25519PrivateKey
    public_bytes: bytes


def _new_ephemeral_key_pair() -> EphemeralKeyPair:
    private = X25519PrivateKey.generate()
    public_bytes = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return EphemeralKeyPair(private=private, public_bytes=public_bytes)


def _public_key(raw_public_key: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(raw_public_key)


def _derive_session_key(
    private_key: X25519PrivateKey,
    peer_public_key: bytes,
    salt: bytes,
) -> bytes:
    shared_secret = private_key.exchange(_public_key(peer_public_key))
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=PROTOCOL_INFO,
    ).derive(shared_secret)


def _encrypt(key: bytes, plaintext: str, associated_data: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), associated_data)
    return nonce, ciphertext


def _decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes,
) -> str:
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    return plaintext.decode("utf-8")


def _fingerprint(value: bytes) -> str:
    """Return a safe short identifier instead of displaying secret key material."""

    digest = hashlib.sha256(value).hexdigest()
    return ":".join(digest[index : index + 2] for index in range(0, 16, 2))


def _signature_payload(sender: str, receiver: str, salt: bytes, public_key: bytes) -> bytes:
    return b"|".join(
        (
            SIGNATURE_CONTEXT,
            sender.encode("utf-8"),
            receiver.encode("utf-8"),
            salt,
            public_key,
        )
    )


def _require_message(message: str) -> str:
    cleaned = message.strip()
    if not cleaned:
        raise ValueError("Message cannot be empty.")
    return cleaned


def _event(
    step: int,
    actor: str,
    operation: str,
    detail: str,
    state: str = "INFO",
) -> dict[str, object]:
    """Create one display-safe protocol transcript entry."""

    return {
        "Step": step,
        "Actor": actor,
        "Operation": operation,
        "Detail": detail,
        "State": state,
    }


def simulate_normal_exchange(message: str) -> dict[str, object]:
    """Run an honest but unauthenticated X25519 + AES-GCM exchange."""

    message = _require_message(message)
    alice = _new_ephemeral_key_pair()
    bob = _new_ephemeral_key_pair()
    salt = os.urandom(16)

    alice_key = _derive_session_key(alice.private, bob.public_bytes, salt)
    bob_key = _derive_session_key(bob.private, alice.public_bytes, salt)

    associated_data = b"Alice->Bob|normal-demo"
    nonce, ciphertext = _encrypt(alice_key, message, associated_data)
    received_message = _decrypt(bob_key, nonce, ciphertext, associated_data)

    return {
        "scenario": "Normal unauthenticated exchange",
        "sent_message": message,
        "received_message": received_message,
        "alice_public_fingerprint": _fingerprint(alice.public_bytes),
        "bob_public_fingerprint": _fingerprint(bob.public_bytes),
        "alice_session_key_fingerprint": _fingerprint(alice_key),
        "bob_session_key_fingerprint": _fingerprint(bob_key),
        "keys_match": alice_key == bob_key,
        "ciphertext_hex": ciphertext.hex(),
        "security_result": (
            "Confidential against passive observers, but vulnerable to active public-key substitution."
        ),
        "transcript": [
            _event(1, "Alice", "Generate X25519 key pair", "Creates a fresh private/public key pair."),
            _event(2, "Bob", "Generate X25519 key pair", "Creates a fresh private/public key pair."),
            _event(3, "Network", "Exchange public keys", "Public keys travel without identity proof.", "WARNING"),
            _event(4, "Alice + Bob", "X25519 + HKDF-SHA-256", "Both independently derive the same 256-bit session key."),
            _event(5, "Alice", "AES-256-GCM encryption", "Encrypts the plaintext with a fresh 96-bit nonce."),
            _event(6, "Bob", "AES-256-GCM decryption", "Authentication succeeds and the original message is recovered.", "SUCCESS"),
        ],
    }


def simulate_mitm_attack(message: str, replacement_message: str | None = None) -> dict[str, object]:
    """Show Mallory reading and changing traffic during unauthenticated exchange."""

    message = _require_message(message)
    replacement_message = (
        _require_message(replacement_message)
        if replacement_message is not None
        else f"[Modified by Mallory] {message}"
    )

    alice = _new_ephemeral_key_pair()
    bob = _new_ephemeral_key_pair()
    mallory_for_alice = _new_ephemeral_key_pair()
    mallory_for_bob = _new_ephemeral_key_pair()
    salt = os.urandom(16)

    # Mallory replaces Bob's public key before it reaches Alice.
    alice_to_mallory_key = _derive_session_key(
        alice.private, mallory_for_alice.public_bytes, salt
    )
    mallory_from_alice_key = _derive_session_key(
        mallory_for_alice.private, alice.public_bytes, salt
    )

    # Mallory separately replaces Alice's public key before it reaches Bob.
    bob_to_mallory_key = _derive_session_key(
        bob.private, mallory_for_bob.public_bytes, salt
    )
    mallory_to_bob_key = _derive_session_key(
        mallory_for_bob.private, bob.public_bytes, salt
    )

    alice_channel = b"Alice->Mallory|mitm-demo"
    alice_nonce, alice_ciphertext = _encrypt(
        alice_to_mallory_key, message, alice_channel
    )
    intercepted_message = _decrypt(
        mallory_from_alice_key,
        alice_nonce,
        alice_ciphertext,
        alice_channel,
    )

    bob_channel = b"Mallory->Bob|mitm-demo"
    bob_nonce, bob_ciphertext = _encrypt(
        mallory_to_bob_key, replacement_message, bob_channel
    )
    bob_received_message = _decrypt(
        bob_to_mallory_key,
        bob_nonce,
        bob_ciphertext,
        bob_channel,
    )

    return {
        "scenario": "Successful man-in-the-middle attack",
        "alice_sent": message,
        "mallory_read": intercepted_message,
        "mallory_forwarded": replacement_message,
        "bob_received": bob_received_message,
        "alice_mallory_keys_match": alice_to_mallory_key == mallory_from_alice_key,
        "mallory_bob_keys_match": mallory_to_bob_key == bob_to_mallory_key,
        "alice_bob_have_direct_key": False,
        "alice_channel_key_fingerprint": _fingerprint(alice_to_mallory_key),
        "bob_channel_key_fingerprint": _fingerprint(bob_to_mallory_key),
        "first_ciphertext_hex": alice_ciphertext.hex(),
        "forwarded_ciphertext_hex": bob_ciphertext.hex(),
        "security_result": (
            "Attack successful: encryption alone did not prove who owned the exchanged public keys."
        ),
        "transcript": [
            _event(1, "Alice + Bob", "Generate X25519 key pairs", "Both create fresh ephemeral keys."),
            _event(2, "Mallory", "Intercept public keys", "Mallory prevents the genuine public keys from reaching their destination.", "DANGER"),
            _event(3, "Mallory", "Substitute two public keys", "Alice receives Mallory key A; Bob receives Mallory key B.", "DANGER"),
            _event(4, "Alice + Mallory", "Derive channel key A", "Alice unknowingly shares a valid AES key with Mallory.", "DANGER"),
            _event(5, "Mallory + Bob", "Derive channel key B", "Bob unknowingly shares a different AES key with Mallory.", "DANGER"),
            _event(6, "Mallory", "Decrypt Alice's ciphertext", f"Plaintext exposed: {intercepted_message!r}.", "DANGER"),
            _event(7, "Mallory", "Modify and re-encrypt", f"Replacement plaintext: {replacement_message!r}.", "DANGER"),
            _event(8, "Bob", "Accept forged message", "AES-GCM is valid because Mallory knows channel key B.", "DANGER"),
        ],
    }


def simulate_authenticated_exchange(
    message: str,
    attempted_replacement: str | None = None,
) -> dict[str, object]:
    """Authenticate ephemeral keys with Ed25519, block substitution, then communicate."""

    message = _require_message(message)
    attempted_replacement = (
        _require_message(attempted_replacement)
        if attempted_replacement is not None
        else "No replacement message supplied"
    )
    alice_identity = Ed25519PrivateKey.generate()
    bob_identity = Ed25519PrivateKey.generate()
    alice_ephemeral = _new_ephemeral_key_pair()
    bob_ephemeral = _new_ephemeral_key_pair()
    mallory_ephemeral = _new_ephemeral_key_pair()
    salt = os.urandom(16)

    alice_payload = _signature_payload(
        "Alice", "Bob", salt, alice_ephemeral.public_bytes
    )
    bob_payload = _signature_payload("Bob", "Alice", salt, bob_ephemeral.public_bytes)
    alice_signature = alice_identity.sign(alice_payload)
    bob_signature = bob_identity.sign(bob_payload)

    # Mallory substitutes a key but can only replay Alice's signature. The signature
    # no longer matches because it covers the exact ephemeral public key and context.
    substituted_payload = _signature_payload(
        "Alice", "Bob", salt, mallory_ephemeral.public_bytes
    )
    attack_blocked = False
    try:
        alice_identity.public_key().verify(alice_signature, substituted_payload)
    except InvalidSignature:
        attack_blocked = True

    # Honest keys and their signatures are accepted.
    alice_identity.public_key().verify(alice_signature, alice_payload)
    bob_identity.public_key().verify(bob_signature, bob_payload)

    alice_key = _derive_session_key(
        alice_ephemeral.private, bob_ephemeral.public_bytes, salt
    )
    bob_key = _derive_session_key(
        bob_ephemeral.private, alice_ephemeral.public_bytes, salt
    )
    associated_data = b"Alice->Bob|authenticated-demo"
    nonce, ciphertext = _encrypt(alice_key, message, associated_data)
    received_message = _decrypt(bob_key, nonce, ciphertext, associated_data)

    alice_identity_public = alice_identity.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    bob_identity_public = bob_identity.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )

    return {
        "scenario": "Authenticated exchange with blocked MITM attack",
        "sent_message": message,
        "received_message": received_message,
        "mallory_attempted_message": attempted_replacement,
        "replacement_blocked": True,
        "attack_blocked": attack_blocked,
        "signatures_valid": True,
        "keys_match": alice_key == bob_key,
        "alice_identity_fingerprint": _fingerprint(alice_identity_public),
        "bob_identity_fingerprint": _fingerprint(bob_identity_public),
        "session_key_fingerprint": _fingerprint(alice_key),
        "ciphertext_hex": ciphertext.hex(),
        "security_result": (
            "Attack blocked: the substituted ephemeral key failed Ed25519 signature verification."
        ),
        "transcript": [
            _event(1, "Alice + Bob", "Generate identity and X25519 keys", "Long-term Ed25519 identities authenticate fresh X25519 keys."),
            _event(2, "Alice + Bob", "Sign ephemeral public keys", "Signatures cover protocol context, identities, salt and exact key bytes."),
            _event(3, "Mallory", "Attempt key substitution", f"Mallory substitutes a key and plans to send {attempted_replacement!r}.", "DANGER"),
            _event(4, "Bob", "Verify Ed25519 signature", "Verification fails because the signed key bytes were changed.", "SUCCESS"),
            _event(5, "Alice + Bob", "Accept genuine signed keys", "Both authentic signatures verify successfully.", "SUCCESS"),
            _event(6, "Alice + Bob", "X25519 + HKDF-SHA-256", "Both derive the same authenticated session key."),
            _event(7, "Alice", "AES-256-GCM encryption", "Encrypts the message with authenticated context."),
            _event(8, "Bob", "Authenticated decryption", "Bob receives the original message; Mallory has no session key.", "SUCCESS"),
        ],
    }


def benchmark_protocols(rounds: int = 20) -> list[dict[str, float | str]]:
    """Measure complete scenario runtimes for the report's performance comparison."""

    if not 1 <= rounds <= 200:
        raise ValueError("Rounds must be between 1 and 200.")

    scenarios = (
        ("Normal exchange", simulate_normal_exchange),
        ("MITM attack", simulate_mitm_attack),
        ("Authenticated defense", simulate_authenticated_exchange),
    )
    rows: list[dict[str, float | str]] = []
    for name, simulation in scenarios:
        samples_ms: list[float] = []
        for _ in range(rounds):
            started = perf_counter_ns()
            simulation("Performance test message")
            samples_ms.append((perf_counter_ns() - started) / 1_000_000)
        rows.append(
            {
                "Scenario": name,
                "Average time (ms)": round(mean(samples_ms), 4),
                "Minimum time (ms)": round(min(samples_ms), 4),
                "Maximum time (ms)": round(max(samples_ms), 4),
            }
        )
    return rows

