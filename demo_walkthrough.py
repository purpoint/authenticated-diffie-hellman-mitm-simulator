"""Automated presentation walkthrough for the complete attack/defense story."""

from __future__ import annotations

from simulation_service import SimulationService


def _heading(step: int, title: str) -> None:
    print("\n" + "=" * 86)
    print(f"STEP {step}: {title.upper()}")
    print("=" * 86)


def _show_transcript(result: dict[str, object]) -> None:
    for entry in result["transcript"]:
        print(
            f"  [{entry['Step']}] {entry['Actor']:<18} | "
            f"{entry['Operation']:<34} | {entry['State']}"
        )


def run_full_demonstration(service: SimulationService | None = None) -> bool:
    service = service or SimulationService()
    message = "Transfer Rs. 5,000 to Bob"
    replacement = "Transfer Rs. 50,000 to Mallory"

    print("\n" + "#" * 86)
    print(" AUTHENTICATED DIFFIE-HELLMAN: MITM ATTACK AND PREVENTION")
    print(" BCS703 Cryptography and Network Security | Automated Demonstration")
    print("#" * 86)

    _heading(1, "Define participants and threat model")
    print("Alice sends a confidential instruction to Bob across a network controlled by Mallory.")
    print("Mallory may intercept, replace, decrypt and re-encrypt messages, but cannot steal identity keys.")

    _heading(2, "Run honest unauthenticated key exchange")
    normal = service.run_normal(message)
    _show_transcript(normal)
    assert normal["keys_match"] is True
    assert normal["received_message"] == message
    print(f"Outcome: {normal['outcome']} | Audit ID: {normal['audit_id']}")

    _heading(3, "Identify the missing security property")
    print("The ciphertext is confidential, but neither participant authenticated the received public key.")
    print("Encryption without peer identity remains vulnerable to active substitution.")

    _heading(4, "Insert Mallory and substitute both public keys")
    attack = service.run_mitm(message, replacement)
    _show_transcript(attack)
    assert attack["mallory_read"] == message
    assert attack["bob_received"] == replacement
    print(f"Outcome: {attack['outcome']} | Audit ID: {attack['audit_id']}")

    _heading(5, "Explain why AES-GCM did not fail")
    print("Mallory did not break AES-GCM. Alice and Bob each established a valid key with Mallory.")
    print("Therefore Mallory could generate valid authentication tags on both fraudulent channels.")

    _heading(6, "Authenticate ephemeral keys with Ed25519")
    protected = service.run_authenticated(message)
    _show_transcript(protected)
    assert protected["attack_blocked"] is True
    assert protected["received_message"] == message
    print(f"Outcome: {protected['outcome']} | Audit ID: {protected['audit_id']}")

    _heading(7, "Verify security conclusions")
    print("Normal channel     : Encrypted but unauthenticated")
    print("MITM channel       : Plaintext exposed and altered")
    print("Authenticated mode : Substitution rejected before message transmission")

    _heading(8, "Inspect persistent audit evidence")
    stats = service.database.get_statistics()
    print(f"Total recorded runs : {stats['total_runs']}")
    print(f"Attacks exposed     : {stats['attacks_exposed']}")
    print(f"Attacks blocked     : {stats['attacks_blocked']}")
    print("Plaintext storage   : DISABLED (only SHA-256 message digests are stored)")

    print("\n" + "#" * 86)
    print(" DEMONSTRATION COMPLETED SUCCESSFULLY")
    print("#" * 86 + "\n")
    return True


if __name__ == "__main__":
    run_full_demonstration()

