"""Application service that executes simulations and records safe audit metadata."""

from __future__ import annotations

import hashlib
from time import perf_counter_ns
from typing import Callable

from audit_database import AuditDatabase
from crypto_simulator.protocol import (
    simulate_authenticated_exchange,
    simulate_mitm_attack,
    simulate_normal_exchange,
)


class SimulationService:
    """Coordinate protocol execution, timing and SQLite audit persistence."""

    def __init__(self, database: AuditDatabase | None = None) -> None:
        self.database = database or AuditDatabase()

    def _execute(
        self,
        scenario: str,
        message: str,
        simulation: Callable[..., dict[str, object]],
        *args: str,
    ) -> dict[str, object]:
        started = perf_counter_ns()
        result = simulation(message, *args)
        duration_ms = (perf_counter_ns() - started) / 1_000_000

        attack_success = scenario == "MITM Attack"
        attack_blocked = bool(result.get("attack_blocked", False))
        keys_match = bool(
            result.get("keys_match", result.get("alice_mallory_keys_match", False))
        )
        if attack_success:
            outcome = "ATTACK SUCCEEDED"
        elif attack_blocked:
            outcome = "ATTACK BLOCKED"
        else:
            outcome = "SECURE DELIVERY"

        result["scenario_label"] = scenario
        result["duration_ms"] = round(duration_ms, 4)
        result["outcome"] = outcome
        result["message_sha256"] = hashlib.sha256(message.encode("utf-8")).hexdigest()

        metadata = {
            "transcript_steps": len(result.get("transcript", [])),
            "ciphertext_bytes": len(str(result.get("ciphertext_hex", ""))) // 2,
            "algorithms": ["X25519", "HKDF-SHA-256", "AES-256-GCM"],
        }
        if attack_blocked:
            metadata["algorithms"].append("Ed25519")

        result["audit_id"] = self.database.record_run(
            scenario=scenario,
            outcome=outcome,
            attack_success=attack_success,
            attack_blocked=attack_blocked,
            keys_match=keys_match,
            duration_ms=duration_ms,
            message_sha256=str(result["message_sha256"]),
            summary=str(result["security_result"]),
            metadata=metadata,
        )
        return result

    def run_normal(self, message: str) -> dict[str, object]:
        return self._execute(
            "Normal Exchange", message, simulate_normal_exchange
        )

    def run_mitm(self, message: str, replacement: str) -> dict[str, object]:
        return self._execute(
            "MITM Attack", message, simulate_mitm_attack, replacement
        )

    def run_authenticated(self, message: str) -> dict[str, object]:
        return self._execute(
            "Authenticated Defense", message, simulate_authenticated_exchange
        )

    def run_complete_demo(
        self,
        message: str,
        replacement: str,
    ) -> list[dict[str, object]]:
        return [
            self.run_normal(message),
            self.run_mitm(message, replacement),
            self.run_authenticated(message),
        ]

