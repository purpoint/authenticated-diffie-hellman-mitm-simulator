"""Integration tests for protocol execution and safe audit recording."""

from pathlib import Path

from audit_database import AuditDatabase
from simulation_service import SimulationService


def make_service(tmp_path: Path) -> SimulationService:
    return SimulationService(AuditDatabase(tmp_path / "service.db"))


def test_normal_run_is_recorded(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    result = service.run_normal("confidential classroom message")
    assert result["outcome"] == "SECURE DELIVERY"
    assert result["audit_id"] == 1
    assert len(result["transcript"]) == 6
    assert service.database.count() == 1


def test_attack_records_exposure_without_plaintext(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    secret = "do not store this plaintext"
    result = service.run_mitm(secret, "modified")
    stored = service.database.get_history()[0]
    assert result["outcome"] == "ATTACK SUCCEEDED"
    assert result["mallory_read"] == secret
    assert secret not in str(stored)
    assert len(stored["message_sha256"]) == 64


def test_authenticated_run_records_blocked_attack(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    result = service.run_authenticated("signed exchange", "forged message")
    assert result["outcome"] == "ATTACK BLOCKED"
    assert result["attack_blocked"] is True
    assert result["mallory_attempted_message"] == "forged message"
    assert service.database.get_statistics()["attacks_blocked"] == 1


def test_complete_demo_records_three_distinct_scenarios(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    results = service.run_complete_demo("original", "replacement")
    assert [result["scenario_label"] for result in results] == [
        "Normal Exchange",
        "MITM Attack",
        "Authenticated Defense",
    ]
    assert service.database.count() == 3

