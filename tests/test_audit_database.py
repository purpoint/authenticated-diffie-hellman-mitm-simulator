"""Persistence tests for simulation audit history."""

import json
from pathlib import Path

import pytest

from audit_database import AuditDatabase


def record_sample(database: AuditDatabase, scenario: str = "MITM Attack") -> int:
    return database.record_run(
        scenario=scenario,
        outcome="ATTACK SUCCEEDED",
        attack_success=True,
        attack_blocked=False,
        keys_match=False,
        duration_ms=0.42,
        message_sha256="a" * 64,
        summary="Educational attack succeeded.",
        metadata={"algorithms": ["X25519"]},
    )


def test_database_initializes_with_zero_statistics(tmp_path: Path) -> None:
    database = AuditDatabase(tmp_path / "audit.db")
    assert database.get_statistics() == {
        "total_runs": 0,
        "attacks_exposed": 0,
        "attacks_blocked": 0,
        "secure_deliveries": 0,
    }


def test_record_is_persisted_with_json_metadata(tmp_path: Path) -> None:
    database = AuditDatabase(tmp_path / "audit.db")
    record_id = record_sample(database)
    row = database.get_history()[0]
    assert record_id == 1
    assert row["scenario"] == "MITM Attack"
    assert row["message_sha256"] == "a" * 64
    assert json.loads(row["metadata_json"])["algorithms"] == ["X25519"]


def test_history_filters_by_scenario(tmp_path: Path) -> None:
    database = AuditDatabase(tmp_path / "audit.db")
    record_sample(database, "MITM Attack")
    record_sample(database, "Normal Exchange")
    rows = database.get_history(scenario="MITM Attack")
    assert len(rows) == 1
    assert rows[0]["scenario"] == "MITM Attack"


def test_statistics_count_attack_and_blocked_defense(tmp_path: Path) -> None:
    database = AuditDatabase(tmp_path / "audit.db")
    record_sample(database)
    database.record_run(
        scenario="Authenticated Defense",
        outcome="ATTACK BLOCKED",
        attack_success=False,
        attack_blocked=True,
        keys_match=True,
        duration_ms=0.5,
        message_sha256="b" * 64,
        summary="Blocked.",
        metadata={},
    )
    stats = database.get_statistics()
    assert stats["total_runs"] == 2
    assert stats["attacks_exposed"] == 1
    assert stats["attacks_blocked"] == 1


def test_invalid_history_limit_is_rejected(tmp_path: Path) -> None:
    database = AuditDatabase(tmp_path / "audit.db")
    with pytest.raises(ValueError, match="between 1 and 2000"):
        database.get_history(limit=0)

