"""Tests for downloadable evidence and history exports."""

import csv
import io
from pathlib import Path

from audit_database import AuditDatabase
from report_generator import generate_run_report, history_to_csv
from simulation_service import SimulationService


def test_run_report_contains_outcome_and_transcript(tmp_path: Path) -> None:
    service = SimulationService(AuditDatabase(tmp_path / "report.db"))
    result = service.run_authenticated("report message")
    report = generate_run_report(result)
    assert "AUTHENTICATED DIFFIE-HELLMAN MITM SIMULATION REPORT" in report
    assert "ATTACK BLOCKED" in report
    assert "PROTOCOL TRANSCRIPT" in report
    assert "Educational security notice" in report


def test_history_csv_has_header_and_record(tmp_path: Path) -> None:
    service = SimulationService(AuditDatabase(tmp_path / "report.db"))
    service.run_normal("csv message")
    rows = list(csv.DictReader(io.StringIO(history_to_csv(service.database.get_history()))))
    assert len(rows) == 1
    assert rows[0]["scenario"] == "Normal Exchange"
    assert len(rows[0]["message_sha256"]) == 64

