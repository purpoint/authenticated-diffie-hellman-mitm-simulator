"""Persistent SQLite audit history for simulator runs.

The database deliberately stores only a SHA-256 digest of the demonstration message,
not its plaintext. This makes the audit trail useful without turning it into a store of
potentially sensitive classroom input.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_DB_PATH = Path(__file__).resolve().parent / "data" / "protocol_audit.db"


class AuditDatabase:
    """Small data-access layer for protocol simulation audit records."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simulation_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    scenario TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    attack_success INTEGER NOT NULL CHECK (attack_success IN (0, 1)),
                    attack_blocked INTEGER NOT NULL CHECK (attack_blocked IN (0, 1)),
                    keys_match INTEGER NOT NULL CHECK (keys_match IN (0, 1)),
                    duration_ms REAL NOT NULL CHECK (duration_ms >= 0),
                    message_sha256 TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_runs_created_at ON simulation_runs(created_at DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_runs_scenario ON simulation_runs(scenario)"
            )

    def record_run(
        self,
        *,
        scenario: str,
        outcome: str,
        attack_success: bool,
        attack_blocked: bool,
        keys_match: bool,
        duration_ms: float,
        message_sha256: str,
        summary: str,
        metadata: dict[str, Any],
    ) -> int:
        created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO simulation_runs (
                    created_at, scenario, outcome, attack_success, attack_blocked,
                    keys_match, duration_ms, message_sha256, summary, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    created_at,
                    scenario,
                    outcome,
                    int(attack_success),
                    int(attack_blocked),
                    int(keys_match),
                    round(duration_ms, 6),
                    message_sha256,
                    summary,
                    json.dumps(metadata, sort_keys=True),
                ),
            )
            return int(cursor.lastrowid)

    def get_history(
        self,
        *,
        scenario: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        if not 1 <= limit <= 2_000:
            raise ValueError("History limit must be between 1 and 2000.")
        query = "SELECT * FROM simulation_runs"
        parameters: list[Any] = []
        if scenario and scenario != "All":
            query += " WHERE scenario = ?"
            parameters.append(scenario)
        query += " ORDER BY id DESC LIMIT ?"
        parameters.append(limit)
        with self._connect() as connection:
            return [dict(row) for row in connection.execute(query, parameters).fetchall()]

    def get_statistics(self) -> dict[str, int]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    COUNT(*) AS total_runs,
                    COALESCE(SUM(attack_success), 0) AS attacks_exposed,
                    COALESCE(SUM(attack_blocked), 0) AS attacks_blocked,
                    COALESCE(SUM(CASE WHEN outcome = 'SECURE DELIVERY' THEN 1 ELSE 0 END), 0)
                        AS secure_deliveries
                FROM simulation_runs
                """
            ).fetchone()
        return {key: int(row[key]) for key in row.keys()}

    def count(self) -> int:
        return self.get_statistics()["total_runs"]

