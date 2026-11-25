"""Human-readable protocol reports and CSV audit exports."""

from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Any


SECURITY_NOTICE = (
    "Educational security notice: This simulator models prior trust in Ed25519 "
    "identity public keys. A production protocol also needs certificate/key distribution, "
    "secure private-key storage, replay state, error handling and independent review."
)


def generate_run_report(result: dict[str, object]) -> str:
    """Return a structured text report suitable for download or report evidence."""

    divider = "=" * 88
    lines = [
        divider,
        "AUTHENTICATED DIFFIE-HELLMAN MITM SIMULATION REPORT",
        "Subject: Cryptography and Network Security",
        divider,
        f"Generated at       : {datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"Audit record ID    : {result.get('audit_id', 'Not recorded')}",
        f"Scenario           : {result.get('scenario_label', result.get('scenario'))}",
        f"Final outcome      : {result.get('outcome', 'N/A')}",
        f"Execution time     : {result.get('duration_ms', 'N/A')} ms",
        f"Message SHA-256    : {result.get('message_sha256', 'N/A')}",
        "Algorithms         : X25519, HKDF-SHA-256, AES-256-GCM, Ed25519 (defense)",
        "-" * 88,
        "SECURITY RESULT",
        str(result.get("security_result", "No result available.")),
        "-" * 88,
        "PROTOCOL TRANSCRIPT",
    ]
    for entry in result.get("transcript", []):
        if not isinstance(entry, dict):
            continue
        lines.append(
            f"[{entry.get('Step')}] {entry.get('Actor')} | {entry.get('Operation')} | "
            f"{entry.get('State')}\n    {entry.get('Detail')}"
        )
    lines.extend(["-" * 88, SECURITY_NOTICE, divider])
    return "\n".join(lines) + "\n"


def history_to_csv(records: list[dict[str, Any]]) -> str:
    """Serialize audit history to CSV without exposing message plaintext."""

    output = io.StringIO()
    fields = [
        "id",
        "created_at",
        "scenario",
        "outcome",
        "attack_success",
        "attack_blocked",
        "keys_match",
        "duration_ms",
        "message_sha256",
        "summary",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(records)
    return output.getvalue()

