"""Correctness and security-property tests for all three demonstrations."""

import pytest

from crypto_simulator.protocol import (
    benchmark_protocols,
    simulate_authenticated_exchange,
    simulate_mitm_attack,
    simulate_normal_exchange,
)


def test_normal_exchange_creates_matching_keys_and_delivers_message() -> None:
    result = simulate_normal_exchange("Meet at 10:00")

    assert result["keys_match"] is True
    assert result["received_message"] == "Meet at 10:00"
    assert (
        result["alice_session_key_fingerprint"]
        == result["bob_session_key_fingerprint"]
    )


def test_mitm_can_read_and_replace_message() -> None:
    result = simulate_mitm_attack("Pay Bob ₹500", "Pay Mallory ₹5,000")

    assert result["mallory_read"] == "Pay Bob ₹500"
    assert result["bob_received"] == "Pay Mallory ₹5,000"
    assert result["alice_mallory_keys_match"] is True
    assert result["mallory_bob_keys_match"] is True
    assert result["alice_bob_have_direct_key"] is False


def test_authenticated_exchange_rejects_substituted_key() -> None:
    result = simulate_authenticated_exchange("Authenticated hello")

    assert result["attack_blocked"] is True
    assert result["signatures_valid"] is True
    assert result["keys_match"] is True
    assert result["received_message"] == "Authenticated hello"


@pytest.mark.parametrize(
    "simulation",
    [
        simulate_normal_exchange,
        simulate_mitm_attack,
        simulate_authenticated_exchange,
    ],
)
def test_empty_message_is_rejected(simulation) -> None:
    with pytest.raises(ValueError, match="cannot be empty"):
        simulation("   ")


def test_benchmark_returns_all_scenarios() -> None:
    results = benchmark_protocols(rounds=2)

    assert [row["Scenario"] for row in results] == [
        "Normal exchange",
        "MITM attack",
        "Authenticated defense",
    ]
    assert all(float(row["Average time (ms)"]) >= 0 for row in results)


def test_benchmark_rejects_unreasonable_round_count() -> None:
    with pytest.raises(ValueError, match="between 1 and 200"):
        benchmark_protocols(rounds=0)

