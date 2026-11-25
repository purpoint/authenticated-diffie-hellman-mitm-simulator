"""Educational authenticated Diffie-Hellman simulator."""

from .protocol import (
    benchmark_protocols,
    simulate_authenticated_exchange,
    simulate_mitm_attack,
    simulate_normal_exchange,
)

__all__ = [
    "benchmark_protocols",
    "simulate_authenticated_exchange",
    "simulate_mitm_attack",
    "simulate_normal_exchange",
]

