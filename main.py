"""Command-line entry point for simulations, audit history and demonstrations."""

from __future__ import annotations

import argparse
import json

from crypto_simulator import benchmark_protocols
from demo_walkthrough import run_full_demonstration
from simulation_service import SimulationService


def _print_result(result: dict[str, object]) -> None:
    print("\n" + "=" * 82)
    print(f"SCENARIO : {result['scenario_label']}")
    print(f"OUTCOME  : {result['outcome']}")
    print(f"AUDIT ID : {result['audit_id']}")
    print(f"TIME     : {result['duration_ms']} ms")
    print("-" * 82)
    print(result["security_result"])
    print("-" * 82)
    for entry in result["transcript"]:
        print(f"[{entry['Step']}] {entry['Actor']} — {entry['Operation']} ({entry['State']})")
        print(f"    {entry['Detail']}")
    print("=" * 82)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authenticated Diffie-Hellman MITM simulator"
    )
    parser.add_argument("--demo", action="store_true", help="run the full guided demonstration")
    parser.add_argument(
        "--scenario",
        choices=("normal", "mitm", "protected"),
        help="execute one protocol scenario",
    )
    parser.add_argument("--message", default="Transfer Rs. 5,000 to Bob")
    parser.add_argument("--replacement", default="Transfer Rs. 50,000 to Mallory")
    parser.add_argument("--history", action="store_true", help="show recent audit records")
    parser.add_argument("--benchmark", type=int, metavar="ROUNDS", help="benchmark each scenario")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    service = SimulationService()

    if args.demo:
        run_full_demonstration(service)
        return 0
    if args.scenario == "normal":
        _print_result(service.run_normal(args.message))
        return 0
    if args.scenario == "mitm":
        _print_result(service.run_mitm(args.message, args.replacement))
        return 0
    if args.scenario == "protected":
        _print_result(service.run_authenticated(args.message))
        return 0
    if args.history:
        print(json.dumps(service.database.get_history(limit=30), indent=2))
        return 0
    if args.benchmark is not None:
        print(json.dumps(benchmark_protocols(args.benchmark), indent=2))
        return 0

    build_parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

