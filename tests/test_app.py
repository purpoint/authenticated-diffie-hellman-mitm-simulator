"""Streamlit smoke tests for every interactive project scenario."""

from pathlib import Path

from streamlit.testing.v1 import AppTest


APP_FILE = Path(__file__).resolve().parents[1] / "app.py"


SCENARIOS = (
    "1. Normal exchange (works, but identity is not verified)",
    "2. MITM attack (Mallory reads and modifies the message)",
    "3. Authenticated defense (Mallory is detected)",
)


def test_app_loads_without_exception() -> None:
    app = AppTest.from_file(APP_FILE).run(timeout=10)

    assert not app.exception
    assert app.title[0].value == "🔐 Authenticated Diffie-Hellman MITM Simulator"


def test_each_live_scenario_runs_without_exception() -> None:
    for scenario in SCENARIOS:
        app = AppTest.from_file(APP_FILE).run(timeout=10)
        app.radio[0].set_value(scenario)
        app.button[0].click()
        app.run(timeout=10)

        assert not app.exception


def test_experiment_runs_without_exception() -> None:
    app = AppTest.from_file(APP_FILE).run(timeout=10)
    app.button[1].click()
    app.run(timeout=20)

    assert not app.exception
    assert len(app.dataframe) == 1

