"""Streamlit smoke tests for the professional dashboard workflows."""

from pathlib import Path

from streamlit.testing.v1 import AppTest


APP_FILE = Path(__file__).resolve().parents[1] / "app.py"
SCENARIOS = ("Normal exchange", "MITM attack", "Authenticated defense")


def test_dashboard_loads_without_exception() -> None:
    app = AppTest.from_file(APP_FILE).run(timeout=10)
    assert not app.exception
    assert len(app.tabs) == 4
    assert any("Live demonstration" in tab.label for tab in app.tabs)
    assert any("Experiment log" in tab.label for tab in app.tabs)
    assert any("Key exchange playground" in tab.label for tab in app.tabs)


def test_dark_theme_toggle_reruns_without_exception() -> None:
    app = AppTest.from_file(APP_FILE).run(timeout=10)
    app.toggle[0].set_value(True)
    app.run(timeout=10)

    assert not app.exception
    assert app.toggle[0].value is True
    assert "#101417" in app.markdown[0].value


def test_each_interactive_scenario_runs_without_exception() -> None:
    for scenario in SCENARIOS:
        app = AppTest.from_file(APP_FILE).run(timeout=10)
        app.radio[0].set_value(scenario)
        app.button[1].click()
        app.run(timeout=10)
        assert not app.exception


def test_complete_mission_and_experiment_run_without_exception() -> None:
    app = AppTest.from_file(APP_FILE).run(timeout=10)
    app.button[0].click()
    app.run(timeout=15)
    assert not app.exception

    app.button[2].click()
    app.run(timeout=20)
    assert not app.exception
    assert len(app.dataframe) >= 1

