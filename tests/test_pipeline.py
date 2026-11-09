"""Tests du Module 2 (pipeline)."""

from moteur_traitement.pipeline import remove_invalid


def test_remove_invalid_supprime_les_none():
    data = [{"level": "INFO"}, None, {"level": "ERROR"}, None]
    assert list(remove_invalid(data)) == [
        {"level": "INFO"},
        {"level": "ERROR"},
    ]