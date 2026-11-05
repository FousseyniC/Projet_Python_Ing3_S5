"""Tests du Module 3."""

from moteur_traitement import analysis


def test_error_ips():
    records = [
        {"level": "ERROR", "ip": "1.1.1.1"},
        {"level": "CRITICAL", "ip": "1.1.1.1"},
        {"level": "INFO", "ip": "2.2.2.2"},
    ]
    assert analysis.error_ips(records) == {"1.1.1.1"}