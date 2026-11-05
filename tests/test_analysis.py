"""Tests du Module 3."""

from moteur_traitement import analysis


def test_error_ips():
    records = [
        {"level": "ERROR", "ip": "1.1.1.1"},
        {"level": "CRITICAL", "ip": "1.1.1.1"},
        {"level": "INFO", "ip": "2.2.2.2"},
    ]
    assert analysis.error_ips(records) == {"1.1.1.1"}


def test_compare_with_blacklist():
    result = analysis.compare_with_blacklist(
        {"1.1.1.1", "203.0.113.9"},
        frozenset({"203.0.113.9", "8.8.8.8"}),
    )
    assert result["union"] == {"1.1.1.1", "203.0.113.9", "8.8.8.8"}
    assert result["intersection"] == {"203.0.113.9"}
    assert result["difference"] == {"1.1.1.1"}
    assert result["symmetric_difference"] == {"1.1.1.1", "8.8.8.8"}