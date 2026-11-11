"""Tests du Module 3."""

from datetime import datetime, timedelta

from moteur_traitement import analysis


def login(status: str, ip: str = "6.6.6.6") -> dict:
    """Fabrique un record de connexion pour les tests."""
    return {
        "timestamp": datetime(2026, 1, 1),
        "ip": ip,
        "user": "bob",
        "level": "WARNING",
        "payload": {"action": "login", "status": status},
    }


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


def test_count_by():
    records = [
        {"level": "INFO"}, {"level": "INFO"}, {"level": "INFO"},
        {"level": "ERROR"}, {"level": "CRITICAL"},
    ]
    assert analysis.count_by(records, "level") == {
        "INFO": 3,
        "ERROR": 1,
        "CRITICAL": 1,
    }


def test_detect_brute_force():
    fail, ok = login("failed"), login("success")
    alert = [("6.6.6.6", "bob")]
    assert analysis.detect_brute_force([fail] * 6) == alert
    assert analysis.detect_brute_force([fail] * 40) == alert
    assert analysis.detect_brute_force([fail] * 3) == []
    assert analysis.detect_brute_force([fail] * 3 + [ok] + [fail] * 3) == []
    text = {"ip": "1.1.1.1", "user": None, "payload": "texte"}
    assert analysis.detect_brute_force([text]) == []


def test_detect_brute_force_small_batches():
    # Le compteur continue d'un paquet à l'autre.
    records = [login("failed")] * 6
    result = analysis.detect_brute_force(records, batch_size=2)
    assert result == [("6.6.6.6", "bob")]


def test_stats_update(sample_records):
    stats = analysis.Stats()
    for record in sample_records:
        stats.update(record)
    assert stats.total == 4
    assert stats.error_ips == {"22.128.79.209", "77.185.106.206"}
    assert stats.by_level == {
        "INFO": 1,
        "WARNING": 1,
        "ERROR": 1,
        "CRITICAL": 1,
    }
    assert stats.alerts == []


def test_stats_same_as_detect_brute_force():
    records = [login("failed")] * 6 + [login("success", "7.7.7.7")]
    stats = analysis.Stats(threshold=5)
    for record in records:
        stats.update(record)
    assert stats.alerts == analysis.detect_brute_force(records, threshold=5)


def test_stats_compare_with_blacklist(sample_records):
    stats = analysis.Stats()
    for record in sample_records:
        stats.update(record)
    blacklist = frozenset({"77.185.106.206", "8.8.8.8"})
    result = stats.compare_with_blacklist(blacklist)
    assert result["intersection"] == {"77.185.106.206"}


def test_forget_old_oublie_les_vieux_echecs():
    stats = analysis.Stats()
    for _ in range(3):
        stats.update(login("failed"))
    assert len(stats.failures) == 1
    stats.forget_old(datetime(2026, 1, 1) + timedelta(minutes=10))
    assert len(stats.failures) == 0


def test_forget_old_garde_les_echecs_recents():
    stats = analysis.Stats()
    for _ in range(3):
        stats.update(login("failed"))
    stats.forget_old(datetime(2026, 1, 1) + timedelta(minutes=1))
    assert len(stats.failures) == 1


def test_vieil_echec_ne_compte_plus():
    # 4 échecs à minuit, puis 4 échecs une heure plus tard.
    old = login("failed")
    new = login("failed")
    new["timestamp"] = datetime(2026, 1, 1, 1, 0)
    records = [old] * 4 + [new] * 4
    assert analysis.detect_brute_force(records) == []


def test_statut_inconnu_ne_remet_pas_a_zero():
    # Seule une connexion réussie remet le compteur à zéro.
    fail = login("failed")
    records = [fail] * 3 + [login("unknown")] + [fail] * 2
    assert analysis.detect_brute_force(records) == [("6.6.6.6", "bob")]
