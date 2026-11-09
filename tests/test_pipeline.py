"""Tests du Module 2 (pipeline)."""

from moteur_traitement.pipeline import (
    filter_levels,
    normalize,
    remove_invalid,
    route,
    transform,
)


def test_remove_invalid_supprime_les_none():
    data = [{"level": "INFO"}, None, {"level": "ERROR"}, None]
    assert list(remove_invalid(data)) == [
        {"level": "INFO"},
        {"level": "ERROR"},
    ]

def test_normalize_niveau_en_majuscules():
    result = normalize({"level": " info ", "ip": "1.2.3.4", "user": "u1"})
    assert result["level"] == "INFO"


def test_normalize_alias_de_niveau():
    result = normalize({"level": "warn", "ip": "1.2.3.4", "user": "u1"})
    assert result["level"] == "WARNING"


def test_normalize_valeur_nulle_devient_none():
    result = normalize({"level": "INFO", "ip": "1.2.3.4", "user": "N/A"})
    assert result["user"] is None


def test_normalize_ne_modifie_pas_loriginal():
    original = {"level": " info ", "ip": "1.2.3.4", "user": "u1"}
    normalize(original)
    assert original["level"] == " info "


def test_normalize_entree_inattendue():
    assert normalize(None)["level"] is None

def test_filter_levels_retire_les_niveaux_invalides():
    sample = [{"level": "INFO"}, {"level": "DEBUGG"}, {"level": None}]
    assert list(filter_levels(sample)) == [{"level": "INFO"}]

def test_route_texte_brut():
    record = {"payload": "cron: backup_4 completed", "connection": None}
    assert route(record) == ("text", "cron: backup_4 completed")


def test_route_connexion_ssh():
    record = {
        "payload": {"action": "login", "port": 22, "protocol": "SSH"},
        "connection": ("10.0.0.5", 22, "SSH"),
    }
    assert route(record) == ("connection", "10.0.0.5:22/SSH")


def test_route_connexion_web():
    record = {
        "payload": {"method": "GET", "port": 443, "protocol": "HTTPS"},
        "connection": ("10.0.0.6", 443, "HTTPS"),
    }
    assert route(record) == ("connection", "10.0.0.6:443/HTTPS")


def test_route_action_sans_connexion():
    record = {"payload": {"action": "login"}, "connection": None}
    assert route(record) == ("action", "login")


def test_route_web_sans_connexion():
    record = {"payload": {"method": "POST"}, "connection": None}
    assert route(record) == ("web", "POST")


def test_route_inconnu():
    assert route({}) == ("unknown", None)

def test_transform_enchaine_les_etapes():
    raw = [
        {"level": " warning ", "ip": "1.1.1.1", "user": "u1"},
        None,
        {"level": "DEBUGG", "ip": "2.2.2.2", "user": "u2"},
    ]
    out = list(transform(raw))
    assert len(out) == 1
    assert out[0]["level"] == "WARNING"


def test_transform_reste_paresseux():
    flux = (r for r in [{"level": "INFO", "ip": "1.1.1.1", "user": None}])
    result = transform(flux)
    assert iter(result) is result