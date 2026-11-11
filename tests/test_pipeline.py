"""Tests du Module 2 (pipeline)."""

from moteur_traitement.pipeline import (
    filter_levels,
    is_valid_ip,
    normalize,
    remove_invalid,
    route,
    transform,
)


def test_remove_invalid_supprime_les_none():
    data = [{"ip": "1.1.1.1"}, None, {"ip": "2.2.2.2"}, None]
    assert list(remove_invalid(data)) == [
        {"ip": "1.1.1.1"},
        {"ip": "2.2.2.2"},
    ]


def test_remove_invalid_supprime_les_ip_invalides():
    data = [{"ip": "999.300.1.1"}, {"ip": "localhost"}, {"ip": "10.0.0.5"}]
    assert list(remove_invalid(data)) == [{"ip": "10.0.0.5"}]


def test_is_valid_ip():
    assert is_valid_ip("10.0.0.5")
    assert is_valid_ip("010.000.000.005")
    assert not is_valid_ip("999.300.1.1")
    assert not is_valid_ip("10.0.0")
    assert not is_valid_ip("unknown")


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


def test_normalize_utilisateur_en_minuscule():
    for user in ("BOB46", "Bob46", '"bob46"', "  bob46 "):
        result = normalize({"level": "INFO", "ip": "1.2.3.4", "user": user})
        assert result["user"] == "bob46"


def test_normalize_ip_sans_zeros():
    result = normalize(
        {"level": "INFO", "ip": "010.000.000.005", "user": "u1"}
    )
    assert result["ip"] == "10.0.0.5"


def test_normalize_reconstruit_connection():
    record = {
        "level": "INFO",
        "ip": "010.000.000.005",
        "user": "u1",
        "connection": ("010.000.000.005", 22, "SSH"),
    }
    assert normalize(record)["connection"] == ("10.0.0.5", 22, "SSH")


def test_normalize_payload_json():
    record = {
        "level": "WARNING",
        "ip": "1.2.3.4",
        "user": "u1",
        "payload": {"Action": "login", "Status": "FAILED", "Port": "22"},
    }
    assert normalize(record)["payload"] == {
        "action": "login",
        "status": "failed",
        "port": 22,
    }


def test_normalize_payload_texte():
    for text in ("cron:   backup_4   completed   ",
                 "CRON: BACKUP_4 COMPLETED",
                 "cron:\tbackup_4 completed\x07",
                 '"cron: backup_4 completed"'):
        record = {"level": "INFO", "ip": "1.2.3.4", "user": None,
                  "payload": text}
        assert normalize(record)["payload"] == "cron: backup_4 completed"
