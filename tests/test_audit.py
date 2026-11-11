"""Tests du Module 4 : audit avec globals() et locals()."""

import json
import logging
from datetime import datetime

from moteur_traitement.audit import audit_scope

REPORT_KEYS = {
    "generated_at",
    "python_version",
    "globals",
    "locals",
    "shadowed",
    "alerts",
}


def names(variables):
    """Noms des variables d'une partie du rapport."""
    return [v["name"] for v in variables]


def card(report, name):
    """Fiche d'une variable locale du rapport."""
    return next(v for v in report["locals"] if v["name"] == name)


def test_sans_argument_audite_le_module():
    report = audit_scope()
    assert set(report) == REPORT_KEYS
    assert "audit_scope" in names(report["globals"])


def test_portees_de_l_appelant():
    seuil = 5  # lue par locals()
    report = audit_scope(globals(), locals())
    assert "REPORT_KEYS" in names(report["globals"])
    assert "seuil" in names(report["locals"])


def test_fiche_d_une_variable():
    blacklist = frozenset({"6.6.6.6", "7.7.7.7"})
    fiche = card(audit_scope({}, {"blacklist": blacklist}), "blacklist")
    assert fiche["kind"] == "data"
    assert fiche["type"] == "frozenset"
    assert fiche["length"] == 2
    assert fiche["bytes"] > 0


def test_genre_des_variables():
    report = audit_scope({}, {"j": json, "d": datetime, "n": names, "x": 1})
    kinds = {v["name"]: v["kind"] for v in report["locals"]}
    assert kinds == {"d": "class", "j": "module", "n": "function", "x": "data"}


def test_noms_internes_ignores():
    report = audit_scope({"__name__": "main", "a": 1}, {})
    assert names(report["globals"]) == ["a"]


def test_variable_qui_cache_une_globale():
    report = audit_scope({"x": 1, "y": 2}, {"x": 3})
    assert report["shadowed"] == ["x"]


def test_meme_portee_rien_de_cache():
    scope = {"x": 1}
    assert audit_scope(scope, scope)["shadowed"] == []


def test_generateur_non_consomme():
    gen = (i for i in range(3))
    fiche = card(audit_scope({}, {"gen": gen}), "gen")
    assert fiche["length"] is None
    assert list(gen) == [0, 1, 2]


def test_pas_d_apercu_pour_un_gros_conteneur():
    fiche = card(audit_scope({}, {"ips": set(range(100_000))}), "ips")
    assert fiche["preview"] is None
    assert fiche["length"] == 100_000


def test_apercu_tronque():
    fiche = card(audit_scope({}, {"texte": "a" * 500}), "texte")
    assert len(fiche["preview"]) == 80


def test_export_json(tmp_path):
    path = tmp_path / "sortie" / "audit.json"
    alerts = {"samples": [{"timestamp": datetime(2026, 1, 1)}]}
    audit_scope({"a": 1}, {}, alerts, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert set(data) == REPORT_KEYS
    assert data["alerts"]["samples"][0]["timestamp"] == "2026-01-01 00:00:00"


def test_export_impossible_ne_plante_pas(tmp_path, caplog):
    # Un dossier à la place du fichier : l'écriture échoue.
    report = audit_scope({}, {}, None, tmp_path)
    assert set(report) == REPORT_KEYS
    assert any(r.levelno == logging.ERROR for r in caplog.records)
