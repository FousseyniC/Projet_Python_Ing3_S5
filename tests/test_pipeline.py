"""Tests du Module 2 (pipeline)."""

from moteur_traitement.pipeline import (
    filter_levels,
    normalize,
    remove_invalid,
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