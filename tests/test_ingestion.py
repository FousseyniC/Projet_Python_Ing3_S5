"""Tests du Module 1 : lecture des fichiers et parsing des lignes."""

import tracemalloc
from pathlib import Path
from types import GeneratorType

import pytest

from moteur_traitement.ingestion import (
    load_blacklist,
    parse_line,
    read_log_file,
    read_many_files,
    read_records,
)

ECHANTILLON = Path(__file__).parent.parent / "data" / "echantillon"


# --- Lecture des fichiers (yield / yield from) ---

# Vérifie que read_log_file renvoie un générateur (yield).
def test_read_log_file_est_un_generateur(tmp_path):
    fichier = tmp_path / "a.log"
    fichier.write_text("ligne 1\nligne 2\n", encoding="utf-8")
    lignes = read_log_file(fichier)
    assert isinstance(lignes, GeneratorType)
    assert list(lignes) == ["ligne 1\n", "ligne 2\n"]


# Vérifie que plusieurs fichiers sont lus à la suite (yield from).
def test_read_many_files_enchaine_les_fichiers(tmp_path):
    a = tmp_path / "a.log"
    b = tmp_path / "b.log"
    a.write_text("a1\na2\n", encoding="utf-8")
    b.write_text("b1\n", encoding="utf-8")
    assert list(read_many_files([a, b])) == ["a1\n", "a2\n", "b1\n"]


# Vérifie qu'on peut donner un seul chemin au lieu d'une liste.
def test_read_many_files_accepte_un_chemin_seul(tmp_path):
    a = tmp_path / "a.log"
    a.write_text("a1\n", encoding="utf-8")
    assert list(read_many_files(str(a))) == ["a1\n"]


# Vérifie qu'un fichier absent est ignoré sans planter.
def test_read_many_files_ignore_un_fichier_absent(tmp_path):
    a = tmp_path / "a.log"
    a.write_text("a1\n", encoding="utf-8")
    absent = tmp_path / "absent.log"
    assert list(read_many_files([absent, a])) == ["a1\n"]


# --- Parsing des lignes ---

# Vérifie qu'une ligne propre donne le bon dictionnaire.
def test_parse_line_lignes_propres(sample_lines, sample_records):
    for i in range(len(sample_lines)):
        assert parse_line(sample_lines[i]) == sample_records[i]


# Vérifie que les lignes sales sont réparées.
def test_parse_line_lignes_sales(dirty_lines):
    for line, champs_attendus in dirty_lines:
        record = parse_line(line)
        assert record is not None, line
        for cle, valeur in champs_attendus.items():
            assert record[cle] == valeur, line


# Vérifie que les lignes cassées donnent None.
def test_parse_line_lignes_inutilisables(invalid_lines):
    for line in invalid_lines:
        assert parse_line(line) is None, repr(line)


# Vérifie que les IP invalides sont gardées (le Module 2 les retire).
def test_parse_line_garde_les_ip_invalides(bad_ip_lines):
    for line in bad_ip_lines:
        assert parse_line(line) is not None, line


# Vérifie que connection est bien un tuple (IP, port, protocole).
def test_connection_est_un_tuple(sample_lines):
    record = parse_line(sample_lines[0])
    assert record["connection"] == ("197.125.255.225", 22, "SSH")
    assert isinstance(record["connection"], tuple)


# --- read_records et load_blacklist ---

# Vérifie que read_records ne crée pas de liste en mémoire.
def test_read_records_reste_paresseux(tmp_path):
    fichier = tmp_path / "a.log"
    fichier.write_text("2026-01-01 00:00:00 | INFO | 10.0.0.1 | - | ok\n\n",
                       encoding="utf-8")
    records = read_records(fichier)
    assert not isinstance(records, list)
    resultat = list(records)
    assert resultat[0]["level"] == "INFO"
    assert resultat[1] is None


# Vérifie que la blacklist devient un frozenset, sans les lignes vides.
def test_load_blacklist(tmp_path):
    fichier = tmp_path / "blacklist.txt"
    fichier.write_text("1.2.3.4\n\n5.6.7.8\n", encoding="utf-8")
    blacklist = load_blacklist(fichier)
    assert blacklist == frozenset({"1.2.3.4", "5.6.7.8"})


# --- Mémoire : le fichier n'est jamais chargé en entier ---

# Vérifie que la mémoire reste basse en lisant tout l'échantillon.
def test_memoire_reste_basse():
    log = ECHANTILLON / "server.log"
    if not log.exists():
        pytest.skip("échantillon absent")

    tracemalloc.start()
    nb_records = sum(1 for _ in read_records(log))
    _, pic = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    taille_fichier = log.stat().st_size
    assert nb_records > 0
    # Le pic de mémoire doit rester très inférieur à la taille du fichier.
    assert pic < taille_fichier / 10
