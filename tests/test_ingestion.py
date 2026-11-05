"""Tests du Module 1 : lecture des fichiers et parsing des lignes."""

from types import GeneratorType

from moteur_traitement.ingestion import parse_line, read_log_file, read_many_files


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
    