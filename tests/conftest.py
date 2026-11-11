"""Données d'exemple partagées par tous les tests.

Fichier commun : ajoute tes fixtures, mais ne modifie pas celles des autres.
"""

from datetime import datetime

import pytest


@pytest.fixture
def sample_lines() -> list[str]:
    """Lignes propres."""
    return [
        '2026-01-01 00:26:31 | WARNING | 197.125.255.225 | farid49 | '
        '{"action": "login", "status": "failed", '
        '"port": 22, "protocol": "SSH"}',
        '2026-01-01 00:26:31 | ERROR | 22.128.79.209 | david49 | '
        '{"method": "GET", "url": "/api/products", "status": 503, '
        '"duration_ms": 14479, "port": 443, "protocol": "HTTPS"}',
        "2026-01-01 00:26:46 | CRITICAL | 77.185.106.206 | postgres | "
        "Access denied to /etc/shadow",
        "2026-01-01 00:26:31 | INFO | 85.87.30.172 | - | kernel: eth1 link up",
    ]


@pytest.fixture
def sample_records() -> list[dict]:
    """Résultat attendu de parse_line pour sample_lines."""
    return [
        {
            "timestamp": datetime(2026, 1, 1, 0, 26, 31),
            "level": "WARNING",
            "ip": "197.125.255.225",
            "user": "farid49",
            "payload": {"action": "login", "status": "failed",
                        "port": 22, "protocol": "SSH"},
            "connection": ("197.125.255.225", 22, "SSH"),
        },
        {
            "timestamp": datetime(2026, 1, 1, 0, 26, 31),
            "level": "ERROR",
            "ip": "22.128.79.209",
            "user": "david49",
            "payload": {
                "method": "GET",
                "url": "/api/products",
                "status": 503,
                "duration_ms": 14479,
                "port": 443,
                "protocol": "HTTPS",
            },
            "connection": ("22.128.79.209", 443, "HTTPS"),
        },
        {
            "timestamp": datetime(2026, 1, 1, 0, 26, 46),
            "level": "CRITICAL",
            "ip": "77.185.106.206",
            "user": "postgres",
            "payload": "Access denied to /etc/shadow",
            "connection": None,
        },
        {
            "timestamp": datetime(2026, 1, 1, 0, 26, 31),
            "level": "INFO",
            "ip": "85.87.30.172",
            "user": None,
            "payload": "kernel: eth1 link up",
            "connection": None,
        },
    ]


@pytest.fixture
def dirty_lines() -> list[tuple[str, dict]]:
    """Lignes sales mais réparables : (ligne, champs attendus)."""
    login = ('{"action": "login", "status": "failed", '
             '"port": 22, "protocol": "SSH"}')
    return [
        # Séparateurs
        (f"2026-01-01 00:26:31|INFO  |  10.0.0.5\t|\talice1 | {login}",
         {"level": "INFO", "ip": "10.0.0.5", "user": "alice1"}),
        # Espaces et fin de ligne Windows
        (f"2026-01-01 00:26:31 | INFO | 10.0.0.5 | alice1 | {login}   \r\n",
         {"payload": {"action": "login", "status": "failed",
                      "port": 22, "protocol": "SSH"}}),
        # Dates
        (f"2026-01-01T00:26:31 | INFO | 10.0.0.5 | alice1 | {login}",
         {"timestamp": datetime(2026, 1, 1, 0, 26, 31)}),
        (f"2026/01/01 00:26:31 | INFO | 10.0.0.5 | alice1 | {login}",
         {"timestamp": datetime(2026, 1, 1, 0, 26, 31)}),
        (f"01/01/2026 00:26:31 | INFO | 10.0.0.5 | alice1 | {login}",
         {"timestamp": datetime(2026, 1, 1, 0, 26, 31)}),
        (f"2026-01-01 00:26:31.482 | INFO | 10.0.0.5 | alice1 | {login}",
         {"timestamp": datetime(2026, 1, 1, 0, 26, 31, 482000)}),
        # Niveaux
        (f"2026-01-01 00:26:31 | warn | 10.0.0.5 | alice1 | {login}",
         {"level": "WARNING"}),
        (f"2026-01-01 00:26:31 | [CRITICAL] | 10.0.0.5 | alice1 | {login}",
         {"level": "CRITICAL"}),
        (f"2026-01-01 00:26:31 | err | 10.0.0.5 | alice1 | {login}",
         {"level": "ERROR"}),
        # Utilisateur vide
        (f"2026-01-01 00:26:31 | INFO | 10.0.0.5 | NULL | {login}",
         {"user": None}),
        (f"2026-01-01 00:26:31 | INFO | 10.0.0.5 | N/A | {login}",
         {"user": None}),
        (f"2026-01-01 00:26:31 | INFO | 10.0.0.5 |  | {login}",
         {"user": None}),
        # JSON avec des quotes simples
        ("2026-01-01 00:26:31 | WARNING | 10.0.0.5 | alice1 | "
         "{'action': 'login', 'status': 'failed', "
         "'port': 22, 'protocol': 'SSH'}",
         {"connection": ("10.0.0.5", 22, "SSH")}),
        # Clés JSON en majuscule
        ("2026-01-01 00:26:31 | WARNING | 10.0.0.5 | alice1 | "
         '{"Action": "login", "Status": "failed", '
         '"Port": 22, "Protocol": "ssh"}',
         {"connection": ("10.0.0.5", 22, "SSH")}),
        # JSON cassé : gardé en texte
        ('2026-01-01 00:26:31 | WARNING | 10.0.0.5 | alice1 | {"action": "lo',
         {"payload": '{"action": "lo', "connection": None}),
        # Corrigés plus tard par le Module 2
        (f"2026-01-01 00:26:31 | INFO | 10.0.0.5 | BOB46 | {login}",
         {"user": "BOB46"}),
        (f"2026-01-01 00:26:31 | INFO | 010.000.000.005 | alice1 | {login}",
         {"ip": "010.000.000.005"}),
    ]


@pytest.fixture
def invalid_lines() -> list[str]:
    """Lignes inutilisables : parse_line renvoie None."""
    return [
        "",
        "   ",
        "\t",
        # Ligne coupée
        "2026-01-01 00:26:31 | INFO | 85.87.3",
        # Niveau inconnu
        "2026-01-01 00:26:31 | DEBUG | 10.0.0.5 | alice1 | test",
        # Dates fausses
        "2026-13-45 99:99:99 | INFO | 10.0.0.5 | alice1 | test",
        "yesterday | INFO | 10.0.0.5 | alice1 | test",
        # 4 champs au lieu de 5
        "2026-01-01 00:26:31 | INFO | 10.0.0.5 | alice1",
        # Lignes parasites
        "#### log rotated ####",
        "\x00\x00\x00\x00",
        "<<<EOF>>>",
    ]


@pytest.fixture
def injection_record() -> dict:
    """Tentative d'injection SQL, déjà parsée (Module 4)."""
    return {
        "timestamp": datetime(2026, 1, 1, 0, 30, 12),
        "level": "WARNING",
        "ip": "45.33.12.9",
        "user": None,
        "payload": {
            "attack": "injection",
            "content": "' OR 1=1 --",
            "url": "/login",
            "port": 443,
            "protocol": "HTTPS",
        },
        "connection": ("45.33.12.9", 443, "HTTPS"),
    }


@pytest.fixture
def bad_ip_lines() -> list[str]:
    """IP invalides : gardées par le Module 1, retirées par le Module 2."""
    return [
        "2026-01-01 00:26:31 | INFO | 999.300.1.1 | alice1 | test",
        "2026-01-01 00:26:31 | INFO | localhost | alice1 | test",
        "2026-01-01 00:26:31 | INFO | unknown | alice1 | test",
        "2026-01-01 00:26:31 | INFO | 10.0.0 | alice1 | test",
    ]
