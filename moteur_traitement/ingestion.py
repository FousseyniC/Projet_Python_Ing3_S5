"""Module 1 : lecture paresseuse des logs et découpage des lignes en records.

Rien n'est jamais chargé en entier : les fichiers sont lus ligne par ligne
avec des générateurs, et chaque ligne est transformée en dictionnaire (ou en
None si elle est inutilisable) au moment où on la demande.

Ce module ne fait que le nettoyage structurel (découpage, types, dates,
niveaux, JSON). Le nettoyage des valeurs (casse, zéros des IP...) est fait
par le Module 2.
"""

from __future__ import annotations

import ast
import json
import logging
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from moteur_traitement.constants import (
    DATE_FORMATS,
    LEVEL_ALIASES,
    NULL_USERS,
    VALID_LEVELS,
)

logger = logging.getLogger(__name__)

Record = dict[str, Any]
PathLike = str | Path


def read_log_file(path: PathLike) -> Iterator[str]:
    """Renvoie les lignes du fichier une par une, sans rien filtrer.

    Les octets illisibles sont remplacés plutôt que de faire planter la
    lecture. Si le fichier n'existe pas, FileNotFoundError remonte dès la
    première ligne demandée.
    """
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line


def read_many_files(paths: PathLike | Iterable[PathLike]) -> Iterator[str]:
    """Enchaîne les lignes de plusieurs fichiers, dans l'ordre donné.

    Accepte aussi un chemin seul, le cas normal puisque les données tiennent
    dans un seul server.log. Un fichier absent ou illisible est signalé dans
    les logs puis ignoré.
    """
    # Sans ce test, une chaîne serait parcourue caractère par caractère.
    if isinstance(paths, (str, Path)):
        paths = [paths]
    for path in paths:
        try:
            yield from read_log_file(path)
        except OSError as exc:
            logger.warning("Fichier ignoré : %s (%s)", path, exc)


def parse_line(line: str) -> Record | None:
    """Transforme une ligne de log en record, ou renvoie None.

    Format attendu : date heure | niveau | IP | utilisateur | payload.
    La fonction ne lève jamais d'exception : toute ligne qu'on ne sait pas
    lire donne None.
    """
    line = line.strip()
    if not line:
        return None

    # maxsplit=4 : un « | » à l'intérieur du payload ne le coupe pas.
    parts = [part.strip() for part in line.split("|", 4)]
    if len(parts) != 5:
        return None
    date_text, level_text, ip, user_text, payload_text = parts

    timestamp = _parse_timestamp(date_text)
    if timestamp is None:
        return None
    level = _parse_level(level_text)
    if level is None:
        return None
    if not ip:
        return None

    payload = _parse_payload(payload_text)
    return {
        "timestamp": timestamp,
        "level": level,
        "ip": ip,
        "user": _parse_user(user_text),
        "payload": payload,
        "connection": _extract_connection(ip, payload),
    }


def read_records(paths: PathLike | Iterable[PathLike]) -> Iterator[Record | None]:
    """Lit les fichiers et renvoie leurs records au fil de l'eau (None compris)."""
    return map(parse_line, read_many_files(paths))


def load_blacklist(path: PathLike) -> frozenset[str]:
    """Charge la liste noire : une IP par ligne, lignes vides ignorées."""
    with open(path, encoding="utf-8") as f:
        return frozenset(ip for ip in (line.strip() for line in f) if ip)


def _parse_timestamp(text: str) -> datetime | None:
    # fromisoformat est très rapide et couvre la plupart des lignes (avec ou
    # sans T, avec millisecondes). strptime ne sert qu'en secours.
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        pass
    for date_format in DATE_FORMATS:
        try:
            return datetime.strptime(text, date_format)
        except ValueError:
            continue
    return None


def _parse_level(text: str) -> str | None:
    # « [error] », « warn », «   INFO   »... deviennent le niveau canonique.
    level = text.strip("[]").strip().upper()
    level = LEVEL_ALIASES.get(level, level)
    return level if level in VALID_LEVELS else None


def _parse_user(text: str) -> str | None:
    return None if text.lower() in NULL_USERS else text


def _parse_payload(text: str) -> dict | str:
    """Renvoie un dict si le payload est du JSON (ou un dict Python), sinon le texte."""
    if not text.startswith("{"):
        return text
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        # Les dicts écrits à la Python ({'port': 22}) ne sont pas du JSON valide.
        try:
            value = ast.literal_eval(text)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return text
    return value if isinstance(value, dict) else text


def _extract_connection(ip: str, payload: dict | str) -> tuple[str, int, str] | None:
    """Construit (ip, port, PROTOCOLE) si le payload contient un port et un protocole."""
    if not isinstance(payload, dict):
        return None
    # Les clés peuvent être en majuscule (« Port », « Protocol »).
    fields = {str(key).lower(): value for key, value in payload.items()}
    if "port" not in fields or "protocol" not in fields:
        return None
    try:
        port = int(fields["port"])
    except (TypeError, ValueError, OverflowError):
        return None
    return (ip, port, str(fields["protocol"]).upper())
