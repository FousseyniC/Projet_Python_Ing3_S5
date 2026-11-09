"""Module 2 : nettoyage et routage des enregistrements."""

import logging
from collections.abc import Iterable, Iterator
from typing import Any
from moteur_traitement.constants import LEVEL_ALIASES, NULL_USERS

logger = logging.getLogger(__name__)

Record = dict[str, Any]


def remove_invalid(
    records: Iterable[Record | None],
) -> Iterator[Record]:
    """Supprime les None produits par parse_line() (lignes invalides)."""
    return filter(None, records)

def _clean(value: Any) -> Any:
    """Enlève les espaces et transforme les valeurs nulles en None."""
    if isinstance(value, str):
        value = value.strip()
        if value.lower() in NULL_USERS:
            return None
    return value


def normalize(record: Record) -> Record:
    """Nettoie un enregistrement : espaces, niveau, valeurs nulles."""
    try:
        cleaned = dict(record)  # copie : l'original reste intact
        level = _clean(record.get("level"))
        if isinstance(level, str):
            level = level.upper()
            level = LEVEL_ALIASES.get(level, level)
        cleaned["level"] = level
        cleaned["user"] = _clean(record.get("user"))
        cleaned["ip"] = _clean(record.get("ip"))
    except (AttributeError, TypeError, ValueError):
        # Entrée inattendue : le niveau None la fera rejeter plus loin.
        return {"level": None}
    return cleaned
