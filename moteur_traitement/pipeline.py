"""Module 2 : nettoyage et routage des enregistrements."""

import logging
from collections.abc import Iterable, Iterator
from typing import Any

logger = logging.getLogger(__name__)

Record = dict[str, Any]


def remove_invalid(
    records: Iterable[Record | None],
) -> Iterator[Record]:
    """Supprime les None produits par parse_line() (lignes invalides)."""
    return filter(None, records)
