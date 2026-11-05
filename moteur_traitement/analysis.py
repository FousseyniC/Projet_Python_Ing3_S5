"""Module 3 : agrégation des logs et détection de force brute."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from itertools import islice

from moteur_traitement.ingestion import Record


def error_ips(records: Iterable[Record]) -> set[str]:
    """Renvoie les IP uniques ayant un niveau ERROR ou CRITICAL."""
    ips = set()
    for record in records:
        if record["level"] in ("ERROR", "CRITICAL"):
            ips.add(record["ip"])
    return ips