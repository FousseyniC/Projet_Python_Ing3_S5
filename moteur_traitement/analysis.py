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


def compare_with_blacklist(
    ips: set[str], blacklist: frozenset[str]
) -> dict[str, set[str]]:
    """Compare les IP actives à la liste noire avec les opérations d'ensembles."""
    return {
        "union": ips | blacklist,
        "intersection": ips & blacklist,
        "difference": ips - blacklist,
        "symmetric_difference": ips ^ blacklist,
    }


def count_by(records: Iterable[Record], key: str) -> defaultdict[str, int]:
    """Compte les records selon la valeur de la clé donnée."""
    counts: defaultdict[str, int] = defaultdict(int)
    for record in records:
        counts[record[key]] += 1
    return counts