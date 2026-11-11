"""Module 3 : agrégation des logs et détection de force brute.

- Les fonctions reçoivent tous les records d'un coup.
- La classe Stats reçoit les records un par un avec update(record),
  pour la boucle unique de main.py.
"""

import logging
from collections import defaultdict
from collections.abc import Iterable

logger = logging.getLogger(__name__)


def error_ips(records: Iterable[dict]) -> set[str]:
    """Renvoie les IP uniques ayant un niveau ERROR ou CRITICAL."""
    ips = set()
    for record in records:
        if record["level"] in ("ERROR", "CRITICAL"):
            ips.add(record["ip"])
    return ips


def compare_with_blacklist(
    ips: set[str], blacklist: frozenset[str]
) -> dict[str, set[str]]:
    """Compare les IP actives à la liste noire."""
    return {
        "union": ips | blacklist,
        "intersection": ips & blacklist,
        "difference": ips - blacklist,
        "symmetric_difference": ips ^ blacklist,
    }


def count_by(records: Iterable[dict], key: str) -> defaultdict[str, int]:
    """Compte les records selon la valeur de la clé donnée."""
    counts = defaultdict(int)
    for record in records:
        counts[record[key]] += 1
    return counts


class Stats:
    """Regroupe toutes les analyses du Module 3.

    main.py appelle update(record) pour chaque record : le fichier
    n'est lu qu'une seule fois.
    """

    def __init__(self, threshold: int = 5) -> None:
        self.threshold = threshold
        self.total = 0
        self.ips = set()
        self.error_ips = set()
        self.by_level = defaultdict(int)
        self.by_user = defaultdict(int)
        self.failures = defaultdict(int)
        self.alerts = []

    def update(self, record: dict) -> None:
        """Ajoute un record à toutes les analyses."""
        self.total += 1
        self.ips.add(record["ip"])
        self.by_level[record["level"]] += 1
        self.by_user[record["user"]] += 1
        if record["level"] in ("ERROR", "CRITICAL"):
            self.error_ips.add(record["ip"])
        self.check_login(record)

    def check_login(self, record: dict) -> None:
        """Compte les échecs de connexion consécutifs d'une IP."""
        payload = record["payload"]
        if not isinstance(payload, dict):
            return
        if payload.get("action") != "login":
            return

        key = (record["ip"], record["user"])
        if payload.get("status") == "failed":
            self.failures[key] += 1
            # == et pas >= : une seule alerte par attaque.
            if self.failures[key] == self.threshold:
                self.alerts.append(key)
        else:
            # Connexion réussie : on remet le compteur à zéro.
            self.failures.pop(key, None)

    def compare_with_blacklist(
        self, blacklist: frozenset[str]
    ) -> dict[str, set[str]]:
        """Compare toutes les IP vues à la liste noire."""
        return compare_with_blacklist(self.ips, blacklist)

    def log_summary(self) -> None:
        """Écrit un seul message de débogage avec le bilan."""
        logger.debug(
            "Module 3 : %d records, %d IP en erreur, %d alertes",
            self.total,
            len(self.error_ips),
            len(self.alerts),
        )


def detect_brute_force(
    records: Iterable[dict], threshold: int = 5, batch_size: int = 1000
) -> list[tuple[str, str | None]]:
    """Détecte les attaques par force brute, paquet par paquet."""
    stats = Stats(threshold)
    records = iter(records)
    end = False

    while not end:
        # 1. On remplit un paquet de records.
        batch = []
        for record in records:
            batch.append(record)
            if len(batch) == batch_size:
                break  # paquet plein
        else:
            end = True  # pas de break : il n'y a plus de records

        # 2. On analyse le paquet.
        for record in batch:
            if not isinstance(record["payload"], dict):
                continue  # texte brut : ce n'est pas une connexion
            stats.check_login(record)

    return stats.alerts
