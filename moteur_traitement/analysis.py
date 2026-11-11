"""Module 3 : agrégation des logs et détection de force brute.

- Les fonctions reçoivent tous les records d'un coup.
- La classe Stats reçoit les records un par un avec update(record),
  pour la boucle unique de main.py.
"""

import logging
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Un échec plus vieux que 5 minutes ne fait plus partie d'une attaque.
WINDOW = timedelta(minutes=5)


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
        self.errors_by_ip = defaultdict(int)
        self.by_level = defaultdict(int)
        self.by_user = defaultdict(int)
        self.failures = defaultdict(int)
        self.last_seen = {}
        self.alerts = []

    def update(self, record: dict) -> None:
        """Ajoute un record à toutes les analyses."""
        self.total += 1
        # Tous les 100 000 records, on oublie les vieux échecs.
        if self.total % 100_000 == 0:
            self.forget_old(record["timestamp"])
        self.ips.add(record["ip"])
        self.by_level[record["level"]] += 1
        self.by_user[record["user"]] += 1
        if record["level"] in ("ERROR", "CRITICAL"):
            self.error_ips.add(record["ip"])
            self.errors_by_ip[record["ip"]] += 1
        self.check_login(record)

    def check_login(self, record: dict) -> None:
        """Compte les échecs de connexion consécutifs d'une IP."""
        payload = record["payload"]
        if not isinstance(payload, dict):
            return
        if payload.get("action") != "login":
            return

        key = (record["ip"], record["user"])
        status = payload.get("status")
        if status == "failed":
            # Dernier échec trop ancien : c'est une nouvelle série.
            last = self.last_seen.get(key)
            if last is not None and record["timestamp"] - last > WINDOW:
                self.failures[key] = 0
            self.failures[key] += 1
            self.last_seen[key] = record["timestamp"]
            # == et pas >= : une seule alerte par attaque.
            if self.failures[key] == self.threshold:
                self.alerts.append(key)
        elif status == "success":
            # Connexion réussie : on remet le compteur à zéro.
            self.failures.pop(key, None)
            self.last_seen.pop(key, None)

    def forget_old(self, now: datetime) -> None:
        """Oublie les échecs de connexion de plus de 5 minutes."""
        old_keys = []
        for key, when in self.last_seen.items():
            if now - when > WINDOW:
                old_keys.append(key)
        for key in old_keys:
            del self.failures[key]
            del self.last_seen[key]

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
            stats.update(record)

    return stats.alerts
