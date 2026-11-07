"""Module 3 : agrégation des logs et détection de force brute.

Deux façons d'utiliser ce module :

- les fonctions (error_ips, count_by, detect_brute_force...) reçoivent
  tous les records d'un coup : pratique pour les tests et l'échantillon ;
- la classe Stats reçoit les records un par un avec update(record), pour
  la boucle unique de main.py (un seul passage sur les 15 Go).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable
from itertools import islice

from moteur_traitement.ingestion import Record

logger = logging.getLogger(__name__)

ERROR_LEVELS = frozenset({"ERROR", "CRITICAL"})

# Clé du compteur de force brute : (IP, utilisateur).
LoginKey = tuple[str, str | None]


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
    """Compare les IP actives à la liste noire."""
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


def login_status(record: Record) -> str | None:
    """Renvoie le statut d'une tentative de connexion, sinon None."""
    payload = record["payload"]
    if not isinstance(payload, dict):
        return None
    if payload.get("action") != "login":
        return None
    return payload.get("status")


class BruteForceDetector:
    """Compte les échecs de connexion consécutifs par (IP, utilisateur)."""

    def __init__(self, threshold: int = 5) -> None:
        self.threshold = threshold
        self.failures: defaultdict[LoginKey, int] = defaultdict(int)
        self.alerts: list[LoginKey] = []

    def feed(self, record: Record) -> bool:
        """Traite un record et renvoie True s'il déclenche une alerte."""
        status = login_status(record)
        if status is None:
            return False

        key = (record["ip"], record["user"])
        if status != "failed":
            # Une connexion réussie remet le compteur à zéro.
            self.failures.pop(key, None)
            return False

        self.failures[key] += 1
        # == et pas >= : une seule alerte par attaque.
        if self.failures[key] == self.threshold:
            self.alerts.append(key)
            return True
        return False


def detect_brute_force(
    records: Iterable[Record],
    threshold: int = 5,
    batch_size: int = 1000,
    max_alerts: int | None = None,
) -> list[LoginKey]:
    """Détecte les attaques par force brute dans tous les records.

    Le while lit les records par paquets, le for les examine un par un.
    """
    detector = BruteForceDetector(threshold)
    iterator = iter(records)

    while True:
        batch = list(islice(iterator, batch_size))
        if not batch:
            break

        for record in batch:
            if login_status(record) is None:
                continue  # pas une connexion : rien à compter
            detector.feed(record)
            if max_alerts is not None and len(detector.alerts) >= max_alerts:
                break
        else:
            continue  # paquet analysé en entier : on passe au suivant
        break  # le for a été interrompu : on arrête aussi le while

    logger.debug("Force brute : %d alertes", len(detector.alerts))
    return detector.alerts


class Stats:
    """Regroupe les analyses du Module 3, alimentées record par record.

    main.py appelle update(record) pour chaque record, dans sa boucle
    unique : le fichier n'est lu qu'une seule fois.
    """

    def __init__(self, threshold: int = 5) -> None:
        self.total = 0
        self.ips: set[str] = set()
        self.error_ips: set[str] = set()
        self.by_level: defaultdict[str, int] = defaultdict(int)
        self.by_user: defaultdict[str | None, int] = defaultdict(int)
        self.brute_force = BruteForceDetector(threshold)

    def update(self, record: Record) -> None:
        """Ajoute un record à toutes les analyses."""
        self.total += 1
        self.ips.add(record["ip"])
        self.by_level[record["level"]] += 1
        self.by_user[record["user"]] += 1
        if record["level"] in ERROR_LEVELS:
            self.error_ips.add(record["ip"])
        self.brute_force.feed(record)

    @property
    def alerts(self) -> list[LoginKey]:
        """Alertes de force brute trouvées jusqu'ici."""
        return self.brute_force.alerts

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
        