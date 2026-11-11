"""Module 4 : moteur de règles de sécurité.

Une règle reçoit un record et la configuration, puis renvoie une alerte
ou None. apply_security_rules() regroupe les règles et renvoie une
fonction check(record), appelée sur chaque record dans main.py.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from moteur_traitement.ingestion import Record

logger = logging.getLogger(__name__)

Alert = dict[str, Any]
Rule = Callable[..., Alert | None]
RuleChecker = Callable[[Record], list[Alert]]

# Poids de chaque gravité dans le score d'une IP.
SEVERITY_WEIGHT = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

SENSITIVE_ACCOUNTS = frozenset(
    {"admin", "root", "test", "guest", "oracle", "postgres"}
)

# Motifs d'attaque connus. Le nom du groupe donne le type d'attaque.
INJECTION_PATTERN = re.compile(
    r"(?P<SQL>'\s*or\s+1\s*=\s*1|;\s*drop\s+table)"
    r"|(?P<XSS><script)"
    r"|(?P<path_traversal>\.\./)"
    r"|(?P<Log4Shell>\$\{jndi:)",
    re.IGNORECASE,
)

DEFAULT_SCAN_THRESHOLD = 10

# Sanctions d'un scan : 24 h, 48 h, 1 semaine, 1 mois, puis le double.
DEFAULT_BAN_STEPS = (
    timedelta(hours=24),
    timedelta(hours=48),
    timedelta(weeks=1),
    timedelta(days=30),
)

# Après 6 mois sans scan, on oublie les récidives d'une IP.
DEFAULT_FORGET_AFTER = timedelta(days=180)


def _make_alert(
    rule: str, severity: str, record: Record, detail: str
) -> Alert:
    """Construit une alerte au format commun à toutes les règles."""
    return {
        "rule": rule,
        "severity": severity,
        "timestamp": record["timestamp"],
        "ip": record["ip"],
        "user": record["user"],
        "detail": detail,
    }


def _get(payload: dict, key: str) -> str:
    """Lit une clé du payload (« status » ou « Status »), en minuscule."""
    value = payload.get(key, payload.get(key.capitalize()))
    return str(value).lower()


def _payload_text(payload: dict | str) -> str:
    """Renvoie le texte du payload dans lequel chercher une attaque."""
    if isinstance(payload, str):
        return payload
    return " ".join(v for v in payload.values() if isinstance(v, str))


def _is_internal(ip: str) -> bool:
    """Dit si l'IP vient du réseau interne (192.168.x.x par exemple)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def rule_blacklisted_ip(record: Record, **config: Any) -> Alert | None:
    """Alerte si l'IP est dans la liste noire."""
    # Pas de valeur par défaut : sans blacklist, on veut une erreur.
    if record["ip"] not in config["blacklist"]:
        return None
    return _make_alert(
        "blacklisted_ip", "MEDIUM", record, "IP présente dans la blacklist"
    )


def rule_injection(record: Record, **config: Any) -> Alert | None:
    """Alerte si le payload contient un motif d'injection connu."""
    payload = record["payload"]
    match = INJECTION_PATTERN.search(_payload_text(payload))
    if match is None:
        return None
    detail = f"{match.lastgroup} : {match.group(0)!r}"
    if isinstance(payload, dict) and "url" in payload:
        detail += f" sur {payload['url']}"
    return _make_alert("injection", "HIGH", record, detail)


def rule_sensitive_account(record: Record, **config: Any) -> Alert | None:
    """Alerte si un compte sensible se connecte depuis l'extérieur."""
    payload = record["payload"]
    if not isinstance(payload, dict) or record["user"] is None:
        return None
    user = record["user"].strip('"').lower()
    accounts = config.get("sensitive_accounts", SENSITIVE_ACCOUNTS)
    if user not in accounts:
        return None
    if _get(payload, "action") != "login":
        return None
    if _get(payload, "status") != "success":
        return None
    if _is_internal(record["ip"]):
        return None
    return _make_alert(
        "sensitive_account",
        "MEDIUM",
        record,
        f"connexion réussie sur {user} depuis l'extérieur",
    )


def rule_critical_level(record: Record, **config: Any) -> Alert | None:
    """Alerte si l'événement est de niveau CRITICAL."""
    if record["level"] != "CRITICAL":
        return None
    return _make_alert("critical_level", "LOW", record, str(record["payload"]))


def ban_duration(offense: int, steps: tuple[timedelta, ...]) -> timedelta:
    """Durée de sanction du n-ième scan (offense commence à 1)."""
    if offense <= len(steps):
        return steps[offense - 1]
    # Au-delà de la liste, la durée double à chaque fois.
    return steps[-1] * 2 ** (offense - len(steps))


def _format_duration(duration: timedelta) -> str:
    """Écrit une durée en heures (moins de 3 jours) ou en jours."""
    hours = int(duration.total_seconds() // 3600)
    return f"{hours} h" if hours < 72 else f"{duration.days} j"


class PortScanRule:
    """Repère une IP qui essaie beaucoup de ports différents.

    Une seule ligne ne suffit pas : la règle se souvient des ports déjà
    essayés par chaque IP. Chaque scan donne une sanction plus longue
    que la précédente. L'objet s'appelle comme une fonction.
    """

    def __init__(self) -> None:
        self.ports: defaultdict[str, set[int]] = defaultdict(set)
        self.offenses: dict[str, int] = {}
        self.banned_until: dict[str, datetime] = {}

    def __call__(self, record: Record, **config: Any) -> Alert | None:
        payload = record["payload"]
        connection = record["connection"]
        if connection is None or not isinstance(payload, dict):
            return None
        if _get(payload, "status") != "blocked":
            return None

        ip, port, _ = connection
        now = record["timestamp"]
        banned = self.banned_until.get(ip)
        if banned is not None and now < banned:
            return None  # déjà sanctionnée

        self.ports[ip].add(port)
        threshold = config.get("scan_threshold", DEFAULT_SCAN_THRESHOLD)
        if len(self.ports[ip]) < threshold:
            return None

        # Seuil atteint : on repart de zéro port pour la prochaine fois.
        del self.ports[ip]
        forget_after = config.get("forget_after", DEFAULT_FORGET_AFTER)
        if banned is not None and now - banned >= forget_after:
            self.offenses.pop(ip, None)  # longtemps sans scan : on oublie

        offense = self.offenses.get(ip, 0) + 1
        self.offenses[ip] = offense
        steps = config.get("ban_steps", DEFAULT_BAN_STEPS)
        duration = ban_duration(offense, steps)
        self.banned_until[ip] = now + duration
        return _make_alert(
            "port_scan",
            "HIGH",
            record,
            f"scan n°{offense} ({threshold} ports), sanction "
            f"{_format_duration(duration)} jusqu'au "
            f"{now + duration:%Y-%m-%d %H:%M}",
        )

    def bans(self) -> list[dict[str, Any]]:
        """Liste des IP sanctionnées, les plus récidivistes d'abord."""
        ranked = sorted(self.offenses.items(), key=lambda item: -item[1])
        return [
            {
                "ip": ip,
                "offenses": offenses,
                "banned_until": self.banned_until[ip],
            }
            for ip, offenses in ranked
        ]


def apply_security_rules(*rules: Rule, **config: Any) -> RuleChecker:
    """Prépare le moteur et renvoie check(record).

    rules : les fonctions de sécurité, passées sans les appeler.
    config : les réglages donnés à chaque règle (ex. blacklist=...).
    """
    if not rules:
        raise ValueError("au moins une règle est nécessaire")
    logger.debug(
        "Moteur de règles : %d règles, options %s", len(rules), sorted(config)
    )

    def check(record: Record) -> list[Alert]:
        """Applique toutes les règles à un record."""
        alerts = []
        for rule in rules:
            alert = rule(record, **config)
            if alert is not None:
                alerts.append(alert)
        return alerts

    return check


class IpProfile:
    """Ce que l'on sait d'une IP qui a déclenché des alertes."""

    def __init__(self, timestamp: datetime) -> None:
        self.counts: defaultdict[str, int] = defaultdict(int)
        self.first_seen = timestamp
        self.last_seen = timestamp

    def add(self, alert: Alert) -> None:
        """Ajoute une alerte au profil."""
        self.counts[alert["rule"]] += 1
        self.first_seen = min(self.first_seen, alert["timestamp"])
        self.last_seen = max(self.last_seen, alert["timestamp"])


class AlertSummary:
    """Bilan des alertes, avec une mémoire limitée.

    Toutes les alertes sont comptées, mais on ne garde que quelques
    exemples par règle et une fiche par IP.
    """

    def __init__(self, max_samples: int = 20, top: int = 50) -> None:
        self.max_samples = max_samples
        self.top = top
        self.total = 0
        self.by_rule: defaultdict[str, int] = defaultdict(int)
        self.by_severity: defaultdict[str, int] = defaultdict(int)
        self.samples: defaultdict[str, list[Alert]] = defaultdict(list)
        self.rule_severity: dict[str, str] = {}
        self.by_ip: dict[str, IpProfile] = {}

    def update(self, alerts: list[Alert]) -> None:
        """Ajoute au bilan les alertes d'un record."""
        for alert in alerts:
            rule = alert["rule"]
            self.total += 1
            self.by_rule[rule] += 1
            self.by_severity[alert["severity"]] += 1
            self.rule_severity[rule] = alert["severity"]
            if len(self.samples[rule]) < self.max_samples:
                self.samples[rule].append(alert)

            ip = alert["ip"]
            if ip not in self.by_ip:
                self.by_ip[ip] = IpProfile(alert["timestamp"])
            self.by_ip[ip].add(alert)

    def score(self, profile: IpProfile) -> int:
        """Score d'une IP : chaque règle compte une seule fois."""
        return sum(
            SEVERITY_WEIGHT[self.rule_severity[rule]]
            for rule in profile.counts
        )

    def top_ips(self) -> list[dict[str, Any]]:
        """Les IP les plus suspectes, de la pire à la moins grave."""
        ranked = sorted(
            self.by_ip.items(),
            key=lambda item: (
                self.score(item[1]),
                sum(item[1].counts.values()),
            ),
            reverse=True,
        )
        return [
            {
                "ip": ip,
                "score": self.score(profile),
                "rules": dict(profile.counts),
                "first_seen": profile.first_seen,
                "last_seen": profile.last_seen,
            }
            for ip, profile in ranked[: self.top]
        ]

    def multi_rule_ips(self) -> int:
        """Nombre d'IP qui déclenchent au moins deux règles."""
        return sum(1 for p in self.by_ip.values() if len(p.counts) >= 2)

    def as_dict(self) -> dict[str, Any]:
        """Renvoie le bilan, prêt à mettre dans le rapport."""
        return {
            "total": self.total,
            "by_rule": dict(self.by_rule),
            "by_severity": dict(self.by_severity),
            "ips_count": len(self.by_ip),
            "multi_rule_ips": self.multi_rule_ips(),
            "top_ips": self.top_ips(),
            "samples": dict(self.samples),
        }

    def log_summary(self) -> None:
        """Écrit un seul message de débogage avec le bilan."""
        logger.debug(
            "Module 4 : %d alertes, %d IP dont %d sur plusieurs règles",
            self.total,
            len(self.by_ip),
            self.multi_rule_ips(),
        )
