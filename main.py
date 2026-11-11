"""Point d'entrée : lance l'analyse des logs depuis le terminal."""

import argparse
import logging
import os
import time

from moteur_traitement.ingestion import (
    load_blacklist,
    parse_line,
    read_many_files,
)
from moteur_traitement.pipeline import is_valid_ip, normalize
from moteur_traitement.analysis import Stats
from moteur_traitement.rules import (
    AlertSummary,
    PortScanRule,
    RuleChecker,
    apply_security_rules,
    rule_blacklisted_ip,
    rule_critical_level,
    rule_injection,
    rule_sensitive_account,
)
from moteur_traitement.audit import audit_scope


def parse_args() -> argparse.Namespace:
    """Lit les options données dans le terminal."""
    parser = argparse.ArgumentParser(description="Analyse de logs")
    parser.add_argument(
        "--input",
        default="data/echantillon/server.log",
        help="fichier de logs à analyser",
    )
    parser.add_argument(
        "--blacklist",
        default="data/echantillon/blacklist.txt",
        help="liste noire (une IP par ligne)",
    )
    parser.add_argument(
        "--max-echecs",
        type=int,
        default=5,
        help="nombre d'échecs de connexion d'affilée avant une alerte",
    )
    return parser.parse_args()


def setup_logging() -> None:
    """Affiche tous les messages de débogage, à chaque lancement."""
    logging.basicConfig(
        level=logging.DEBUG,
        format="[%(levelname)s] %(message)s",
    )


def show_progress(done: int, total: int, nb_lines: int, start: float) -> None:
    """Affiche une barre d'avancement sur une seule ligne."""
    ratio = min(done / total, 1) if total else 1
    bar = "#" * int(ratio * 30) + "-" * (30 - int(ratio * 30))
    elapsed = time.time() - start
    speed = nb_lines / elapsed if elapsed else 0
    remaining = elapsed * (1 - ratio) / ratio if ratio else 0
    print(
        f"\r[{bar}] {ratio:6.1%}  {nb_lines:,} lignes  "
        f"{speed:,.0f} lignes/s  reste ~{remaining:.0f} s   ",
        end="",
        flush=True,
    )


def read_and_count(
    path: str,
    analyse: Stats,
    check: RuleChecker,
    summary: AlertSummary,
) -> dict[str, int]:
    """Lit le fichier ligne par ligne, nettoie et analyse les records."""
    total = os.path.getsize(path)
    stats = {"lues": 0, "rejetees": 0, "ip_invalides": 0, "gardees": 0}
    done = 0
    start = time.time()
    for line in read_many_files(path):
        done += len(line)
        stats["lues"] += 1

        # Module 1 : découpe la ligne (None si elle est cassée).
        record = parse_line(line)
        if record is None:
            stats["rejetees"] += 1
        # Module 2 : retire les IP invalides, puis nettoie les valeurs.
        elif not is_valid_ip(record["ip"]):
            stats["ip_invalides"] += 1
        else:
            record = normalize(record)
            stats["gardees"] += 1
            # Module 3 : ajoute le record à toutes les analyses.
            analyse.update(record)
            # Module 4 : applique les règles de sécurité.
            summary.update(check(record))
        if stats["lues"] % 50_000 == 0:
            show_progress(done, total, stats["lues"], start)

    show_progress(total, total, stats["lues"], start)
    print()
    return stats


def print_summary(stats: dict[str, int]) -> None:
    """Affiche le bilan du nettoyage."""
    lues = stats["lues"]
    if lues == 0:
        print("\nAucune ligne lue.")
        return
    rejetees = stats["rejetees"]
    ip_invalides = stats["ip_invalides"]
    print("\nBilan du nettoyage :")
    print(f"  Lignes lues           : {lues:>12,}")
    print(f"  Lignes rejetées       : {rejetees:>12,}"
          f"  ({rejetees / lues:.1%})")
    print(f"  IP invalides retirées : {ip_invalides:>12,}"
          f"  ({ip_invalides / lues:.1%})")
    print(f"  Lignes gardées        : {stats['gardees']:>12,}")


def print_analysis(analyse: Stats, blacklist: frozenset[str]) -> None:
    """Affiche les résultats de l'analyse (Module 3)."""
    comparaison = analyse.compare_with_blacklist(blacklist)
    actives = comparaison["intersection"]
    print("\nRésultats de l'analyse :")
    print(f"  IP différentes          : {len(analyse.ips):>10,}")
    print(f"  IP en erreur            : {len(analyse.error_ips):>10,}")
    print(f"  IP blacklistées actives : {len(actives):>10,}")
    print(f"  Attaques force brute    : {len(analyse.alerts):>10,}")
    print("\n  Logs par niveau :")
    for level in ("INFO", "WARNING", "ERROR", "CRITICAL"):
        print(f"    {level:<10} {analyse.by_level[level]:>10,}")


def print_alerts(summary: AlertSummary, scan_rule: PortScanRule) -> None:
    """Affiche le bilan des alertes de sécurité (Module 4)."""
    print("\nAlertes de sécurité :")
    print(f"  Total                   : {summary.total:>10,}")
    for rule, nb in summary.by_rule.items():
        print(f"    {rule:<21} {nb:>10,}")
    print(f"  IP sanctionnées (scan)  : {len(scan_rule.bans()):>10,}")


def main() -> None:
    """Lance le programme."""
    setup_logging()
    args = parse_args()
    logging.debug("Options reçues : %s", vars(args))

    if not os.path.exists(args.input):
        logging.error("Fichier de logs introuvable : %s", args.input)
        return
    if not os.path.exists(args.blacklist):
        logging.error("Blacklist introuvable : %s", args.blacklist)
        return

    blacklist = load_blacklist(args.blacklist)
    logging.debug("Blacklist chargée : %d IP", len(blacklist))

    analyse = Stats(args.max_echecs)
    scan_rule = PortScanRule()
    check = apply_security_rules(
        rule_blacklisted_ip,
        rule_injection,
        rule_sensitive_account,
        rule_critical_level,
        scan_rule,
        blacklist=blacklist,
    )
    summary = AlertSummary()

    print(f"Analyse de {args.input}...")
    stats = read_and_count(args.input, analyse, check, summary)
    analyse.log_summary()
    summary.log_summary()
    print_summary(stats)
    print_analysis(analyse, blacklist)
    print_alerts(summary, scan_rule)
    # Module 4 : audit des variables en mémoire (globals / locals).
    alerts = summary.as_dict()
    alerts["bans"] = scan_rule.bans()
    audit_scope(globals(), locals(), alerts, "audit_report.json")
    print("\nRapport d'audit : audit_report.json")


if __name__ == "__main__":
    main()
