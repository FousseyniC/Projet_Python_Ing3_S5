"""Point d'entrée : lance l'analyse des logs depuis le terminal."""

import argparse
import logging
import os
import time
from collections import defaultdict
from collections.abc import Iterable, Iterator

from moteur_traitement.ingestion import (
    load_blacklist,
    parse_line_with_reason,
    read_many_files,
)
from moteur_traitement.pipeline import route, transform
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

ECHANTILLON = "data/echantillon/server.log"
COMPLET = "data/complet/server.log"


def parse_args() -> argparse.Namespace:
    """Lit les options données dans le terminal."""
    parser = argparse.ArgumentParser(description="Analyse de logs")
    # -i et -c ne peuvent pas être utilisés ensemble.
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "-i",
        "--input",
        default=ECHANTILLON,
        help="fichier de logs à analyser (par défaut : l'échantillon)",
    )
    source.add_argument(
        "-c",
        "--complet",
        action="store_true",
        help=f"analyse le jeu complet ({COMPLET})",
    )
    parser.add_argument(
        "-b",
        "--blacklist",
        help="liste noire (par défaut : blacklist.txt à côté des logs)",
    )
    parser.add_argument(
        "-m",
        "--max-echecs",
        type=int,
        default=5,
        help="nombre d'échecs de connexion d'affilée avant une alerte",
    )
    parser.add_argument(
        "-g",
        "--graphiques",
        action="store_true",
        help="crée les graphiques du rapport dans le dossier rapport/",
    )
    args = parser.parse_args()

    if args.complet:
        args.input = COMPLET
    # Sans -b, on prend le blacklist.txt du même dossier que les logs.
    if args.blacklist is None:
        dossier = os.path.dirname(args.input)
        args.blacklist = os.path.join(dossier, "blacklist.txt")
    return args


def setup_logging() -> None:
    """Affiche tous les messages de débogage, à chaque lancement."""
    logging.basicConfig(
        level=logging.DEBUG,
        format="[%(levelname)s] %(message)s",
    )
    # matplotlib et PIL écrivent beaucoup de messages : on les cache.
    logging.getLogger("matplotlib").setLevel(logging.WARNING)
    logging.getLogger("PIL").setLevel(logging.WARNING)


def short(n: float) -> str:
    """Écrit un grand nombre en version courte : 507 k, 33.4 M."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f} M"
    if n >= 1_000:
        return f"{n / 1_000:.0f} k"
    return str(int(n))


def format_duration(seconds: float) -> str:
    """Écrit une durée en minutes et secondes : 11 min 05 s."""
    minutes, secondes = divmod(int(seconds), 60)
    if minutes == 0:
        return f"{secondes} s"
    return f"{minutes} min {secondes:02d} s"


def show_progress(
    done: int,
    total: int,
    stats: dict[str, int],
    analyse: Stats,
    summary: AlertSummary,
    start: float,
) -> None:
    """Affiche l'avancement et les résultats en direct, sur une ligne."""
    ratio = min(done / total, 1) if total else 1
    bar = "#" * int(ratio * 10) + "-" * (10 - int(ratio * 10))
    elapsed = time.time() - start
    speed = stats["lues"] / elapsed if elapsed else 0
    remaining = elapsed * (1 - ratio) / ratio if ratio else 0
    # Temps restant arrondi à la minute, pour garder la ligne courte.
    if remaining >= 60:
        reste = f"{int(remaining // 60)} min"
    else:
        reste = f"{int(remaining)} s"
    print(
        f"\r[{bar}] {ratio:4.0%} {short(stats['lues'])} lignes "
        f"{short(speed)}/s reste {reste}"
        f" | rejets {short(stats['rejetees'])}"
        f" | IP inv. {short(ip_invalides(stats))}"
        f" | attaques {short(len(analyse.alerts))}"
        f" | alertes {short(summary.total)} ",
        end="",
        flush=True,
    )


def ip_invalides(stats: dict) -> int:
    """Lignes lues, ni rejetées ni gardées : retirées par le Module 2."""
    return stats["lues"] - stats["rejetees"] - stats["gardees"]


def count_lines(lines: Iterable[str], stats: dict) -> Iterator[str]:
    """Laisse passer les lignes en comptant leur nombre et leur taille."""
    for line in lines:
        stats["lues"] += 1
        stats["octets"] += len(line)
        yield line


def count_rejects(parsed: Iterable[tuple], stats: dict) -> Iterator[dict]:
    """Laisse passer les records valides, compte les rejets par cause."""
    for record, cause in parsed:
        if record is None:
            stats["rejetees"] += 1
            stats["causes"][cause] += 1
        else:
            yield record


def read_and_count(
    path: str,
    analyse: Stats,
    check: RuleChecker,
    summary: AlertSummary,
) -> dict:
    """Lit, nettoie et analyse les logs avec une chaîne de générateurs."""
    total = os.path.getsize(path)
    stats = {"lues": 0, "octets": 0, "rejetees": 0, "gardees": 0}
    stats["causes"] = defaultdict(int)
    stats["types"] = defaultdict(int)
    start = time.time()

    # Chaîne paresseuse : chaque ligne traverse toutes les étapes une par
    # une, sans que le fichier soit jamais chargé en mémoire.
    # Module 1 : yield / yield from, puis map pour parser chaque ligne.
    lines = count_lines(read_many_files(path), stats)
    parsed = map(parse_line_with_reason, lines)
    records = count_rejects(parsed, stats)
    # Module 2 : filter + lambda (IP invalides, niveaux), map (normalize).
    cleaned = transform(records)

    next_update = 50_000
    for record in cleaned:
        stats["gardees"] += 1
        # Module 2 : match-case pour classer le type d'événement.
        kind, _ = route(record)
        stats["types"][kind] += 1
        # Module 3 : ajoute le record à toutes les analyses.
        analyse.update(record)
        # Module 4 : applique les règles de sécurité.
        summary.update(check(record))
        if stats["lues"] >= next_update:
            show_progress(stats["octets"], total, stats, analyse,
                          summary, start)
            next_update += 50_000

    show_progress(total, total, stats, analyse, summary, start)
    print()
    stats["ip_invalides"] = ip_invalides(stats)
    return stats


def print_summary(stats: dict) -> None:
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
    # Détail des rejets, de la cause la plus fréquente à la plus rare.
    causes = sorted(
        stats["causes"].items(), key=lambda item: item[1], reverse=True
    )
    for cause, nb in causes:
        print(f"    - {cause:<26} {nb:>10,}")
    print(f"  IP invalides retirées : {ip_invalides:>12,}"
          f"  ({ip_invalides / lues:.1%})")
    print(f"  Lignes gardées        : {stats['gardees']:>12,}")


TYPE_NAMES = {
    "connection": "connexions réseau",
    "text": "messages texte",
    "action": "actions",
    "web": "requêtes web",
    "unknown": "autres",
}


def print_types(stats: dict) -> None:
    """Affiche les types d'événements trouvés par route() (match-case)."""
    print("\nTypes d'événements (match-case) :")
    types = sorted(
        stats["types"].items(), key=lambda item: item[1], reverse=True
    )
    for kind, nb in types:
        print(f"  {TYPE_NAMES.get(kind, kind):<22} {nb:>12,}")


def examples(ips: set[str]) -> str:
    """Renvoie 3 IP d'exemple, triées, pour l'affichage."""
    return ", ".join(sorted(ips)[:3])


def print_analysis(analyse: Stats, blacklist: frozenset[str]) -> None:
    """Affiche les résultats de l'analyse (Module 3)."""
    print("\nRésultats de l'analyse :")
    print(f"  IP différentes          : {len(analyse.ips):>10,}")
    print(f"  IP en erreur            : {len(analyse.error_ips):>10,}")
    print(f"  Attaques force brute    : {len(analyse.alerts):>10,}")

    # Les 4 opérations d'ensembles entre les IP vues et la blacklist.
    comparaison = analyse.compare_with_blacklist(blacklist)
    print("\n  IP vues comparées à la blacklist :")
    noms = {
        "union": "union (|)",
        "intersection": "intersection (&)",
        "difference": "différence (-)",
        "symmetric_difference": "diff. symétrique (^)",
    }
    for cle, nom in noms.items():
        ips = comparaison[cle]
        print(f"    {nom:<21} {len(ips):>8,}   ex. {examples(ips)}")

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


def count_attacks_by_ip(alerts: list) -> dict[str, int]:
    """Compte les attaques de force brute par IP source."""
    counts = defaultdict(int)
    for ip, _user in alerts:
        counts[ip] += 1
    return counts


def make_charts(analyse: Stats) -> None:
    """Crée les 3 graphiques du rapport avec les vrais chiffres."""
    # Import ici : matplotlib n'est chargé que si on demande les graphiques.
    from scripts.make_charts import (
        plot_attacks,
        plot_levels,
        plot_top_error_ips,
    )

    plot_levels(analyse.by_level)
    plot_top_error_ips(analyse.errors_by_ip)
    plot_attacks(count_attacks_by_ip(analyse.alerts))
    print("\nGraphiques enregistrés dans le dossier rapport/")


def main() -> None:
    """Lance le programme."""
    start = time.time()
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
    print_types(stats)
    print_analysis(analyse, blacklist)
    print_alerts(summary, scan_rule)
    # Module 4 : audit des variables en mémoire (globals / locals).
    alerts = summary.as_dict()
    alerts["bans"] = scan_rule.bans()
    audit_scope(globals(), locals(), alerts, "audit_report.json")
    print("\nRapport d'audit : audit_report.json")
    if args.graphiques:
        make_charts(analyse)

    print(f"\nTerminé en {format_duration(time.time() - start)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAnalyse interrompue par l'utilisateur.")
