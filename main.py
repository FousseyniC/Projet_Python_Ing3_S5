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

from moteur_traitement.pipeline import is_valid_ip


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


def read_and_count(path: str) -> dict[str, int]:
    """Lit le fichier ligne par ligne, nettoie et compte les records."""
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
        # Module 2 : retire les IP invalides.
        elif not is_valid_ip(record["ip"]):
            stats["ip_invalides"] += 1
        else:
            stats["gardees"] += 1

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

    print(f"Analyse de {args.input}...")
    stats = read_and_count(args.input)
    print_summary(stats)


if __name__ == "__main__":
    main()
