"""Point d'entrée : lance l'analyse des logs depuis le terminal."""

import argparse


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


def main() -> None:
    """Lance le programme."""
    args = parse_args()
    print(f"Fichier de logs : {args.input}")
    print(f"Blacklist : {args.blacklist}")
    print(f"Échecs max avant alerte : {args.max_echecs}")


if __name__ == "__main__":
    main()