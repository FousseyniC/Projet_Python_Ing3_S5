"""Graphiques du rapport, construits à partir de compteurs."""

import logging
from pathlib import Path

import matplotlib.pyplot as plt

logger = logging.getLogger(__name__)

REPORT_DIR = Path("report")
LEVELS = ("INFO", "WARNING", "ERROR", "CRITICAL")
COLORS = ("#4c9f70", "#e8a838", "#d9534f", "#7b1e1e")


def plot_levels(
    counts: dict[str, int],
    output_dir: Path = REPORT_DIR,
) -> Path:
    """Diagramme en barres du nombre de logs par niveau."""
    output_dir.mkdir(exist_ok=True)
    values = [counts.get(level, 0) for level in LEVELS]

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(LEVELS, values, color=COLORS)
    ax.set_title("Logs par niveau")
    ax.set_ylabel("Nombre de logs")
    fig.tight_layout()

    path = output_dir / "logs_par_niveau.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    logger.debug("Graphique enregistré : %s", path)
    return path

def _plot_top(
    counts: dict[str, int],
    title: str,
    filename: str,
    output_dir: Path,
    top: int = 10,
) -> Path:
    """Barres horizontales des `top` plus grandes valeurs."""
    output_dir.mkdir(exist_ok=True)
    best = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:top]
    labels = [key for key, _ in best]
    values = [value for _, value in best]

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.barh(labels, values, color="#d9534f")
    ax.invert_yaxis()  # le plus grand en haut
    ax.set_title(title)
    ax.set_xlabel("Nombre")
    fig.tight_layout()

    path = output_dir / filename
    fig.savefig(path, dpi=150)
    plt.close(fig)
    logger.debug("Graphique enregistré : %s", path)
    return path


def plot_top_error_ips(
    counts: dict[str, int],
    output_dir: Path = REPORT_DIR,
) -> Path:
    """Top 10 des IP ayant le plus de logs ERROR ou CRITICAL."""
    return _plot_top(
        counts,
        "Top 10 des IP en erreur",
        "top_ip_erreur.png",
        output_dir,
    )
def plot_attacks(
    alerts: dict[str, int],
    output_dir: Path = REPORT_DIR,
) -> Path:
    """Attaques de force brute détectées, par IP source."""
    return _plot_top(
        alerts,
        "Attaques par force brute détectées",
        "attaques_force_brute.png",
        output_dir,
    )
def main() -> None:
    """Démo avec de fausses données (remplacée par les vrais compteurs)."""
    logging.basicConfig(level=logging.DEBUG)
    plot_levels({"INFO": 700, "WARNING": 150, "ERROR": 80, "CRITICAL": 20})
    plot_top_error_ips({"203.0.113.9": 120, "45.33.32.156": 90})
    plot_attacks({"185.220.101.4": 14, "198.51.100.23": 9})


if __name__ == "__main__":
    main()