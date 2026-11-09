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