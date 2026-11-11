"""Module 4 : audit des variables en mémoire avec globals() et locals().

main.py passe ses propres globals() et locals() à audit_scope() : appelés
ici, ils décriraient ce fichier et non le programme.
"""

from __future__ import annotations

import inspect
import json
import logging
import platform
import sys
from collections.abc import Sized
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PREVIEW_MAX = 80
SIMPLE_TYPES = (str, int, float, bool, type(None))


def _kind(value: Any) -> str:
    """Classe une variable : module, classe, fonction ou donnée."""
    if inspect.ismodule(value):
        return "module"
    if inspect.isclass(value):
        return "class"
    if inspect.isroutine(value):
        return "function"
    return "data"


def _preview(value: Any) -> str | None:
    """Aperçu court, seulement pour les valeurs simples."""
    # Pas de repr() sur un conteneur : il peut être énorme.
    if isinstance(value, SIMPLE_TYPES):
        return repr(value)[:PREVIEW_MAX]
    return None


def _describe(name: str, value: Any) -> dict[str, Any]:
    """Fiche d'une variable."""
    return {
        "name": name,
        "kind": _kind(value),
        "type": type(value).__name__,
        # len() seulement si l'objet a une taille (pas un générateur).
        "length": len(value) if isinstance(value, Sized) else None,
        "bytes": sys.getsizeof(value),
        "preview": _preview(value),
    }


def _is_dunder(name: str) -> bool:
    """Dit si le nom est interne à Python (__name__, __file__...)."""
    return name.startswith("__") and name.endswith("__")


def _describe_scope(scope: dict[str, Any]) -> list[dict[str, Any]]:
    """Fiches de toutes les variables d'une portée, triées par nom."""
    return [
        _describe(name, scope[name])
        for name in sorted(scope)
        if not _is_dunder(name)
    ]


def _export(report: dict[str, Any], output_path: str | Path) -> None:
    """Écrit le rapport en JSON, sans faire planter le programme."""
    path = Path(output_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            # default=str : les dates ne sont pas du JSON.
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    except OSError as exc:
        logger.error("Export de l'audit impossible : %s", exc)


def audit_scope(
    scope_globals: dict[str, Any] | None = None,
    scope_locals: dict[str, Any] | None = None,
    alerts: dict[str, Any] | None = None,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    """Décrit les variables en mémoire et exporte le rapport si demandé.

    Sans argument, audite ce module. Pour auditer le programme, lui
    passer les globals() et locals() de l'appelant.
    """
    if scope_globals is None:
        scope_globals = globals()
    if scope_locals is None:
        scope_locals = locals()

    # Variables locales qui cachent une globale du même nom.
    shadowed: set[str] = set()
    if scope_locals is not scope_globals:
        common = set(scope_locals) & set(scope_globals)
        shadowed = {name for name in common if not _is_dunder(name)}

    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "python_version": platform.python_version(),
        "globals": _describe_scope(scope_globals),
        "locals": _describe_scope(scope_locals),
        "shadowed": sorted(shadowed),
        "alerts": alerts,
    }
    if output_path is not None:
        _export(report, output_path)
    logger.debug(
        "Audit : %d globales, %d locales",
        len(report["globals"]),
        len(report["locals"]),
    )
    return report
