"""Constantes partagées par tous les modules (maintenues par le Module 1)."""

# Les quatre niveaux acceptés, toujours écrits en majuscule dans les records.
VALID_LEVELS = frozenset({"INFO", "WARNING", "ERROR", "CRITICAL"})

# Abréviations rencontrées dans les logs, ramenées au niveau complet.
LEVEL_ALIASES = {"WARN": "WARNING", "ERR": "ERROR", "CRIT": "CRITICAL"}

# Valeurs qui veulent dire « pas d'utilisateur » (à comparer en minuscule).
NULL_USERS = frozenset({"-", "", "null", "none", "n/a", "unknown"})

# Formats de date essayés quand datetime.fromisoformat échoue.
DATE_FORMATS = ("%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S")
