# Architecture — `moteur_traitement`

Engine de traitement et d'analyse de flux de logs sécurisé — Projet final ING3 — Python 3.10+ — équipe de 4.

Ce document est **la référence commune de l'équipe**. Le contrat (section 4) est figé : toute
modification se décide ensemble, puis on met ce fichier à jour.

---

## 1. Consignes du professeur (en plus de l'énoncé)

| Consigne | Ce qu'on fait |
|---|---|
| Jeu de logs d'**au moins 10-15 Go** | `scripts/generate_logs.py` génère **un seul fichier de 15 Go** (`server.log`) par défaut |
| Logs **variés**, pour des analyses intéressantes | ~15 types d'événements + scénarios d'attaque (section 4.3) |
| **Erreurs et lignes à nettoyer, y compris à l'intérieur des lignes**, pour un nettoyage poussé | ~10 % de lignes **sales mais récupérables** + ~2 % de lignes **irrécupérables** (section 4.4) |
| Lignes de log **bien structurées** | Format fixe à 5 champs (section 4.1) |
| Utiliser **Git avec GitHub** | Dépôt GitHub, une branche par module (section 9) |
| Rapport final **en PDF, pas de notebook** ; évalué sur la qualité | `rapport/rapport.pdf` (section 10) |
| Soutenance : **tenue professionnelle obligatoire** | Sinon **-3 points pour toute l'équipe** |
| Questions | Par mail au professeur (avant le week-end) |

---

## 2. Objectif

Une application **en ligne de commande** (CLI, dans le terminal) qui :

1. lit un fichier de logs très volumineux (15 Go) **sans le charger en RAM** ;
2. rejette les lignes irrécupérables et **nettoie** les lignes sales ;
3. calcule des statistiques (erreurs par IP, par niveau, par utilisateur…) ;
4. compare les IP actives à une liste noire ;
5. détecte les attaques par force brute ;
6. applique des règles de sécurité configurables et produit un rapport d'audit.

```
python main.py --input data/complet/server.log --blacklist data/complet/blacklist.txt --max-echecs 5
```

---

## 3. Arborescence

```
moteur_traitement/
├── data/
│   ├── echantillon/           # ~10 Mo, versionné (tests + démo)
│   │   ├── server.log
│   │   └── blacklist.txt
│   └── complet/               # 15 Go, NON versionné
│       ├── server.log
│       └── blacklist.txt
├── docs/
│   └── ARCHITECTURE.md        # ce document
├── moteur_traitement/         # le package Python
│   ├── __init__.py
│   ├── constants.py           # constantes partagées (niveaux, alias, formats de date…)
│   ├── ingestion.py           # Module 1 : générateurs + parsing
│   ├── pipeline.py            # Module 2 : filter, map, match-case, nettoyage
│   ├── analysis.py            # Module 3 : sets, defaultdict, force brute
│   ├── rules.py               # Module 4 : moteur de règles
│   └── audit.py               # Module 4 : globals() / locals()
├── tests/
│   ├── conftest.py            # fixtures partagées
│   ├── test_ingestion.py
│   ├── test_pipeline.py
│   ├── test_analysis.py
│   ├── test_rules.py
│   └── test_audit.py
├── scripts/
│   └── generate_logs.py       # génère les fichiers de logs
├── notebooks/                 # facultatif : expérimentation / prototypage uniquement
├── rapport/
│   └── rapport.pdf            # rapport final (PDF, pas de notebook)
├── main.py                    # point d'entrée, orchestre le pipeline
├── requirements.txt
├── .gitignore
└── README.md
```

`.gitignore` :

```
venv/
.venv/
__pycache__/
.pytest_cache/
.ipynb_checkpoints/
data/complet/
```

---

## 4. Contrat de données (figé)

### 4.1 Format d'une ligne **propre**

Cinq champs séparés par ` | ` :

```
date heure | niveau | IP | utilisateur | payload
```

```
2026-01-01 00:26:31 | WARNING | 197.125.255.225 | farid49 | {"action": "login", "status": "failed", "port": 22, "protocol": "SSH"}
2026-01-01 00:26:31 | ERROR | 22.128.79.209 | david49 | {"method": "GET", "url": "/api/products", "status": 503, "duration_ms": 14479, "port": 443, "protocol": "HTTPS"}
2026-01-01 00:26:46 | CRITICAL | 77.185.106.206 | postgres | Access denied to /etc/shadow
2026-01-01 00:26:31 | INFO | 85.87.30.172 | - | kernel: eth1 link up
```

- `-` signifie « pas d'utilisateur ».
- Le payload est soit du **JSON**, soit du **texte brut**.

### 4.2 Structure d'un record (ligne parsée)

```python
{
    "timestamp": datetime,         # objet datetime
    "level": str,                  # "INFO", "WARNING", "ERROR" ou "CRITICAL"
    "ip": str,                     # "10.0.0.5"
    "user": str | None,            # None si absent
    "payload": dict | str,         # dict si JSON, sinon texte brut
    "connection": tuple | None,    # (ip, port, protocole) si le payload a port + protocol
}
```

- `connection` est toujours un **tuple** `(str, int, str)`, ex. `("10.0.0.5", 22, "SSH")`.
- **Une ligne irrécupérable donne `None`.** Le Module 2 les supprime avec `filter(None, ...)`.

### 4.3 Événements produits par le générateur (lignes propres)

| Événement | Niveau | Payload |
|---|---|---|
| Connexion SSH réussie | INFO | `{"action": "login", "status": "success", "port": 22, "protocol": "SSH"}` |
| Connexion SSH échouée | WARNING | `{"action": "login", "status": "failed", "port": 22, "protocol": "SSH"}` |
| Requête HTTP | INFO / WARNING (lente) / ERROR (4xx, 5xx) | `{"method": "GET", "url": ..., "status": ..., "duration_ms": ..., "port": 443, "protocol": "HTTPS"}` |
| Injection (SQL, XSS…) | WARNING | `{"attack": "injection", "content": ..., "url": ..., "port": 443, "protocol": "HTTPS"}` |
| Scan de ports | WARNING | `{"action": "connect", "status": "blocked", "port": ..., "protocol": "TCP"/"UDP"}` |
| Tâche cron, CPU, réseau | INFO / WARNING / ERROR | texte : `cron: backup_3 completed`, `CPU at 92% on server_01`, `kernel: eth0 link down` |
| Incident grave | CRITICAL | texte : `Disk usage above 95% on /var`, `Service postgres stopped`… |

Scénarios injectés exprès, pour que les analyses aient quelque chose à trouver :
- **Force brute** : 5 à 40 échecs de connexion consécutifs, même IP et même utilisateur ; dans 25 % des cas,
  une connexion réussie à la fin (compte compromis).
- **Faux positifs** : 2 ou 3 échecs puis une réussite (mot de passe oublié), qui ne doivent pas déclencher d'alerte.
- **IP blacklistées** actives (scans de ports, injections, force brute).

### 4.4 Salissures — le nettoyage poussé

Proportions mesurées sur 1,6 million de lignes : **88,4 % propres, 9,8 % sales mais récupérables,
1,5 % irrécupérables** (`None` au Module 1) et **0,3 % d'IP invalides** (filtrées par le Module 2).
Le générateur affiche ce bilan à la fin de chaque génération.

**a) Lignes sales récupérables** : une ligne sale a 1 à 3 de ces défauts à la fois.

| Défaut | Exemple | Qui le corrige |
|---|---|---|
| Séparateurs irréguliers | `a|b`, `a  |  b`, `a\t|\tb` | Module 1 (`split("|")` + `strip()`) |
| Fin de ligne Windows / espaces finaux | `...\r\n`, `...   \n` | Module 1 (`strip()`) |
| Formats de date variés | `2026-01-01T00:26:31`, `2026/01/01 00:26:31`, `01/01/2026 00:26:31`, `2026-01-01 00:26:31.482` | Module 1 |
| Niveau mal écrit / alias | `warning`, `Error`, `  INFO  `, `[CRITICAL]`, `WARN`, `err`, `CRIT` | Module 1 |
| Utilisateur vide sous d'autres formes | `null`, `NULL`, `None`, `N/A`, `unknown`, champ vide | Module 1 (→ `None`) |
| JSON en quotes simples (format Python) | `{'action': 'login', 'status': 'failed', ...}` | Module 1 (`ast.literal_eval` en secours) |
| Clés JSON en majuscule | `{"Action": "login", "Port": 22, ...}` | Module 1 pour `connection` ; Module 2 pour le reste |
| Utilisateur mal formaté | `BOB46`, `Bob46`, `"bob46"`, `  bob46 ` | Module 2 (`normalize`) |
| IP avec zéros / espaces | `010.000.000.005`, ` 10.0.0.5  ` | Module 2 (`normalize`) |
| Valeurs JSON en majuscule ou en texte | `"status": "FAILED"`, `"port": "22"`, `"status": "503"` | Module 2 (`normalize`) |
| Payload texte sale | espaces multiples, `TOUT EN MAJUSCULE`, tabulation, caractère de contrôle `\x07`, entre guillemets | Module 2 (`normalize`) |

**b) Lignes irrécupérables** → `None` (Module 1) ou filtrées (Module 2).

| Défaut | Exemple | Résultat |
|---|---|---|
| Ligne vide / blancs seuls | `""`, `"   "`, `"\t"` | `None` |
| Ligne tronquée | `2026-01-01 00:26:31 | INFO | 85.87.3` | `None` |
| Niveau inconnu | `DEBUG`, `TRACE`, `NOTICE`, `???` | `None` |
| Date impossible | `2026-13-45 99:99:99`, `yesterday`, `0000-00-00 00:00:00`, `N/A` | `None` |
| Mauvais nombre de champs | 4 champs | `None` |
| Ligne parasite | `#### log rotated ####`, `\x00\x00\x00`, `<<<EOF>>>` | `None` |
| IP invalide | `999.300.1.1`, `localhost`, `unknown`, `10.0.0` | supprimée par le Module 2 (`filter` + `lambda`) |

Le JSON tronqué ou cassé n'est **pas** rejeté : la ligne reste valide, avec un payload texte brut.

**Statistique de nettoyage à afficher dans `main.py` et dans le rapport** : lignes lues, lignes rejetées
(par cause si possible), lignes nettoyées, lignes conservées.

### 4.5 Constantes partagées (`constants.py`, maintenu par le Module 1)

```python
VALID_LEVELS = frozenset({"INFO", "WARNING", "ERROR", "CRITICAL"})
LEVEL_ALIASES = {"WARN": "WARNING", "ERR": "ERROR", "CRIT": "CRITICAL"}
NULL_USERS = frozenset({"-", "", "null", "none", "n/a", "unknown"})   # comparés en minuscule
DATE_FORMATS = ("%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S")          # en secours de fromisoformat
```

---

## 5. Flux de données

```
server.log (15 Go)
      │
      ▼
[Module 1] read_many_files ──yield from──► read_log_file ──yield──► str
      │
      ▼  map(parse_line, ...)          ← structure, types, dates, alias de niveau, JSON
   dict | None
      │
      ▼
[Module 2] remove_invalid ── filter(None) + filter(lambda: IP valide) ──► dict
      │
      ▼  map(normalize, ...)           ← nettoyage des valeurs (user, IP, payload)
   dict propre
      │
      ▼  route(record) : match-case (payload dict / texte brut / connection tuple)
      │
      ├──► [Module 3] error_ips · count_by · detect_brute_force · compare_with_blacklist
      │
      └──► [Module 4] apply_security_rules(*rules, **config) ──► alertes
                                   │
                                   ▼
                         audit_scope() ──► rapport d'audit
```

Tout est **paresseux** jusqu'au Module 3 : aucune liste complète n'est jamais construite.

**Partage du nettoyage :** le Module 1 s'occupe de la *structure* (découper, convertir les types, dire si la ligne
est exploitable). Le Module 2 s'occupe des *valeurs* (casse, espaces, zéros, caractères parasites).

---

## 6. Modules et fonctions

### Module 1 — `ingestion.py` (+ `constants.py`)

| Fonction | Entrée → Sortie | Notions de l'énoncé |
|---|---|---|
| `read_log_file(path)` | chemin → `Iterator[str]` | `yield`, lecture ligne par ligne |
| `read_many_files(paths)` | chemin ou chemins → `Iterator[str]` | `yield from`, fichiers manquants ignorés avec un warning |
| `parse_line(line)` | `str` → `dict \| None` | dictionnaire, tuple `connection`, nettoyage structurel |
| `read_records(paths)` | chemin ou chemins → `Iterator[dict \| None]` | `map(parse_line, read_many_files(paths))`, reste paresseux |
| `load_blacklist(path)` | chemin → `frozenset[str]` | une IP par ligne, lignes vides ignorées |

Le jeu de données tient dans **un seul fichier** (`server.log`). `read_many_files` reste le point d'entrée
du pipeline : il accepte un chemin seul (`read_many_files("data/complet/server.log")`) ou une liste
(par exemple pour enchaîner l'échantillon et un autre fichier), et c'est lui qui porte le `yield from`.

### Module 2 — `pipeline.py` (programmation fonctionnelle + nettoyage des valeurs)

| Fonction | Entrée → Sortie | Notions de l'énoncé |
|---|---|---|
| `remove_invalid(records)` | `Iterable[dict \| None]` → `Iterator[dict]` | `filter(None, ...)` + `filter(lambda r: is_valid_ip(r["ip"]), ...)` |
| `normalize(record)` | `dict` → `dict` | via `map()` : user en minuscule sans guillemets, IP sans zéros, clés et valeurs JSON normalisées (`"FAILED"`→`"failed"`, `"22"`→`22`), texte nettoyé ; **reconstruire `connection` avec l'IP nettoyée** |
| `route(record)` | `dict` → catégorie / résultat | `match-case` sur payload `dict`, `str`, `connection` tuple |

```python
match record:
    case {"payload": {"action": "login", "status": "failed"}}: ...
    case {"payload": {"status": int(code)}} if code >= 500: ...
    case {"connection": (ip, 22, "SSH")}: ...
    case {"payload": str(text)}: ...
```

### Module 3 — `analysis.py` (agrégation + contrôle de flux)

| Fonction | Entrée → Sortie | Notions de l'énoncé |
|---|---|---|
| `error_ips(records)` | records → `set[str]` | `set`, IP uniques en ERROR/CRITICAL |
| `compare_with_blacklist(ips, blacklist)` | `set`, `frozenset` → `dict[str, set]` | `\|`, `&`, `-`, `^` |
| `count_by(records, key)` | records, clé → `defaultdict(int)` | `defaultdict` |
| `detect_brute_force(records, threshold)` | records, seuil → liste d'alertes | `while` + `for`, `break`, `continue`, `else` |

### Module 4 — `rules.py` + `audit.py`

| Fonction | Entrée → Sortie | Notions de l'énoncé |
|---|---|---|
| `apply_security_rules(*rules, **config)` | fonctions-règles + config → alertes | `*args`, `**kwargs`, fonctions de première classe |
| 2-3 règles (ex. `rule_blacklisted_ip`, `rule_critical_level`, `rule_injection`) | `(record, **config)` → alerte ou `None` | fonctions passées en argument |
| `audit_scope()` | → rapport (dict / fichier) | `globals()`, `locals()` |

### `main.py`

- Lit les arguments CLI (`argparse`) : fichier de logs, blacklist, seuil force brute.
- Branche les modules dans l'ordre du flux de données.
- Affiche le résumé (y compris les **statistiques de nettoyage**) et écrit le rapport d'audit.
- Affiche à chaque lancement les messages de débogage (`logging`, niveau DEBUG) et une barre d'avancement.

---

## 7. Point ouvert : un seul passage sur les données

Un générateur **ne se lit qu'une seule fois**. Si `error_ips`, `count_by` et `detect_brute_force`
consomment chacune le flux complet, il faut relire les 15 Go plusieurs fois (lent), ou stocker les records
en mémoire (interdit).

Options, à décider ensemble avant de coder le Module 3 et `main.py` :

1. **Relire les fichiers pour chaque analyse.** C'est le plus simple et ça respecte la contrainte mémoire,
   mais c'est N fois plus lent. Acceptable pour `data/echantillon/`.
2. **Un seul passage dans `main.py`.** Les fonctions du Module 3 ont aussi une version « record par record »
   (ex. une classe `Stats` avec une méthode `update(record)`) et `main.py` fait une seule boucle `for`
   qui alimente toutes les analyses. C'est l'option recommandée pour les 15 Go.

Ordre de grandeur : en Python pur, le parsing tourne à environ 150 000 lignes/s par cœur. Les 15 Go
(environ 120 millions de lignes) se traitent donc en 15 à 20 minutes **par passage**. Pour la soutenance,
faire la démo sur `data/echantillon/` et montrer des résultats pré-calculés sur le jeu complet.

---

## 8. Tests

- Outil : `pytest` → `python -m pytest -v`.
- Un fichier de test par module (`tests/test_<module>.py`), géré par le responsable du module.
- `tests/conftest.py` contient les **fixtures partagées** :
  - `sample_lines` : lignes propres de la section 4.1 ;
  - `dirty_lines` : une ligne par défaut récupérable de la section 4.4 a), avec le record attendu ;
  - `invalid_lines` : une ligne par défaut irrécupérable de la section 4.4 b) ;
  - `sample_records` : records attendus.
  On ajoute ses fixtures, on ne supprime pas celles des autres.
- Les modules 2, 3 et 4 se testent avec ces fixtures : pas besoin d'attendre que le Module 1 soit fini.
- Tests lents (sur `data/echantillon/`) marqués `@pytest.mark.slow`.
- Le Module 1 inclut un test mémoire (`tracemalloc`) qui prouve que la RAM reste basse.

---

## 9. Données, Git et conventions

### Données

```
python scripts/generate_logs.py --size-gb 0.01 --output data/echantillon   # ~10 Mo, versionné
python scripts/generate_logs.py --size-gb 15 --output data/complet         # 15 Go, non versionné
```

- Chaque dossier contient **un seul fichier de logs**, `server.log`, et `blacklist.txt` (60 IP).
  Les messages système citent toujours 8 serveurs (`CPU at 92% on server_03`).
- Pendant la génération, une barre de progression affiche l'avancement (Mo, lignes, vitesse,
  temps restant), puis un bilan : lignes propres / sales / irrécupérables, IP invalides,
  nombre d'attaques force brute (et réussies), faux positifs, scans de ports, injections.
- Graine par défaut `--seed 42` : tout le monde génère **exactement les mêmes données**.
- Génération en un seul processus, environ 22 Mo/s : compter **une douzaine de minutes** pour les 15 Go,
  et au moins 20 Go d'espace disque libre.

### Git / GitHub

- Dépôt sur **GitHub**, tous les membres en collaborateurs.
- Une branche par module : `module1-ingestion`, `module2-pipeline`, `module3-analysis`, `module4-rules`.
- Petits commits, messages clairs ; **Pull Request** vers `main`, relue par un autre membre, mergée
  uniquement si `pytest` passe.
- Ne jamais pousser `data/complet/` (GitHub refuse les fichiers > 100 Mo).
- Avant le rendu : clone propre → nouveau `venv` → `pip install -r requirements.txt` → `python main.py`.

### Conventions de code

- Python 3.10+, environnement `venv/`. Toute dépendance ajoutée → `pip freeze > requirements.txt` et prévenir l'équipe.
- Noms de fonctions et de clés en anglais (contrat), commentaires et docstrings en français.
- PEP8 vérifiée avec `black .` et `flake8 .`, typage sur toutes les fonctions publiques.
- Exceptions précises, jamais de `except:` nu ; `logging` dans le package, `print` seulement dans `main.py`.

---

## 10. Rapport final (PDF)

Pas de notebook pour le rapport. Un **PDF** dans `rapport/rapport.pdf`, évalué sur la qualité (pas sur
le nombre de pages). Plan suggéré :

1. Introduction et objectifs.
2. Architecture (reprendre les sections 3 à 5 de ce document, avec le schéma du flux).
3. Génération des données : volume, variété, salissures injectées.
4. Un chapitre par module : choix techniques, extraits de code commentés, notions de l'énoncé couvertes.
5. Nettoyage : statistiques avant/après (lignes rejetées par cause, lignes corrigées).
6. Résultats des analyses : graphiques (erreurs par heure, top IP, attaques détectées, blacklist).
7. Performance : temps de traitement, **preuve que la RAM reste basse** (mesure `tracemalloc` ou capture).
8. Tests : ce qui est couvert, résultat de `pytest`.
9. Limites et améliorations possibles.

Les graphiques peuvent être produits par un script (`matplotlib`, enregistrés en PNG), puis insérés dans le PDF.

---

## 11. Répartition et barème

| Module | Responsable | Barème associé |
|---|---|---|
| 1. Ingestion | Fousseyni | Gestion mémoire & générateurs (4 pts) |
| 2. Pipeline & nettoyage | Adam | Programmation fonctionnelle (4 pts) |
| 3. Analyse | Selyan | Structures de données complexes (4 pts) |
| 4. Règles & audit | Amine | Moteur de règles & introspection (3 pts) |
| Commun | toute l'équipe | Environnement & livrables (2 pts), qualité du code (3 pts), rapport PDF, soutenance |
