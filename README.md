# Moteur de traitement et d'analyse de logs

Projet final Python — ING3 — ECE Paris.

Outil en ligne de commande qui lit de très gros fichiers de logs (10 à 15 Go)
sans les charger en mémoire, les nettoie, les analyse et détecte des
comportements suspects (force brute, IP blacklistées, injections, scans de
ports...).

Le détail de l'architecture et du format des données est dans
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Équipe

| Partie | Responsable |
| --- | --- |
| Module 1 — Ingestion (`ingestion.py`), `main.py`, tests, README | Fousseyni |
| Module 2 — Pipeline et nettoyage (`pipeline.py`), graphiques | Adam |
| Module 3 — Analyse (`analysis.py`) | Selyan |
| Module 4 — Règles et audit (`rules.py`, `audit.py`), générateur | Amine |

## Installation

Python 3.10 ou plus est nécessaire.

```
git clone https://github.com/FousseyniC/Projet_Python_Ing3_S5.git
cd Projet_Python_Ing3_S5
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Sur Mac ou Linux, l'activation se fait avec `source venv/bin/activate`.

## Données

Un échantillon de 10 Mo (80 000 lignes) est déjà fourni dans
`data/echantillon/` : `server.log` et `blacklist.txt` (60 IP).

Pour générer le jeu complet de 10 Go (environ 8 minutes, 12 Go d'espace
libre) :

```
python scripts/generate_logs.py --size-gb 10 --output data/complet
```

Le fichier généré mélange des lignes propres (88 %), des lignes sales mais
récupérables (10 %), des lignes inutilisables (1,5 %) et des IP invalides
(0,3 %). Il contient aussi des attaques simulées : force brute, scans de
ports, injections SQL/XSS. La graine `--seed 42` donne toujours le même
fichier.

Le dossier `data/complet/` n'est jamais envoyé sur GitHub.

## Lancer l'analyse

```
python main.py          # échantillon de 10 Mo (quelques secondes)
python main.py -c       # jeu complet de 10 Go (environ 20 minutes)
python main.py -c -g    # jeu complet + graphiques du rapport
```

| Option | Rôle | Valeur par défaut |
| --- | --- | --- |
| `-i`, `--input` | Fichier de logs à analyser | `data/echantillon/server.log` |
| `-c`, `--complet` | Analyse `data/complet/server.log` | désactivée |
| `-b`, `--blacklist` | Liste noire (une IP par ligne) | `blacklist.txt` à côté des logs |
| `-m`, `--max-echecs` | Échecs de connexion d'affilée avant une alerte | `5` |
| `-g`, `--graphiques` | Crée les graphiques dans `rapport/` | désactivée |

`-i` et `-c` ne peuvent pas être utilisées ensemble.
`python main.py -h` affiche l'aide.

Exemple avec un seuil plus strict :

```
python main.py -c -m 3
```

Ctrl+C arrête l'analyse proprement.

## Ce que fait le programme

Le fichier n'est lu **qu'une seule fois**, ligne par ligne, à travers une
chaîne de générateurs. Chaque ligne traverse toute la chaîne avant que la
suivante soit lue : la mémoire reste basse quelle que soit la taille du
fichier.

```
read_many_files      lecture ligne par ligne (yield / yield from)   Module 1
  -> parse_line      découpage en dictionnaire (map)                Module 1
  -> transform       retrait des IP invalides et normalisation      Module 2
                     (filter, lambda, map)
  -> route           type d'événement (match-case)                  Module 2
  -> Stats.update    IP, niveaux, force brute                       Module 3
  -> check           règles de sécurité et alertes                  Module 4
```

À chaque lancement, le programme affiche :

1. Les messages de débogage (`[DEBUG] ...`) : options reçues, blacklist,
   règles chargées.
2. Une barre d'avancement mise à jour en temps réel : pourcentage, vitesse,
   temps restant, rejets, attaques et alertes trouvées.
3. Le bilan du nettoyage, avec la cause de chaque rejet.
4. Les types d'événements, les résultats de l'analyse (opérations
   d'ensembles avec la blacklist, logs par niveau) et les alertes de
   sécurité.

Exemple sur l'échantillon (extrait) :

```
[##########] 100% 80 k lignes 70 k/s reste 0 s | rejets 1 k | IP inv. 217 | attaques 202 | alertes 8 k

Bilan du nettoyage :
  Lignes lues           :       80,000
  Lignes rejetées       :        1,276  (1.6%)
    - nombre de champs incorrect        582
    - ligne vide                        372
    - date invalide                     161
    - niveau inconnu                    161
  IP invalides retirées :          217  (0.3%)
  Lignes gardées        :       78,507
```

## Fichiers produits

| Fichier | Contenu | Envoyé sur GitHub |
| --- | --- | --- |
| `audit_report.json` | Audit des variables (`globals()` / `locals()`) et bilan des alertes | non |
| `rapport/*.png` | Graphiques : logs par niveau, IP en erreur, attaques (option `-g`) | oui |

## Lancer les tests

```
python -m pytest -v
```

105 tests, un fichier par module dans `tests/`. Les données de test
partagées sont dans `tests/conftest.py`. Un test vérifie aussi que la
mémoire reste basse pendant la lecture (`tracemalloc`).

## Style du code

Le code suit la PEP 8 (lignes de 79 caractères au plus), vérifiée avec :

```
python -m flake8 main.py moteur_traitement tests
```

## Organisation Git

- Une branche par module, fusionnée dans `main` par Pull Request.
- Une Pull Request n'est fusionnée que si `python -m pytest -v` passe.
- Petits commits, messages en français.
