# Moteur de traitement et d'analyse de logs

Projet final Python — ING3 — ECE Paris.

Outil en ligne de commande qui lit de très gros fichiers de logs (jusqu'à 15 Go)
sans les charger en mémoire, les nettoie, les analyse et détecte des
comportements suspects (force brute, IP blacklistées...).

Le détail de l'architecture et du format des données est dans
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Équipe

| Partie | Responsable |
| --- | --- |
| Module 1 — Ingestion (`ingestion.py`), `main.py`, README | Fousseyni |
| Module 2 — Pipeline et nettoyage (`pipeline.py`) | Adam |
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

Un échantillon de 10 Mo (80 000 lignes) est déjà fourni dans `data/echantillon/` :
`server.log` et `blacklist.txt` (60 IP).

Pour générer le jeu complet de 15 Go (environ 12 minutes, 20 Go d'espace libre) :

```
python scripts/generate_logs.py --size-gb 15 --output data/complet
```

Le dossier `data/complet/` n'est jamais envoyé sur GitHub.

## Lancer l'analyse

```
python main.py
```

Sans option, l'analyse porte sur l'échantillon. Options disponibles :

| Option | Rôle | Valeur par défaut |
| --- | --- | --- |
| `--input` | Fichier de logs à analyser | `data/echantillon/server.log` |
| `--blacklist` | Liste noire (une IP par ligne) | `data/echantillon/blacklist.txt` |
| `--max-echecs` | Échecs de connexion d'affilée avant une alerte | `5` |

Exemple sur le jeu complet :

```
python main.py --input data/complet/server.log --max-echecs 10
```

Le programme affiche les messages de débogage, une barre d'avancement,
puis le bilan du nettoyage (lignes lues, gardées, rejetées).

## Lancer les tests

```
python -m pytest -v
```

Les données de test partagées sont dans `tests/conftest.py`.

## Organisation Git

- Une branche par module, fusionnée dans `main` par Pull Request.
- Une Pull Request n'est fusionnée que si `python -m pytest -v` passe.
- Petits commits, messages en français.