# Guide de lancement

Toutes les commandes se lancent **depuis la racine du projet**, dans un
terminal PowerShell, **venv activé**.

---

## 1. Installation (une seule fois)

Python **3.11 ou plus** est nécessaire (`numpy` et `contourpy` ne
s'installent plus en 3.10).

```powershell
git clone https://github.com/FousseyniC/Projet_Python_Ing3_S5.git
cd Projet_Python_Ing3_S5
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

- Sur Mac ou Linux : `source venv/bin/activate`.
- À chaque nouveau terminal, il faut **réactiver** le venv
  (`venv\Scripts\activate`). On le voit au `(venv)` devant l'invite.
- Après un `git pull`, relancer `pip install -r requirements.txt` si le
  fichier a changé.

---

## 2. Vérifications (avant chaque Pull Request)

| Vérification | Commande | Résultat attendu | Durée |
| --- | --- | --- | --- |
| Tests | `python -m pytest -v` | tous les tests `PASSED` | ~7 s |
| Style (mise en forme) | `black --check .` | `All done!`, 0 fichier à reformater | ~1 s |
| Style (PEP8, 79 caractères) | `flake8 .` | aucune ligne affichée | ~2 s |

Les trois d'un coup :

```powershell
python -m pytest -v; black --check .; flake8 .
```

### Pytest en détail

- `python -m pytest` trouve seul le dossier `tests/` (réglé dans
  `pyproject.toml`) et lance toutes les fonctions `test_*`.
- Un seul fichier : `python -m pytest tests/test_rules.py -v`
- Un seul test : `python -m pytest tests/test_rules.py::nom_du_test -v`
- Les tests dont le nom contient un mot : `python -m pytest -k scan -v`
- Les tests n'utilisent **pas** les gros fichiers de logs : ils travaillent
  sur les petites données de `tests/conftest.py`.

### Corriger le style

- `black .` reformate automatiquement (lignes, espaces, guillemets).
  `black fichier.py` pour un seul fichier.
- `flake8` ne corrige rien : il liste les problèmes (`fichier:ligne:colonne
  code`). `E501` = ligne de plus de 79 caractères, à couper à la main.
- Réglages : `pyproject.toml` (black, 79 caractères) et `.flake8`
  (flake8 ne lit pas `pyproject.toml`).

---

## 3. Générer les logs

| Jeu | Commande | Taille | Durée |
| --- | --- | --- | --- |
| Échantillon | déjà fourni dans `data/echantillon/` | 10 Mo, 80 000 lignes | — |
| Complet | `python scripts/generate_logs.py` | 15 Go, ~115 M lignes | ~12 min |

- Le générateur écrit **deux fichiers** dans le dossier de sortie :
  `server.log` et `blacklist.txt` (60 IP). Il n'y a pas de blacklist à
  écrire soi-même.
- Il faut **20 Go d'espace libre** pour le jeu complet.
- `data/complet/` est dans `.gitignore` : il n'est jamais envoyé sur GitHub.
- Une barre d'avancement s'affiche, puis un bilan (lignes propres, sales,
  irrécupérables, attaques injectées).

Options :

| Option | Rôle | Défaut |
| --- | --- | --- |
| `--size-gb` | Taille du fichier en Go | `15` |
| `--output` | Dossier de sortie | `data/complet` |
| `--seed` | Graine aléatoire : même graine = mêmes logs | `42` |

Exemples :

```powershell
python scripts/generate_logs.py                                  # 15 Go dans data/complet
python scripts/generate_logs.py --size-gb 1 --output data/test   # 1 Go pour essayer
```

---

## 4. Lancer l'analyse

```powershell
python main.py          # sur l'échantillon (~2 s)
python main.py -c       # sur le jeu complet data/complet/ (~35 min)
```

| Option | Rôle | Défaut |
| --- | --- | --- |
| `-i FICHIER`, `--input` | Fichier de logs à analyser | l'échantillon |
| `-c`, `--complet` | Analyse `data/complet/server.log` | — |
| `-b FICHIER`, `--blacklist` | Liste noire | `blacklist.txt` **à côté des logs** |
| `-m N`, `--max-echecs` | Échecs de connexion d'affilée avant une alerte force brute | `5` |
| `-g`, `--graphiques` | Crée les graphiques dans `rapport/` | non |
| `-h`, `--help` | Affiche l'aide | — |

- `-i` et `-c` ne peuvent pas être utilisés ensemble.
- Sans `-b`, la blacklist est cherchée dans le **même dossier** que les logs.
- `Ctrl + C` arrête proprement l'analyse.

Exemples :

```powershell
python main.py -c -g                       # jeu complet + graphiques
python main.py -i data/test/server.log     # un autre fichier (blacklist à côté)
python main.py -m 10                       # alerte force brute à 10 échecs
```

---

## 5. Ce qui se passe pendant l'analyse

Le fichier est lu **une seule fois, ligne par ligne**, sans jamais être
chargé en mémoire. Chaque ligne traverse toutes les étapes avant que la
suivante soit lue.

```
server.log
   │  Module 1 (ingestion.py)  lecture ligne par ligne (yield), découpe
   │                           en record, rejet des lignes cassées
   ▼
record brut
   │  Module 2 (pipeline.py)   retire les IP invalides, nettoie les valeurs
   │                           (normalize), classe l'événement (match-case)
   ▼
record propre
   ├──► Module 3 (analysis.py)  statistiques, IP en erreur, blacklist,
   │                            force brute
   └──► Module 4 (rules.py)     règles de sécurité → alertes → bilan
                                    │
                    fin du fichier  ▼
                         Module 4 (audit.py) → audit_report.json
```

Dans le terminal :

1. **Pendant** : les messages `[DEBUG]`, puis une ligne d'avancement mise à
   jour toutes les 50 000 lignes (pourcentage, vitesse, temps restant,
   rejets, attaques, alertes).
2. **À la fin** :
   - bilan du nettoyage : lignes lues, rejetées (par cause), IP invalides,
     lignes gardées ;
   - types d'événements (match-case) ;
   - résultats de l'analyse : IP, IP en erreur, force brute, comparaison
     avec la blacklist (`|`, `&`, `-`, `^`), logs par niveau ;
   - alertes de sécurité par règle, IP sanctionnées pour scan ;
   - durée totale.

---

## 6. Les résultats

| Fichier | Contenu | Écrasé à chaque lancement ? | Sur GitHub ? |
| --- | --- | --- | --- |
| `audit_report.json` | Rapport d'audit (voir ci-dessous) | oui | non (`.gitignore`) |
| `rapport/*.png` | 3 graphiques (avec `-g`) : logs par niveau, top IP en erreur, attaques force brute | oui | oui |

`audit_report.json` contient :

| Clé | Contenu |
| --- | --- |
| `generated_at`, `python_version` | Date du rapport, version de Python |
| `globals`, `locals` | Chaque variable de `main.py` : nom, genre, type, taille, octets, aperçu (`globals()` / `locals()`) |
| `shadowed` | Variables locales qui cachent une globale du même nom |
| `alerts` | Bilan des règles : total, par règle, par gravité, top 50 des IP suspectes avec score, 20 exemples par règle, IP sanctionnées (`bans`) |

Pour garder un rapport par analyse, renommer le fichier avant de relancer
(ex. `audit_complet_2026-11-11.json`).

Pour le rapport PDF : faire la démo en direct sur l'échantillon, et
montrer les résultats du jeu complet calculés à l'avance.

---

## 7. Problèmes fréquents

| Message | Cause | Solution |
| --- | --- | --- |
| `No module named pytest` (ou `black`, `flake8`) | venv non activé | `venv\Scripts\activate` |
| `No matching distribution found for ...` | Python trop ancien | Python 3.11 ou plus, recréer le venv |
| `Fichier de logs introuvable` | Jeu complet pas généré | `python scripts/generate_logs.py` |
| `Blacklist introuvable` | Pas de `blacklist.txt` à côté des logs | le générer, ou donner `-b` |
| `ModuleNotFoundError: moteur_traitement` | Lancé depuis un autre dossier | se placer à la racine du projet |
