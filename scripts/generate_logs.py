#!/usr/bin/env python3
"""Génère un gros fichier de faux logs pour tester le moteur de traitement.

Chaque ligne suit le format du contrat :
    date heure | niveau | IP | utilisateur | payload

Environ 88 % des lignes sont propres, 10 % sont abîmées mais récupérables
(dates, niveaux, espaces, JSON...) et 2 % sont irrécupérables (vides,
tronquées, niveau inconnu...). Le détail est dans docs/ARCHITECTURE.md.

À lancer depuis la racine du projet :
    python scripts/generate_logs.py --size-gb 0.01 --output data/echantillon
    python scripts/generate_logs.py --size-gb 15 --output data/complet

Le dossier de sortie contient server.log et blacklist.txt (une IP par ligne).
La progression s'affiche pendant la génération, puis un bilan de ce qui a
été écrit (lignes sales, irrécupérables, attaques injectées...).
"""

from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path

LOG_NAME = "server.log"
BUFFER_LINES = 20_000
START = 1_767_225_600  # 1er janvier 2026, minuit UTC
DIRTY_RATE = 0.10
MB = 1024**2

FIRST_NAMES = [
    "alice",
    "bob",
    "carol",
    "david",
    "emma",
    "farid",
    "gael",
    "hugo",
    "ines",
    "jules",
    "karim",
    "lea",
    "mehdi",
    "nora",
    "oscar",
    "paul",
    "quentin",
    "rania",
    "sami",
    "theo",
    "ugo",
    "vanessa",
    "wassim",
    "yanis",
]
SENSITIVE_ACCOUNTS = ["admin", "root", "test", "guest", "oracle", "postgres"]
SERVERS = [f"server_{i:02d}" for i in range(1, 9)]
URLS = [
    "/",
    "/login",
    "/api/users",
    "/api/orders",
    "/admin",
    "/static/app.js",
    "/api/products",
    "/logout",
    "/search",
    "/api/payments",
]
INJECTIONS = [
    "' OR 1=1 --",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "; DROP TABLE users;",
    "${jndi:ldap://evil/a}",
]
CRITICAL_MESSAGES = [
    "Disk usage above 95% on /var",
    "Service postgres stopped",
    "Access denied to /etc/shadow",
    "TLS certificate expired",
    "Out of memory, OOM killer invoked",
]

# Variantes utilisées pour salir les lignes (elles restent récupérables).
LEVEL_ALIASES = {
    "WARNING": "WARN",
    "ERROR": "ERR",
    "CRITICAL": "CRIT",
    "INFO": "INFO",
}
NULL_USERS = ["null", "NULL", "None", "N/A", "", "unknown"]
SEPARATORS = ["|", " |  ", "  | ", "\t|\t", " | "]

# Valeurs qui rendent une ligne inutilisable.
UNKNOWN_LEVELS = ["DEBUG", "TRACE", "NOTICE", "???"]
BAD_DATES = ["2026-13-45 99:99:99", "yesterday", "0000-00-00 00:00:00", "N/A"]
GARBAGE = [
    "#### log rotated ####",
    "# server restarted",
    "\x00\x00\x00\x00",
    "----------------------------------------",
    "<<<EOF>>>",
]
BAD_IPS = ["999.300.1.1", "unknown", "localhost", "256.256.256.256", "10.0.0"]


def build_users(rng: random.Random) -> list[str]:
    """Crée environ 300 utilisateurs (alice42...) et les comptes sensibles."""
    users = {
        f"{rng.choice(FIRST_NAMES)}{rng.randint(1, 99)}" for _ in range(300)
    }
    return sorted(users) + SENSITIVE_ACCOUNTS


def build_blacklist(rng: random.Random) -> list[str]:
    """Tire 60 IP « malveillantes »."""
    ips = {
        f"{rng.randint(1, 223)}.{rng.randint(0, 255)}."
        f"{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        for _ in range(60)
    }
    return sorted(ips)


def format_duration(seconds: float) -> str:
    """Affiche une durée lisible : 42 s, 3 min 05 s..."""
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} s"
    return f"{seconds // 60} min {seconds % 60:02d} s"


def show_progress(
    written: int, target: int, n_lines: int, start: float
) -> None:
    """Réécrit la même ligne du terminal avec l'avancement."""
    elapsed = time.time() - start
    speed = written / elapsed if elapsed else 0
    remaining = (target - written) / speed if speed else 0
    ratio = min(written / target, 1)
    bar = "#" * int(ratio * 30)
    print(
        f"\r  [{bar:<30}] {ratio:6.1%}  "
        f"{written / MB:,.0f}/{target / MB:,.0f} Mo"
        f"  {n_lines:,} lignes  {speed / MB:.1f} Mo/s"
        f"  reste ~{format_duration(remaining)}   ",
        end="",
        flush=True,
    )


def generate_log(
    path: Path, target: int, seed: int, blacklist: list[str], users: list[str]
) -> tuple[int, int, dict]:
    """Remplit le fichier de logs jusqu'à la taille voulue (en octets).

    Renvoie le nombre d'octets écrits, le nombre de lignes et un dictionnaire
    qui compte ce qui a été généré (lignes sales, attaques...).
    """
    rng = random.Random(seed)
    stats = dict.fromkeys(
        [
            "propres",
            "sales",
            "irrecuperables",
            "ip_invalides",
            "force_brute",
            "force_brute_reussie",
            "faux_positifs",
            "scans",
            "injections",
        ],
        0,
    )

    # Raccourcis locaux : ces fonctions sont appelées des millions de fois.
    r = rng.random
    pick = rng.choice
    rint = rng.randint
    dumps = json.dumps

    internal_ips = [
        f"192.168.{rint(0, 20)}.{rint(1, 254)}" for _ in range(400)
    ]
    external_ips = [
        f"{rint(1, 223)}.{rint(0, 255)}.{rint(0, 255)}.{rint(1, 254)}"
        for _ in range(3000)
    ]

    # L'horloge avance de quelques millisecondes par ligne. Comme strftime est
    # lent, on ne reformate la date que lorsque la seconde change.
    t = float(START)
    cached_second = -1
    ts = ""

    def timestamp() -> str:
        nonlocal t, cached_second, ts
        t += r() * 0.02
        s = int(t)
        if s != cached_second:
            cached_second = s
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(s))
        return ts

    # --- Salissures récupérables : chaque fonction abîme un seul champ ---

    def dirty_date(d: str) -> str:
        # Même instant, mais écrit autrement (ISO avec T, slashs, format
        # français ou millisecondes).
        y, mo, rest = d[:4], d[5:7], d[8:]
        day, hms = rest[:2], rest[3:]
        return pick(
            [
                f"{y}-{mo}-{day}T{hms}",
                f"{y}/{mo}/{day} {hms}",
                f"{day}/{mo}/{y} {hms}",
                f"{d}.{rint(0, 999):03d}",
            ]
        )

    def dirty_level(lv: str) -> str:
        return pick(
            [
                lv.lower(),
                lv.capitalize(),
                LEVEL_ALIASES[lv],
                LEVEL_ALIASES[lv].lower(),
                f"  {lv}  ",
                f"[{lv}]",
            ]
        )

    def dirty_ip(ip: str) -> str:
        # Des zéros devant chaque nombre (010.000.000.005) ou des espaces.
        if r() < 0.6:
            return ".".join(f"{int(p):03d}" for p in ip.split("."))
        return f" {ip}  "

    def dirty_user(u: str | None) -> str:
        if u is None:
            return pick(NULL_USERS)
        return pick([u.upper(), u.capitalize(), f"  {u} ", f'"{u}"'])

    def dirty_payload(p: dict | str) -> str:
        if isinstance(p, dict):
            # Quatre façons d'abîmer le JSON : quotes simples à la Python, clés
            # en majuscule, valeurs en majuscule ou en texte ("FAILED", "22"),
            # ou JSON compact entouré d'espaces.
            k = r()
            if k < 0.3:
                return str(p)
            if k < 0.55:
                return dumps({key.capitalize(): v for key, v in p.items()})
            if k < 0.8:
                q = {
                    key: (v.upper() if isinstance(v, str) else str(v))
                    for key, v in p.items()
                }
                return dumps(q)
            return "  " + dumps(p, indent=None, separators=(",", ":")) + "  "
        # Texte brut : espaces en trop, tout en majuscule, tabulation et
        # caractère de contrôle (\x07), ou message entre guillemets.
        k = r()
        if k < 0.35:
            return "   ".join(p.split(" ")) + "   "
        if k < 0.6:
            return p.upper()
        if k < 0.8:
            return p.replace(" ", "\t", 1) + "\x07"
        return f'"{p}"'

    def line(
        level: str, ip: str, user: str | None, payload: dict | str
    ) -> str:
        """Construit une ligne propre, ou sale dans DIRTY_RATE des cas."""
        d = timestamp()
        if r() >= DIRTY_RATE:
            stats["propres"] += 1
            pl = dumps(payload) if isinstance(payload, dict) else payload
            return f"{d} | {level} | {ip} | {user or '-'} | {pl}\n"

        # Ligne sale : on abîme entre 1 et 3 éléments tirés au hasard.
        stats["sales"] += 1
        aspects = rng.sample(
            ["date", "level", "ip", "user", "payload", "sep", "end"],
            rint(1, 3),
        )
        fd = dirty_date(d) if "date" in aspects else d
        fl = dirty_level(level) if "level" in aspects else level
        fi = dirty_ip(ip) if "ip" in aspects else ip
        fu = dirty_user(user) if "user" in aspects else (user or "-")
        if "payload" in aspects:
            fp = dirty_payload(payload)
        else:
            fp = dumps(payload) if isinstance(payload, dict) else payload
        sep = pick(SEPARATORS) if "sep" in aspects else " | "
        end = pick(["\r\n", "   \n", " \t\n"]) if "end" in aspects else "\n"
        return sep.join((fd, fl, fi, fu, fp)) + end

    def invalid_line(ip: str, user: str) -> str:
        """Construit une ligne irrécupérable : parse_line doit renvoyer None.

        Exception : les lignes avec une IP invalide sont bien formées, c'est
        le Module 2 qui les filtre.
        """
        k = r()
        d = timestamp()
        good = f"{d} | INFO | {ip} | {user} | " + dumps(login("success"))
        if k < 0.85:
            stats["irrecuperables"] += 1
        if k < 0.25:
            return pick(["\n", "   \n", "\t\n"])
        if k < 0.45:
            # Coupée avant le 4e séparateur, donc moins de 5 champs.
            return good[: rint(5, 45)] + "\n"
        if k < 0.55:
            level = pick(UNKNOWN_LEVELS)
            return f"{d} | {level} | {ip} | {user} | unknown level\n"
        if k < 0.65:
            return f"{pick(BAD_DATES)} | INFO | {ip} | {user} | bad date\n"
        if k < 0.75:
            return f"{d} | INFO | {ip} | {user}\n"
        if k < 0.85:
            return pick(GARBAGE) + "\n"
        stats["ip_invalides"] += 1
        return (
            f"{d} | WARNING | {pick(BAD_IPS)} | {user} | "
            + dumps(login("failed"))
            + "\n"
        )

    def login(status: str, port: int = 22) -> dict:
        return {
            "action": "login",
            "status": status,
            "port": port,
            "protocol": "SSH",
        }

    def http(status: int, url: str, ms: int) -> dict:
        return {
            "method": "GET",
            "url": url,
            "status": status,
            "duration_ms": ms,
            "port": 443,
            "protocol": "HTTPS",
        }

    def any_ip() -> str:
        # Un peu plus de la moitié du trafic est interne, 3 % vient de la
        # blacklist.
        x = r()
        if x < 0.55:
            return pick(internal_ips)
        if x < 0.97:
            return pick(external_ips)
        return pick(blacklist)

    def event() -> list[str]:
        """Tire un événement au hasard et renvoie les lignes qu'il produit.

        Les seuils sur x donnent la fréquence de chaque événement : par exemple
        0.66 pour le trafic normal, c'est environ deux événements sur trois.
        """
        x = r()
        ip = any_ip()
        user = pick(users)

        # Trafic normal : pages web, connexions réussies, tâches cron.
        if x < 0.66:
            y = r()
            if y < 0.6:
                return [
                    line("INFO", ip, user, http(200, pick(URLS), rint(2, 400)))
                ]
            if y < 0.85:
                return [line("INFO", ip, user, login("success"))]
            return [
                line("INFO", ip, None, f"cron: backup_{rint(1, 9)} completed")
            ]

        # Avertissements : connexion ratée, page lente, CPU chargé.
        if x < 0.80:
            y = r()
            if y < 0.4:
                return [line("WARNING", ip, user, login("failed"))]
            if y < 0.7:
                return [
                    line(
                        "WARNING",
                        ip,
                        user,
                        http(200, pick(URLS), rint(2000, 9000)),
                    )
                ]
            return [
                line(
                    "WARNING",
                    ip,
                    None,
                    f"CPU at {rint(85, 99)}% on {pick(SERVERS)}",
                )
            ]

        # Erreurs HTTP (4xx et 5xx).
        if x < 0.885:
            code = pick([404, 404, 403, 500, 500, 502, 503])
            return [
                line("ERROR", ip, user, http(code, pick(URLS), rint(1, 30000)))
            ]

        # Messages système en texte brut (carte réseau qui tombe ou revient).
        if x < 0.915:
            state = pick(["up", "down"])
            level = "ERROR" if state == "down" else "INFO"
            return [
                line(level, ip, None, f"kernel: eth{rint(0, 3)} link {state}")
            ]

        if x < 0.935:
            return [invalid_line(ip, user)]

        # Tentative d'injection (SQL, XSS...), surtout depuis la blacklist.
        if x < 0.940:
            stats["injections"] += 1
            attacker = pick(blacklist + external_ips[:50])
            return [
                line(
                    "WARNING",
                    attacker,
                    None,
                    {
                        "attack": "injection",
                        "content": pick(INJECTIONS),
                        "url": pick(URLS),
                        "port": 443,
                        "protocol": "HTTPS",
                    },
                )
            ]

        # Incidents graves, rares.
        if x < 0.9415:
            return [
                line(
                    "CRITICAL",
                    ip,
                    pick(SENSITIVE_ACCOUNTS),
                    pick(CRITICAL_MESSAGES),
                )
            ]

        # Faux positif : quelqu'un se trompe 2 ou 3 fois puis réussit.
        # La détection de force brute ne doit pas le signaler.
        if x < 0.9465:
            stats["faux_positifs"] += 1
            n = rint(2, 3)
            return [
                line("WARNING", ip, user, login("failed")) for _ in range(n)
            ] + [line("INFO", ip, user, login("success"))]

        # Force brute : 5 à 40 échecs d'affilée sur le même compte. Une fois
        # sur quatre, l'attaquant finit par entrer (compte compromis).
        if x < 0.9495:
            stats["force_brute"] += 1
            attacker = pick(blacklist) if r() < 0.5 else pick(external_ips)
            target_user = pick(SENSITIVE_ACCOUNTS) if r() < 0.7 else user
            lines = [
                line("WARNING", attacker, target_user, login("failed"))
                for _ in range(rint(5, 40))
            ]
            if r() < 0.25:
                stats["force_brute_reussie"] += 1
                lines.append(
                    line("INFO", attacker, target_user, login("success"))
                )
            return lines

        # Scan de ports : une IP de la blacklist essaie 10 à 50 ports.
        if x < 0.951:
            stats["scans"] += 1
            scanner = pick(blacklist)
            return [
                line(
                    "WARNING",
                    scanner,
                    None,
                    {
                        "action": "connect",
                        "status": "blocked",
                        "port": p,
                        "protocol": pick(["TCP", "UDP"]),
                    },
                )
                for p in rng.sample(range(1, 10000), rint(10, 50))
            ]

        # Tout le reste : redirections HTTP.
        return [line("INFO", ip, user, http(301, pick(URLS), rint(1, 50)))]

    # On écrit par blocs de BUFFER_LINES lignes : beaucoup plus rapide qu'une
    # écriture par ligne, et la mémoire reste faible. La progression est
    # rafraîchie au plus deux fois par seconde.
    written = 0
    n_lines = 0
    start = time.time()
    last_display = 0.0
    with open(path, "w", encoding="utf-8", newline="", buffering=8 * MB) as f:
        while written < target:
            buffer: list[str] = []
            while len(buffer) < BUFFER_LINES:
                buffer.extend(event())
            block = "".join(buffer)
            f.write(block)
            # Tout est en ASCII, donc un caractère = un octet.
            written += len(block)
            n_lines += len(buffer)
            if time.time() - last_display > 0.5:
                show_progress(written, target, n_lines, start)
                last_display = time.time()
    show_progress(written, target, n_lines, start)
    print()
    return written, n_lines, stats


def print_summary(
    path: Path, written: int, n_lines: int, stats: dict, duration: float
) -> None:
    """Affiche le bilan de la génération."""

    def share(n: int) -> str:
        return f"{n:>13,}  {n / n_lines:6.2%}"

    print(
        f"\nFichier : {path} ({written / MB:,.0f} Mo, {n_lines:,} lignes)"
        f" en {format_duration(duration)}"
    )
    print("\nLignes écrites :")
    print(f"  propres                  {share(stats['propres'])}")
    print(f"  sales mais récupérables  {share(stats['sales'])}")
    print(f"  irrécupérables           {share(stats['irrecuperables'])}")
    print(f"  IP invalides (Module 2)  {share(stats['ip_invalides'])}")
    print("\nScénarios injectés :")
    print(
        f"  attaques force brute     {stats['force_brute']:>13,}"
        f"  (dont {stats['force_brute_reussie']:,} réussies)"
    )
    print(f"  faux positifs            {stats['faux_positifs']:>13,}")
    print(f"  scans de ports           {stats['scans']:>13,}")
    print(f"  tentatives d'injection   {stats['injections']:>13,}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Générateur de faux logs")
    parser.add_argument(
        "--size-gb",
        type=float,
        default=15.0,
        help="taille du fichier en Go (défaut : 15)",
    )
    parser.add_argument(
        "--output", default="data/complet", help="dossier de sortie"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="graine aléatoire (même graine = mêmes logs)",
    )
    args = parser.parse_args()

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    log_path = out / LOG_NAME

    rng = random.Random(args.seed)
    users = build_users(rng)
    blacklist = build_blacklist(rng)
    (out / "blacklist.txt").write_text(
        "\n".join(blacklist) + "\n", encoding="utf-8"
    )

    target = int(args.size_gb * 1024**3)
    print(
        f"Génération de {args.size_gb} Go dans '{log_path}'"
        f" ({len(users)} utilisateurs, {len(blacklist)} IP blacklistées)..."
    )
    start = time.time()
    written, n_lines, stats = generate_log(
        log_path, target, args.seed + 1, blacklist, users
    )
    print_summary(log_path, written, n_lines, stats, time.time() - start)
    print(f"\nBlacklist : {out / 'blacklist.txt'}")


if __name__ == "__main__":
    main()
