"""
Etape 1 : Extraction des flux RSS ANSSI
Recupere la liste des bulletins (avis + alertes) depuis les flux RSS de l'ANSSI.
"""

import feedparser
import time
from datetime import datetime


URLS_RSS = {
    "avis": "https://www.cert.ssi.gouv.fr/avis/feed/",
    "alerte": "https://www.cert.ssi.gouv.fr/alerte/feed/"
}


def parser_date(date_str):
    """Convertit la date RSS en format standard YYYY-MM-DD."""
    try:
        return datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %z").strftime("%Y-%m-%d")
    except Exception:
        return date_str


def extraire_id_anssi(lien):
    """
    Extrait l'ID ANSSI depuis l'URL du bulletin.
    Ex: https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0632/ -> CERTFR-2026-AVI-0632
    """
    return lien.rstrip("/").split("/")[-1]


def recuperer_bulletins():
    """
    Parcourt les deux flux RSS (avis + alertes) et retourne
    une liste de dicts representant chaque bulletin.
    """
    bulletins = []

    for type_bulletin, url in URLS_RSS.items():
        print(f"[RSS] Recuperation des {type_bulletin}s depuis {url}")
        try:
            feed = feedparser.parse(url)

            if feed.bozo:
                print(f"  [AVERTISSEMENT] Flux mal forme pour {type_bulletin}, tentative quand meme...")

            for entry in feed.entries:
                lien = entry.get("link", "")
                bulletins.append({
                    "id_anssi": extraire_id_anssi(lien),
                    "titre": entry.get("title", "Sans titre"),
                    "type": type_bulletin,
                    "date": parser_date(entry.get("published", "")),
                    "description_bulletin": entry.get("summary", ""),
                    "lien": lien
                })

            print(f"  OK - {len(feed.entries)} bulletins recuperes pour les {type_bulletin}s")

        except Exception as e:
            print(f"  ERREUR lors de la recuperation des {type_bulletin}s : {e}")

        time.sleep(2)  # Rate limiting : respecter les serveurs ANSSI

    print(f"\n[RSS] Total : {len(bulletins)} bulletins recuperes")
    return bulletins


if __name__ == "__main__":
    bulletins = recuperer_bulletins()
    for b in bulletins[:3]:
        print(b)