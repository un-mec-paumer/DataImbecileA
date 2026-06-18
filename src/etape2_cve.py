"""
Etape 2 : Extraction des CVE depuis les JSON des bulletins ANSSI
Pour chaque bulletin, recupere la liste des CVE mentionnees.
Produit une ligne par combinaison bulletin + CVE.
"""

import requests
import re
import time


CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"


def extraire_cves_depuis_json(bulletin):
    """
    Accede au JSON d'un bulletin ANSSI et extrait les CVEs.
    Le JSON est accessible en ajoutant 'json/' a l'URL du bulletin.

    Retourne une liste de dicts, une entree par CVE trouvee.
    Si aucune CVE, retourne une ligne avec cve_id=None.
    """
    url_json = bulletin["lien"].rstrip("/") + "/json/"
    lignes = []

    try:
        response = requests.get(url_json, timeout=10)
        response.raise_for_status()
        data = response.json()

        cves = []

        # Methode 1 : cle "cves" dans le JSON (liste de dicts avec "name" et "url")
        if "cves" in data and data["cves"]:
            cves = [
                c["name"] for c in data["cves"]
                if isinstance(c, dict) and "name" in c
            ]

        # Methode 2 : regex sur tout le JSON en filet de securite
        if not cves:
            cves = list(set(re.findall(CVE_PATTERN, str(data))))

        if cves:
            for cve_id in cves:
                ligne = bulletin.copy()
                ligne["cve_id"] = cve_id
                lignes.append(ligne)
        else:
            # Bulletin sans CVE identifiee : on garde quand meme la ligne
            ligne = bulletin.copy()
            ligne["cve_id"] = None
            lignes.append(ligne)

        print(f"  {bulletin['id_anssi']} : {len(cves)} CVE(s) trouvee(s)")

    except requests.exceptions.HTTPError as e:
        print(f"  ERREUR HTTP {e.response.status_code} pour {bulletin['id_anssi']}")
        ligne = bulletin.copy()
        ligne["cve_id"] = None
        lignes.append(ligne)

    except requests.exceptions.Timeout:
        print(f"  ERREUR Timeout pour {bulletin['id_anssi']}")
        ligne = bulletin.copy()
        ligne["cve_id"] = None
        lignes.append(ligne)

    except Exception as e:
        print(f"  ERREUR inattendue pour {bulletin['id_anssi']} : {e}")
        ligne = bulletin.copy()
        ligne["cve_id"] = None
        lignes.append(ligne)

    time.sleep(2)  # Rate limiting
    return lignes


def extraire_toutes_cves(bulletins):
    """
    Parcourt tous les bulletins et extrait les CVEs.
    Retourne une liste de dicts prete a etre transformee en DataFrame.
    """
    toutes_lignes = []

    print(f"[CVE] Extraction des CVEs pour {len(bulletins)} bulletins...\n")

    for i, bulletin in enumerate(bulletins, 1):
        print(f"[{i}/{len(bulletins)}] {bulletin['id_anssi']}")
        lignes = extraire_cves_depuis_json(bulletin)
        toutes_lignes.extend(lignes)

    nb_avec_cve = sum(1 for l in toutes_lignes if l["cve_id"] is not None)
    print(f"\n[CVE] Total lignes : {len(toutes_lignes)} ({nb_avec_cve} avec CVE)")
    return toutes_lignes


if __name__ == "__main__":
    bulletin_test = {
        "id_anssi": "CERTFR-2024-ALE-001",
        "titre": "Test",
        "type": "alerte",
        "date": "2024-01-11",
        "description_bulletin": "",
        "lien": "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-001/"
    }
    lignes = extraire_cves_depuis_json(bulletin_test)
    for l in lignes:
        print(l)