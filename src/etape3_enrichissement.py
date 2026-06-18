"""
Etape 3 : Enrichissement des CVEs via les API MITRE et EPSS
- API MITRE : score CVSS, type CWE, description, editeur, produit, versions
- API EPSS  : probabilite d'exploitation (score entre 0 et 1)
"""

import requests
import time


def get_severity(score):
    """Convertit un score CVSS en niveau de gravite textuel."""
    if score is None:
        return None
    score = float(score)
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    else:
        return "Low"


def extraire_cvss(metrics):
    """
    Tente d'extraire le score CVSS depuis le champ metrics.
    Essaie cvssV3_1, cvssV3_0, cvssV2_0 dans cet ordre.
    """
    if not metrics:
        return None, None

    for metric in metrics:
        for version in ["cvssV3_1", "cvssV3_0", "cvssV2_0"]:
            if version in metric:
                score = metric[version].get("baseScore")
                severity = metric[version].get("baseSeverity") or get_severity(score)
                return score, severity

    return None, None


def enrichir_mitre(cve_id):
    """
    Interroge l'API MITRE pour un CVE donne.
    Retourne un dict avec description, cvss_score, base_severity,
    cwe_id, cwe_description, vendor, product, versions_affectees.
    """
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    resultat = {
        "description": None,
        "cvss_score": None,
        "base_severity": None,
        "cwe_id": None,
        "cwe_description": None,
        "vendor": None,
        "product": None,
        "versions_affectees": None
    }

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        cna = data.get("containers", {}).get("cna", {})

        descriptions = cna.get("descriptions", [])
        if descriptions:
            resultat["description"] = descriptions[0].get("value")

        metrics = cna.get("metrics", [])
        resultat["cvss_score"], resultat["base_severity"] = extraire_cvss(metrics)

        problem_types = cna.get("problemTypes", [])
        if problem_types:
            descs = problem_types[0].get("descriptions", [])
            if descs:
                resultat["cwe_id"] = descs[0].get("cweId", "Non disponible")
                resultat["cwe_description"] = descs[0].get("description", "Non disponible")

        affected = cna.get("affected", [])
        if affected:
            premier = affected[0]
            resultat["vendor"] = premier.get("vendor")
            resultat["product"] = premier.get("product")
            versions = [
                v["version"] for v in premier.get("versions", [])
                if v.get("status") == "affected"
            ]
            resultat["versions_affectees"] = ", ".join(versions) if versions else None

    except requests.exceptions.HTTPError as e:
        print(f"    MITRE HTTP {e.response.status_code} pour {cve_id}")
    except requests.exceptions.Timeout:
        print(f"    MITRE Timeout pour {cve_id}")
    except Exception as e:
        print(f"    MITRE erreur pour {cve_id} : {e}")

    return resultat


def enrichir_epss(cve_id):
    """
    Interroge l'API EPSS (FIRST) pour un CVE donne.
    Retourne le score EPSS (float entre 0 et 1) ou None.
    """
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        epss_data = data.get("data", [])
        if epss_data:
            return float(epss_data[0].get("epss", 0))

    except requests.exceptions.HTTPError as e:
        print(f"    EPSS HTTP {e.response.status_code} pour {cve_id}")
    except requests.exceptions.Timeout:
        print(f"    EPSS Timeout pour {cve_id}")
    except Exception as e:
        print(f"    EPSS erreur pour {cve_id} : {e}")

    return None


def enrichir_cves(cves_uniques):
    """
    Pour une liste de CVE IDs uniques, interroge MITRE + EPSS
    et retourne un dict {cve_id: donnees enrichies}.
    On n'appelle les API qu'une seule fois par CVE unique.
    """
    enrichissements = {}

    print(f"[ENRICHISSEMENT] {len(cves_uniques)} CVEs uniques a enrichir...\n")

    for i, cve_id in enumerate(cves_uniques, 1):
        print(f"  [{i}/{len(cves_uniques)}] {cve_id}")

        donnees = {"cve_id": cve_id}

        mitre = enrichir_mitre(cve_id)
        donnees.update(mitre)
        time.sleep(2)  # Rate limiting

        donnees["epss_score"] = enrichir_epss(cve_id)
        time.sleep(2)  # Rate limiting

        enrichissements[cve_id] = donnees

    print(f"\n[ENRICHISSEMENT] Termine : {len(enrichissements)} CVEs enrichies")
    return enrichissements


if __name__ == "__main__":
    cves_test = ["CVE-2023-46805", "CVE-2023-24488"]
    resultats = enrichir_cves(cves_test)
    for cve_id, data in resultats.items():
        print(f"\n{cve_id}:")
        for k, v in data.items():
            print(f"  {k}: {v}")