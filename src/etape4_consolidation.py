"""
Etape 4 : Consolidation des donnees en DataFrame Pandas et export CSV
Assemble les donnees des etapes 1, 2 et 3 en un seul fichier CSV exploitable.
"""

import os
import pandas as pd
from etape1_rss import recuperer_bulletins
from etape2_cve import extraire_toutes_cves
from etape3_enrichissement import enrichir_cves


OUTPUT_CSV = os.path.join(os.path.dirname(__file__), "../data/output.csv")


def construire_dataframe(lignes_bulletins, enrichissements):
    """
    Fusionne les lignes bulletin+CVE avec les donnees d'enrichissement.
    Retourne un DataFrame pandas avec toutes les colonnes.
    """
    df = pd.DataFrame(lignes_bulletins)
    df_enrichi = pd.DataFrame(list(enrichissements.values()))

    # Left join pour garder les bulletins sans CVE
    df_final = df.merge(df_enrichi, on="cve_id", how="left")

    colonnes = [
        "id_anssi",
        "titre",
        "type",
        "date",
        "lien",
        "description_bulletin",
        "cve_id",
        "cvss_score",
        "base_severity",
        "cwe_id",
        "cwe_description",
        "epss_score",
        "description",
        "vendor",
        "product",
        "versions_affectees"
    ]

    colonnes_presentes = [c for c in colonnes if c in df_final.columns]
    df_final = df_final[colonnes_presentes]

    return df_final


def afficher_stats(df):
    """Affiche un resume du DataFrame produit."""
    print("\n" + "-" * 50)
    print("RESUME DU DATASET")
    print("-" * 50)
    print(f"Nombre total de lignes     : {len(df)}")
    print(f"Nombre de bulletins uniques: {df['id_anssi'].nunique()}")
    print(f"Nombre de CVEs uniques     : {df['cve_id'].nunique()}")
    print(f"Bulletins de type avis     : {len(df[df['type'] == 'avis'])}")
    print(f"Bulletins de type alerte   : {len(df[df['type'] == 'alerte'])}")
    print(f"CVEs avec score CVSS       : {df['cvss_score'].notna().sum()}")
    print(f"CVEs avec score EPSS       : {df['epss_score'].notna().sum()}")
    print(f"CVEs Critical (CVSS >= 9)  : {len(df[df['cvss_score'] >= 9.0])}")
    print("-" * 50)
    print("\nApercu :")
    print(df.head(3).to_string())


def pipeline_complet():
    """
    Lance le pipeline complet :
    1. Recupere les bulletins RSS
    2. Extrait les CVEs par bulletin
    3. Enrichit les CVEs uniques via MITRE et EPSS
    4. Consolide en DataFrame et exporte en CSV
    """
    print("\n--- ETAPE 1 : Recuperation des flux RSS ---")
    bulletins = recuperer_bulletins()

    print("\n--- ETAPE 2 : Extraction des CVEs ---")
    lignes = extraire_toutes_cves(bulletins)

    cves_uniques = list(set(
        l["cve_id"] for l in lignes
        if l["cve_id"] is not None
    ))

    print("\n--- ETAPE 3 : Enrichissement des CVEs ---")
    enrichissements = enrichir_cves(cves_uniques)

    print("\n--- ETAPE 4 : Consolidation ---")
    df = construire_dataframe(lignes, enrichissements)

    df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8")
    print(f"\nCSV exporte : {OUTPUT_CSV}")

    afficher_stats(df)
    return df


if __name__ == "__main__":
    df = pipeline_complet()