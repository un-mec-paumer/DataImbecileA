"""
Etape 7 : Generation d'alertes personnalisees et notifications email
Filtre les vulnerabilites critiques et genere des alertes ciblees par produit.
L'envoi reel de l'email est optionnel (configurer EMAIL_CONFIG).
"""

import os
import pandas as pd
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime


CSV_PATH = os.path.join(os.path.dirname(__file__), "../data/output.csv")

# Seuils d'alerte
SEUIL_CVSS_CRITIQUE = 9.0
SEUIL_EPSS = 0.7

# Configuration email
EMAIL_CONFIG = {
    "from_email": "votre_email@gmail.com",
    "password": "mot_de_passe_application",
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587
}

# Produits surveilles
PRODUITS_SURVEILLES = [
    "Apache", "Windows", "Chrome", "Firefox",
    "Cisco", "VMware", "Ivanti", "Fortinet"
]


def filtrer_vulnerabilites_critiques(df):
    """
    Filtre les CVEs necessitant une alerte urgente :
    - Score CVSS >= 9.0
    - Score EPSS >= 0.7 (forte probabilite d'exploitation)
    - Type = alerte ANSSI (vulnerabilite activement exploitee)
    """
    masque = (
            (df["cvss_score"] >= SEUIL_CVSS_CRITIQUE) |
            (df["epss_score"] >= SEUIL_EPSS) |
            (df["type"] == "alerte")
    )
    df_critique = df[masque].copy()
    df_critique = df_critique.drop_duplicates(subset=["cve_id"])
    return df_critique


def filtrer_par_produit(df, produit):
    """Filtre les CVEs affectant un produit specifique."""
    masque = (
            df["product"].str.contains(produit, case=False, na=False) |
            df["vendor"].str.contains(produit, case=False, na=False)
    )
    return df[masque]


def generer_sujet(df_alerte, produit=None):
    """Genere le sujet de l'email d'alerte."""
    nb = len(df_alerte)
    date = datetime.now().strftime("%d/%m/%Y")
    if produit:
        return f"[{date}] {nb} vulnerabilite(s) critique(s) detectee(s) - {produit}"
    return f"[{date}] {nb} vulnerabilite(s) critique(s) detectee(s) - Veille ANSSI"


def generer_corps_email(df_alerte, produit=None):
    """
    Genere le corps HTML de l'email d'alerte.
    Liste les CVEs critiques avec leurs informations cles.
    """
    date = datetime.now().strftime("%d/%m/%Y a %H:%M")
    nb = len(df_alerte)

    lignes_cve = ""
    for _, row in df_alerte.iterrows():
        cvss = f"{row['cvss_score']:.1f}" if pd.notna(row.get("cvss_score")) else "N/A"
        epss = f"{float(row['epss_score']):.2%}" if pd.notna(row.get("epss_score")) else "N/A"
        severity = row.get("base_severity", "N/A") or "N/A"
        produit_ligne = row.get("product", "N/A") or "N/A"
        vendor_ligne = row.get("vendor", "N/A") or "N/A"
        cwe = row.get("cwe_id", "N/A") or "N/A"
        lien = row.get("lien", "#")
        description = str(row.get("description", ""))[:200] + "..." if row.get("description") else "N/A"

        lignes_cve += f"""
        <tr>
            <td><strong>{row['cve_id']}</strong></td>
            <td style="color: red;">{cvss} ({severity})</td>
            <td>{epss}</td>
            <td>{vendor_ligne} - {produit_ligne}</td>
            <td>{cwe}</td>
            <td><a href="{lien}">Voir le bulletin</a></td>
        </tr>
        <tr>
            <td colspan="6" style="color: gray; font-size: 0.9em;">{description}</td>
        </tr>
        """

    corps = f"""
    <html>
    <body style="font-family: Arial, sans-serif; color: #333;">
        <h2 style="color: #cc0000;">Alerte Cybersecurite - Veille ANSSI</h2>
        <p>Date de generation : <strong>{date}</strong></p>
        <p>
            {'Produit surveille : <strong>' + produit + '</strong><br>' if produit else ''}
            <strong>{nb}</strong> vulnerabilite(s) critique(s) detectee(s).
        </p>
        <h3>Detail des vulnerabilites</h3>
        <table border="1" cellpadding="8" cellspacing="0"
               style="border-collapse: collapse; width: 100%;">
            <thead style="background-color: #cc0000; color: white;">
                <tr>
                    <th>CVE</th>
                    <th>CVSS</th>
                    <th>EPSS</th>
                    <th>Produit</th>
                    <th>CWE</th>
                    <th>Bulletin</th>
                </tr>
            </thead>
            <tbody>
                {lignes_cve}
            </tbody>
        </table>
        <br>
        <p style="color: gray; font-size: 0.85em;">
            Message genere automatiquement par le systeme de veille ANSSI.<br>
            Sources : <a href="https://www.cert.ssi.gouv.fr">cert.ssi.gouv.fr</a> |
            <a href="https://cveawg.mitre.org">MITRE CVE</a> |
            <a href="https://api.first.org">FIRST EPSS</a>
        </p>
    </body>
    </html>
    """
    return corps


def envoyer_email(to_email, sujet, corps_html, simuler=True):
    """
    Envoie un email HTML d'alerte.
    Si simuler=True, affiche l'email sans l'envoyer reellement.
    """
    if simuler:
        print("\n" + "-" * 60)
        print("SIMULATION ENVOI EMAIL")
        print("-" * 60)
        print(f"Destinataire : {to_email}")
        print(f"Sujet        : {sujet}")
        print(f"Corps        : {len(corps_html)} caracteres (HTML)")
        print("-" * 60)
        print("Simulation terminee - email non envoye")
        return True

    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = EMAIL_CONFIG["from_email"]
        msg["To"] = to_email
        msg["Subject"] = sujet
        msg.attach(MIMEText(corps_html, "html"))

        with smtplib.SMTP(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"]) as server:
            server.starttls()
            server.login(EMAIL_CONFIG["from_email"], EMAIL_CONFIG["password"])
            server.sendmail(EMAIL_CONFIG["from_email"], to_email, msg.as_string())

        print(f"Email envoye a {to_email}")
        return True

    except smtplib.SMTPAuthenticationError:
        print("Erreur d'authentification SMTP - verifiez vos identifiants")
    except smtplib.SMTPException as e:
        print(f"Erreur SMTP : {e}")
    except Exception as e:
        print(f"Erreur inattendue : {e}")

    return False


def generer_alertes(csv_path=CSV_PATH, destinataire="admin@exemple.com", simuler=True):
    """
    Pipeline de generation d'alertes :
    1. Charge le CSV
    2. Filtre les CVEs critiques
    3. Genere et envoie les emails par produit surveille
    """
    print("\n[ALERTES] Chargement du CSV...")
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        print(f"Fichier CSV introuvable : {csv_path}")
        print("Lancez d'abord etape4_consolidation.py")
        return

    print(f"[ALERTES] {len(df)} lignes chargees")

    df_critique = filtrer_vulnerabilites_critiques(df)
    print(f"[ALERTES] {len(df_critique)} CVEs critiques identifiees")

    if not df_critique.empty:
        sujet = generer_sujet(df_critique)
        corps = generer_corps_email(df_critique)
        envoyer_email(destinataire, sujet, corps, simuler=simuler)

    for produit in PRODUITS_SURVEILLES:
        df_produit = filtrer_par_produit(df_critique, produit)
        if not df_produit.empty:
            print(f"\n[ALERTES] {len(df_produit)} CVEs critiques pour {produit}")
            sujet = generer_sujet(df_produit, produit=produit)
            corps = generer_corps_email(df_produit, produit=produit)
            envoyer_email(destinataire, sujet, corps, simuler=simuler)


if __name__ == "__main__":
    # Passer simuler=False pour envoyer reellement (configurer EMAIL_CONFIG)
    generer_alertes(simuler=True)