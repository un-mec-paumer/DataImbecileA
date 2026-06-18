# Projet de groupe — Analyse des bulletins ANSSI (Élise, Antoine, Hugo Z.)

Projet d'analyse des avis et alertes de sécurité de l'ANSSI avec enrichissement CVE.

## Description

Pipeline Python qui :
1. Extrait les bulletins depuis les flux RSS ANSSI
2. Récupère les CVEs associées
3. Enrichit avec les scores CVSS (MITRE) et EPSS
4. Génère des visualisations et modèles ML

## Installation

```bash
pip install -r requirements.txt
```

## Utilisation

```bash
cd src
python3 etape4_consolidation.py  # génère data/output.csv (~40 min)
python3 etape7_alertes.py        # génère les alertes email
```

Ouvrir ensuite `projet.ipynb` avec Jupyter pour les visualisations et modèles ML.

## Structure

```
src/                  # Scripts Python du pipeline
data/output.csv       # Dataset enrichi généré
projet.ipynb          # Notebook d'analyse
projet.html           # Export HTML du notebook
rss_anssi_local.csv   # Données RSS fournies
```