# Sécurité Internet Mondiale 2025–2026 — Analyse Cloudflare Radar

> **Analyse empirique multidimensionnelle de la sécurité internet mondiale à partir des données Cloudflare Radar API v4 — 10 études, 252 pays, 53 semaines.**

**Auteur :** Issakha Thiam · [Issakha.THIAM@uca.fr](mailto:Issakha.THIAM@uca.fr)
**Période :** Juin 2025 – Juin 2026

---

## Résultats clés

| # | Étude | Résultat principal |
|---|-------|--------------------|
| 1 | Géopolitique | NA domine TLS 1.3 (71,9 %) ; disparités significatives (KW p=0,011) |
| 2 | Prédiction ARIMA | ISE stable à 79,9 ; IVC prévu en baisse (ARIMA sélection AIC) |
| 3 | Week-ends | **Aucune différence** WE vs jours ouvrés (p=0,58 ; attaques 100% automatisées) |
| 4 | Effet cascade | **ISE précède IVC de 3–5 semaines** (Granger p<0,01 ; r=−0,566) |
| 5 | CVE critiques | Corrélation CVE→BGP lag +3 sem (ρ=−0,379 ; données simulées) |
| 6 | CISA KEV | 254 KEV réelles en 1 an ; Microsoft 1er ciblé (43 KEV) |
| 7 | Navigateurs | HTTP/3 progresse +1,67 %/an ; Chrome impulse +0,40 pp/release |
| 8 | Inégalités | Fracture IPv6 forte (ρ=0,339) ; TLS 1.3 quasi-homogène mondialement |
| 9 | Clustering | 2 clusters : 56 pays « avancés » vs 138 « intermédiaires » |
| 10 | IQI proxy | **IQI prédit le PIB/hab avec ρ=0,789 et R²=0,618** |

---

## Structure du dépôt

```
├── scripts/
│   └── outputs_complet/
│       ├── phase_A_preparation.py   # Collecte et nettoyage des données
│       ├── phase_B_descriptif.py    # Statistiques descriptives
│       ├── phase_C_temporel.py      # Analyse temporelle (Mann-Kendall, ADF)
│       ├── phase_D_geographique.py  # Analyse géographique par pays
│       ├── phase_E_attaques.py      # Analyse des attaques L3/L7
│       ├── phase_F_email.py         # Sécurité email (DMARC/DKIM/SPF)
│       ├── phase_G_bgp.py           # BGP hijacking et leaks
│       ├── phase_H_correlations.py  # Corrélations et causalité de Granger
│       ├── phase_I_clustering.py    # Clustering pays (k-Means)
│       ├── phase_J_anomalies.py     # Détection d'anomalies
│       ├── phase_K_network.py       # Analyse réseau (graphes)
│       ├── phase_L_synthese.py      # Synthèse finale
│       │
│       ├── etude1_geopolitique.py   # Étude 1 — Disparités régionales
│       ├── etude2_prediction.py     # Étude 2 — Prédiction ARIMA
│       ├── etude3_weekends.py       # Étude 3 — Rythmes temporels
│       ├── etude4_cascade.py        # Étude 4 — Effet cascade email→BGP
│       ├── etude5_cve.py            # Étude 5 — CVE critiques NVD
│       ├── etude6_cisa.py           # Étude 6 — CISA KEV
│       ├── etude7_browsers.py       # Étude 7 — Impact navigateurs
│       ├── etude8_inegalites.py     # Étude 8 — Fracture numérique
│       ├── etude9_clustering.py     # Étude 9 — Clustering k-Means
│       ├── etude10_iqi_proxy.py     # Étude 10 — IQI proxy économique
│       │
│       ├── cleaned/                 # Données Cloudflare nettoyées (CSV)
│       │   ├── bgp_timeseries_clean.csv
│       │   ├── email_dmarc_clean.csv
│       │   ├── http_tls_version_clean.csv
│       │   └── ...                  # 25 fichiers CSV
│       │
│       ├── rapport_synthese_10etudes.md   # ← RAPPORT DE SYNTHÈSE PRINCIPAL
│       ├── rapport_synthese_10etudes.docx
│       ├── rapport_etude[1-10]_*.md       # Rapports individuels (Markdown)
│       ├── rapport_etude[1-10]_*.docx     # Rapports individuels (Word)
│       └── rapport_academique.md          # Rapport académique complet
```

---

## Données

Les données proviennent de l'**API Cloudflare Radar v4** (accès libre) et couvrent :

| Source | Variables | Couverture |
|--------|-----------|------------|
| BGP | Volume de routes, hijacks, leaks | Mondiale, hebdomadaire |
| Email | DMARC/DKIM/SPF, spam, phishing | Mondiale, hebdomadaire |
| HTTP | TLS 1.3/1.2/QUIC, IPv6, HTTP/3 | 252 pays, hebdomadaire |
| IQI | Bande passante (p25/p50/p75) | 252 pays, hebdomadaire |
| Attaques L3 | Débit, protocole, version IP | Mondiale, hebdomadaire |
| Attaques L7 | Secteur cible, méthode HTTP | Mondiale, quotidienne |

**Sources externes croisées :**
- [Banque Mondiale API](https://data.worldbank.org/indicator/NY.GDP.PCAP.CD) — PIB/habitant, classification des revenus
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — 254 vulnérabilités activement exploitées
- [NVD NIST](https://nvd.nist.gov/) — CVE critiques (CVSS v3 ≥ 9,0)

---

## Installation et utilisation

```bash
# Cloner le dépôt
git clone https://github.com/isthiam/cloudflare-radar.git
cd cloudflare-radar

# Installer les dépendances Python
pip install -r requirements.txt

# Exécuter une étude (exemple : Étude 4 — Effet cascade)
cd scripts/outputs_complet
python etude4_cascade.py
```

> **Note :** Pour collecter de nouvelles données Cloudflare Radar, vous aurez besoin d'une clé API gratuite obtenue sur [dash.cloudflare.com](https://dash.cloudflare.com/profile/api-tokens). Stockez-la dans un fichier `.env` (non versionné).

---

## Rapports disponibles

| Document | Format | Description |
|----------|--------|-------------|
| [`rapport_synthese_10etudes.md`](scripts/outputs_complet/rapport_synthese_10etudes.md) | Markdown | **Synthèse principale — 10 études, 4 500 mots** |
| [`rapport_academique.md`](scripts/outputs_complet/rapport_academique.md) | Markdown | Rapport académique complet (50 Ko) |
| [`doc_technique_indices.md`](scripts/outputs_complet/doc_technique_indices.md) | Markdown | Documentation des indices ISE, IMP, IVC |
| `rapport_etude[1-10]_*.md` | Markdown | 10 rapports d'études individuels |
| `*.docx` | Word | Versions formatées de tous les rapports |

---

## Méthodes statistiques utilisées

- **Séries temporelles** : ARIMA (sélection AIC), Mann-Kendall, ADF (stationnarité)
- **Causalité** : Test de Granger, cross-corrélation, corrélation de Pearson/Spearman
- **Tests non paramétriques** : Mann-Whitney U, Kruskal-Wallis, Cohen d
- **Apprentissage non supervisé** : k-Means (sélection silhouette), ACP (PCA)
- **Économétrie spatiale** : Régression log-log PIB/IQI, corrélations transnationales
- **Event study** : Fenêtres pré/post release navigateurs

---

## Figures générées

| Fichier | Étude | Description |
|---------|-------|-------------|
| `etude1_regions_boxplot.png` | 1 | Adoption TLS 1.3 par région mondiale |
| `etude2_forecast.png` | 2 | Prévision ARIMA ISE/IMP/IVC +4 semaines |
| `etude3_boxplot.png` | 3 | Attaques L7 par jour de la semaine |
| `etude4_cascade.png` | 4 | Cross-corrélogramme ISE ↔ IVC |
| `etude5_cve_vs_bgp.png` | 5 | CVE critiques vs volume BGP |
| `etude6_kev_timeline.png` | 6 | Timeline CISA KEV vs BGP hijacks |
| `etude7_tls_timeline.png` | 7 | TLS 1.3 avec marqueurs releases Chrome |
| `etude8_scatter_gdp_tls.png` | 8 | PIB/habitant vs adoption TLS 1.3 |
| `etude9_pca.png` | 9 | Clustering PCA 2D (252 pays) |
| `etude10_scatter_iqi_gdp.png` | 10 | IQI bande passante vs PIB/habitant |

---

## Citation

```bibtex
@misc{thiam2026cloudflare,
  author    = {Thiam, Issakha},
  title     = {Sécurité Internet Mondiale 2025–2026 : Analyse Empirique Cloudflare Radar},
  year      = {2026},
  publisher = {GitHub},
  url       = {https://github.com/isthiam/cloudflare-radar}
}
```

---

## Licence

Ce projet est distribué sous licence **MIT** pour le code, et **Creative Commons CC BY 4.0** pour les rapports et figures.

Les données Cloudflare Radar sont soumises aux [Conditions d'utilisation de Cloudflare](https://www.cloudflare.com/terms/).

---

*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*
