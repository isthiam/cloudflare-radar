# Sécurité Internet Mondiale 2025–2026 — Analyse Cloudflare Radar

> **Analyse empirique multidimensionnelle de la sécurité internet mondiale à partir des données Cloudflare Radar API v4 — 11 études, 252 pays, 53 semaines.**

**Auteur :** Issakha Thiam · [Issakha.THIAM@uca.fr](mailto:Issakha.THIAM@uca.fr)  
**Période :** Juin 2025 – Juin 2026

---

## Résultats clés

| # | Étude | Résultat principal |
|---|-------|--------------------|
| 1 | Géopolitique | NA domine TLS 1.3 (71,9 %) ; disparités significatives (KW p=0,011) |
| 2 | Prédiction ARIMA | ISE stable à 79,9 ; IVC prévu en baisse (sélection AIC) |
| 3 | Week-ends | **Aucune différence** WE vs jours ouvrés (p=0,58 ; attaques 100% automatisées) |
| 4 | Effet cascade | **ISE précède IVC de 3–5 semaines** (Granger p<0,01 ; r=−0,566) |
| 5 | CVE critiques | Corrélation CVE→BGP lag +3 sem (ρ=−0,379 ; données simulées) |
| 6 | CISA KEV | 254 KEV réelles en 1 an ; Microsoft 1er ciblé (43 KEV) |
| 7 | Navigateurs | HTTP/3 progresse +1,67 %/an ; Chrome impulse +0,40 pp/release |
| 8 | Inégalités | Fracture IPv6 forte (ρ=0,339) ; TLS 1.3 quasi-homogène mondialement |
| 9 | Clustering | 2 clusters : 56 pays « avancés » vs 138 « intermédiaires » |
| 10 | IQI proxy | **IQI prédit le PIB/hab avec ρ=0,789 et R²=0,618** |
| 11 | IEC/IExC | **Exposition et expérience quasi-indépendantes** (ρ=0,020) — 252 pays × 53 semaines |

---

## Structure du dépôt

```
cloudflare-radar/
│
├── .gitignore
├── LICENSE                              # ODC-By 1.0
├── README.md
├── requirements.txt
│
└── scripts/
    │
    ├── radar_complet_download.py        # Script de collecte Cloudflare Radar API v4
    │
    └── outputs_complet/                 # ════ ANALYSE PRINCIPALE ════
        │
        ├── ── Phases d'analyse A→L ──────────────────────────────────
        ├── phase_A_preparation.py           # Collecte et nettoyage des données
        ├── phase_B_descriptif.py            # Statistiques descriptives
        ├── phase_C_temporel.py              # Analyse temporelle (Mann-Kendall, ADF)
        ├── phase_D_geographique.py          # Analyse géographique (252 pays)
        ├── phase_E_attaques.py              # Attaques L3/L7
        ├── phase_F_email.py                 # Sécurité email (DMARC/DKIM/SPF)
        ├── phase_G_bgp.py                   # BGP hijacking et leaks
        ├── phase_H_correlations.py          # Corrélations et causalité de Granger
        ├── phase_I_clustering.py            # Clustering pays (k-Means)
        ├── phase_J_anomalies.py             # Détection d'anomalies
        ├── phase_K_network.py               # Analyse réseau (graphes ASN)
        ├── phase_L_synthese.py              # Synthèse finale
        ├── rapport_phase_[A-L].md           # 12 rapports de phases
        │
        ├── ── Études thématiques 1→11 ───────────────────────────────
        ├── etude1_geopolitique.py           # Disparités régionales TLS/IPv6
        ├── etude2_prediction.py             # Prédiction ARIMA ISE/IMP/IVC
        ├── etude3_weekends.py               # Rythmes temporels des attaques
        ├── etude4_cascade.py                # Effet cascade email→BGP (Granger)
        ├── etude5_cve.py                    # CVE critiques NVD vs BGP
        ├── etude6_cisa.py                   # CISA KEV (254 vulnérabilités)
        ├── etude7_browsers.py               # Impact navigateurs sur protocoles
        ├── etude8_inegalites.py             # Fracture numérique mondiale
        ├── etude9_clustering.py             # Clustering k-Means (252 pays)
        ├── etude10_iqi_proxy.py             # IQI proxy économique (PIB/hab)
        ├── etude11_vulnerabilite_pays.py    # IEC/IExC — Exposition vs Expérience
        ├── rapport_etude[1-11]_*.md/.docx   # 11 rapports d'études
        │
        ├── ── Rapports de synthèse ──────────────────────────────────
        ├── rapport_synthese_10etudes.md/.docx   # ← SYNTHÈSE PRINCIPALE (4 500 mots)
        ├── rapport_academique.md/.docx/.pdf     # Rapport académique complet
        ├── doc_technique_indices.md/.docx/.pdf  # Documentation ISE, IMP, IVC
        │
        ├── ── Figures (22 PNG) ──────────────────────────────────────
        ├── etude1_regions_boxplot.png / etude1_heatmap.png
        ├── etude2_forecast.png
        ├── etude3_boxplot.png / etude3_timeline.png
        ├── etude4_cascade.png
        ├── etude5_cve_vs_bgp.png / etude5_correlation_lags.png
        ├── etude6_kev_timeline.png / etude6_vendors.png
        ├── etude7_tls_timeline.png / etude7_http3_browsers.png
        ├── etude8_scatter_gdp_tls.png / etude8_boxplot_income.png
        ├── etude9_pca.png / etude9_elbow.png
        ├── etude10_scatter_iqi_gdp.png
        ├── etude11_heatmap_iec.png / etude11_heatmap_iexc.png
        ├── etude11_scatter_iec_iexc.png / etude11_series_globales.png
        │
        ├── ── Données nettoyées (25 CSV) ────────────────────────────
        ├── cleaned/
        │   ├── attacks_l3_bitrate_clean.csv
        │   ├── attacks_l3_ip_version_clean.csv
        │   ├── attacks_l3_protocol_clean.csv
        │   ├── attacks_l7_http_method_clean.csv
        │   ├── attacks_l7_http_version_clean.csv
        │   ├── attacks_l7_vertical_clean.csv
        │   ├── bgp_hijacks_clean.csv
        │   ├── bgp_leaks_clean.csv
        │   ├── bgp_timeseries_clean.csv
        │   ├── dns_timeseries_clean.csv
        │   ├── email_dkim_clean.csv / email_dmarc_clean.csv
        │   ├── email_malicious_clean.csv / email_spam_clean.csv
        │   ├── email_spf_clean.csv / email_spoof_clean.csv
        │   ├── http_bot_class_clean.csv / http_browser_family_clean.csv
        │   ├── http_device_type_clean.csv / http_http_version_clean.csv
        │   ├── http_ip_version_clean.csv / http_os_clean.csv
        │   ├── http_tls_version_clean.csv
        │   ├── iqi_bandwidth_clean.csv
        │   └── iqi_dns_clean.csv
        │
        ├── ── Données brutes par thème ──────────────────────────────
        ├── attacks_l3/   # Bitrate, protocole, IP version (3 CSV)
        ├── attacks_l7/   # Méthode HTTP, vertical, version HTTP (3 CSV)
        ├── bgp/          # Timeseries, hijacks, leaks (3 CSV)
        ├── dns/          # DNS timeseries (1 CSV)
        ├── email/        # DMARC/DKIM/SPF/spam/spoof/malicious (6 CSV)
        ├── http/         # TLS, IPv6, HTTP/3, OS, navigateurs… (7 CSV, 252 pays)
        ├── iqi/          # Bande passante et latence DNS (2 CSV, 252 pays)
        │
        └── etude11_pays_semaine_vulnerabilite.csv  # IEC/IExC pays × semaine
```

---

## Données

Les données proviennent de l'**API Cloudflare Radar v4** (accès libre) :

| Source | Variables | Couverture |
|--------|-----------|------------|
| BGP | Volume de routes, hijacks, leaks | Mondiale, hebdomadaire |
| Email | DMARC/DKIM/SPF, spam, phishing | Mondiale, hebdomadaire |
| HTTP | TLS 1.3/1.2/QUIC, IPv6, HTTP/3 | 252 pays, hebdomadaire |
| IQI | Bande passante (p25/p50/p75), latence DNS | 252 pays, hebdomadaire |
| Attaques L3 | Débit, protocole, version IP | Mondiale, hebdomadaire |
| Attaques L7 | Secteur cible, méthode HTTP | Mondiale, quotidienne |

**Sources externes croisées :**
- [Banque Mondiale API](https://data.worldbank.org/indicator/NY.GDP.PCAP.CD) — PIB/habitant
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — 254 vulnérabilités exploitées
- [NVD NIST](https://nvd.nist.gov/) — CVE critiques (CVSS v3 ≥ 9,0)

---

## Installation

```bash
git clone https://github.com/isthiam/cloudflare-radar.git
cd cloudflare-radar
pip install -r requirements.txt

# Exécuter une étude
cd scripts/outputs_complet
python etude11_vulnerabilite_pays.py
```

> Pour collecter de nouvelles données, stocker la clé API Cloudflare Radar dans un fichier `.env` (non versionné).

---

## Indices composites

| Indice | Définition | Composantes |
|--------|------------|-------------|
| **ISE** | Internet Security Email | DMARC + DKIM + SPF |
| **IMP** | Internet Maturity Protocol | TLS 1.3 + IPv6 + HTTP/3 |
| **IVC** | Internet Vulnerability Composite | ISE + IMP inversé + BGP |
| **IEC** | Indice d'Exposition aux Chocs | IPv4 + vieux TLS + faible bande passante + latence DNS |
| **IExC** | Indice d'Expérience des Chocs | Chutes IQI + pics DNS + BGP hijacks + L3 |

---

## Méthodes statistiques

- **Séries temporelles** : ARIMA (AIC), Mann-Kendall, ADF
- **Causalité** : Granger, cross-corrélation, Pearson/Spearman
- **Tests non paramétriques** : Mann-Whitney U, Kruskal-Wallis, Cohen d
- **Apprentissage non supervisé** : k-Means (silhouette), ACP (PCA)
- **Économétrie** : Régression log-log PIB/IQI, corrélations transnationales
- **Event study** : Fenêtres pré/post release navigateurs

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

Ce projet est distribué sous licence **[Open Data Commons Attribution License (ODC-By) v1.0](https://opendatacommons.org/licenses/by/1-0/)**.

Attribution requise :
> "Contains information from *Cloudflare Radar Security Dataset 2025–2026* by Issakha Thiam, available under ODC-By 1.0 — https://opendatacommons.org/licenses/by/1-0/"

Les données Cloudflare Radar sont soumises aux [Conditions d'utilisation de Cloudflare](https://www.cloudflare.com/terms/).

---

*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*
