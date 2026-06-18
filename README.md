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
├── LICENSE                          # ODC-By 1.0
├── README.md
├── requirements.txt
│
└── scripts/
    │
    ├── radar_complet_download.py    # ← Script principal de collecte (API v4)
    │
    ├── outputs_complet/             # ════ ANALYSE PRINCIPALE ════
    │   │
    │   ├── ── Phases d'analyse A→L ──────────────────────────────
    │   ├── phase_A_preparation.py       # Collecte et nettoyage des données
    │   ├── phase_B_descriptif.py        # Statistiques descriptives
    │   ├── phase_C_temporel.py          # Analyse temporelle (Mann-Kendall, ADF)
    │   ├── phase_D_geographique.py      # Analyse géographique par pays
    │   ├── phase_E_attaques.py          # Analyse des attaques L3/L7
    │   ├── phase_F_email.py             # Sécurité email (DMARC/DKIM/SPF)
    │   ├── phase_G_bgp.py               # BGP hijacking et leaks
    │   ├── phase_H_correlations.py      # Corrélations et causalité de Granger
    │   ├── phase_I_clustering.py        # Clustering pays (k-Means)
    │   ├── phase_J_anomalies.py         # Détection d'anomalies
    │   ├── phase_K_network.py           # Analyse réseau (graphes ASN)
    │   ├── phase_L_synthese.py          # Synthèse finale
    │   │
    │   ├── rapport_phase_A.md → rapport_phase_L_synthese.md   # 12 rapports phases
    │   │
    │   ├── ── Études thématiques ────────────────────────────────
    │   ├── etude1_geopolitique.py       # Disparités régionales TLS/IPv6
    │   ├── etude2_prediction.py         # Prédiction ARIMA ISE/IMP/IVC
    │   ├── etude3_weekends.py           # Rythmes temporels des attaques
    │   ├── etude4_cascade.py            # Effet cascade email→BGP (Granger)
    │   ├── etude5_cve.py                # CVE critiques NVD vs BGP
    │   ├── etude6_cisa.py               # CISA KEV (254 vulnérabilités)
    │   ├── etude7_browsers.py           # Impact navigateurs sur protocoles
    │   ├── etude8_inegalites.py         # Fracture numérique mondiale
    │   ├── etude9_clustering.py         # Clustering k-Means (252 pays)
    │   ├── etude10_iqi_proxy.py         # IQI proxy économique (PIB/hab)
    │   ├── etude11_vulnerabilite_pays.py # IEC/IExC — Exposition vs Expérience
    │   │
    │   ├── rapport_etude1_geopolitique.md/.docx
    │   ├── rapport_etude2_prediction.md/.docx
    │   ├── rapport_etude3_weekends.md/.docx
    │   ├── rapport_etude4_cascade.md/.docx
    │   ├── rapport_etude5_cve.md/.docx
    │   ├── rapport_etude6_cisa.md/.docx
    │   ├── rapport_etude7_browsers.md/.docx
    │   ├── rapport_etude8_inegalites.md/.docx
    │   ├── rapport_etude9_clustering.md/.docx
    │   ├── rapport_etude10_iqi_proxy.md/.docx
    │   ├── rapport_etude11_vulnerabilite_pays.md
    │   │
    │   ├── ── Rapports de synthèse ──────────────────────────────
    │   ├── rapport_synthese_10etudes.md/.docx   # ← SYNTHÈSE PRINCIPALE
    │   ├── rapport_academique.md/.docx/.pdf     # Rapport académique complet
    │   ├── doc_technique_indices.md/.docx/.pdf  # Documentation ISE, IMP, IVC
    │   ├── analyse_statistique_proposition.md   # Proposition initiale d'analyse
    │   │
    │   ├── ── Figures générées ──────────────────────────────────
    │   ├── etude1_regions_boxplot.png    etude1_heatmap.png
    │   ├── etude2_forecast.png
    │   ├── etude3_boxplot.png            etude3_timeline.png
    │   ├── etude4_cascade.png
    │   ├── etude5_cve_vs_bgp.png         etude5_correlation_lags.png
    │   ├── etude6_kev_timeline.png       etude6_vendors.png
    │   ├── etude7_tls_timeline.png       etude7_http3_browsers.png
    │   ├── etude8_scatter_gdp_tls.png    etude8_boxplot_income.png
    │   ├── etude9_pca.png                etude9_elbow.png
    │   ├── etude10_scatter_iqi_gdp.png
    │   ├── etude11_heatmap_iec.png       etude11_heatmap_iexc.png
    │   ├── etude11_scatter_iec_iexc.png  etude11_series_globales.png
    │   │
    │   ├── ── Données nettoyées (25 CSV) ────────────────────────
    │   ├── cleaned/
    │   │   ├── attacks_l3_bitrate_clean.csv
    │   │   ├── attacks_l3_ip_version_clean.csv
    │   │   ├── attacks_l3_protocol_clean.csv
    │   │   ├── attacks_l7_http_method_clean.csv
    │   │   ├── attacks_l7_http_version_clean.csv
    │   │   ├── attacks_l7_vertical_clean.csv
    │   │   ├── bgp_hijacks_clean.csv
    │   │   ├── bgp_leaks_clean.csv
    │   │   ├── bgp_timeseries_clean.csv
    │   │   ├── dns_timeseries_clean.csv
    │   │   ├── email_dkim_clean.csv
    │   │   ├── email_dmarc_clean.csv
    │   │   ├── email_malicious_clean.csv
    │   │   ├── email_spam_clean.csv
    │   │   ├── email_spf_clean.csv
    │   │   ├── email_spoof_clean.csv
    │   │   ├── http_bot_class_clean.csv
    │   │   ├── http_browser_family_clean.csv
    │   │   ├── http_device_type_clean.csv
    │   │   ├── http_http_version_clean.csv
    │   │   ├── http_ip_version_clean.csv
    │   │   ├── http_os_clean.csv
    │   │   ├── http_tls_version_clean.csv
    │   │   ├── iqi_bandwidth_clean.csv
    │   │   └── iqi_dns_clean.csv
    │   │
    │   ├── ── Données brutes par thème ──────────────────────────
    │   ├── attacks_l3/                   # Attaques L3 (bitrate, protocole, IP version)
    │   ├── attacks_l7/                   # Attaques L7 (méthode HTTP, vertical, version)
    │   ├── bgp/                          # BGP (timeseries, hijacks, leaks)
    │   ├── dns/                          # DNS timeseries
    │   ├── email/                        # Email (DMARC/DKIM/SPF/spam/spoof/malicious)
    │   ├── http/                         # HTTP par pays (TLS, IPv6, HTTP/3, OS…)
    │   ├── iqi/                          # IQI par pays (bande passante, latence DNS)
    │   │
    │   └── etude11_pays_semaine_vulnerabilite.csv  # Données IEC/IExC pays × semaine
    │
    ├── ── Scripts de collecte ───────────────────────────────────
    ├── radar_donnees_brutes_4ans.py          # Collecte 4 ans de données brutes
    ├── radar_vulnerabilite_4ans_multithread.py
    ├── radar_full_7piliers.py                # 7 piliers de sécurité
    ├── radar_attacks_l3_daily_by_country.py
    ├── radar_attacks_l3_daily_bytes_by_country.py
    ├── radar_attacks_l3_daily_value_by_country.py
    ├── radar_attacks_l3_stable.py
    ├── radar_iqi_outages_by_country_stable.py
    ├── radar_iqi_outages_stable.py
    ├── radar_l3_bytes_daily_world_5y.py
    ├── radar_http_adm1_world_v2_light.py     # Données ADM1 sous-nationales
    ├── radar_http_adm1_world_robust.ipynb
    │
    ├── ── Scripts d'analyse exploratoire ───────────────────────
    ├── analyze_hurst_ipv4_daily_multicountry.py
    ├── analyze_hurst_layer3_bytes_daily.py
    ├── radar_hurst_multicountry.py           # Exposant de Hurst (mémoire longue)
    ├── simulate_and_analyze_alpha_h.py
    ├── simulate_paper_processes.py
    ├── verifier_hypotheses.py
    ├── verifier_hypotheses_FRA_niveau.py
    ├── pilier1.py
    ├── programme01.py
    ├── programme02_export_excel.py
    ├── programme03_vulnerability.py
    ├── cinq_pays.py
    ├── date.py
    ├── fix_l7.py
    ├── hurst.py
    ├── make_graphs_radar_layer3_bytes.py
    │
    ├── ── Données ADM1 sous-nationales ─────────────────────────
    ├── radar_adm1_timeseries_all_countries.csv      # ~82 MB
    ├── radar_adm1_timeseries_all_countries_async.csv # ~86 MB
    ├── radar_adm1_geolocations_cache.csv
    ├── radar_adm1_geolocations_cache_async.csv
    ├── radar_adm1_missing_geolocations_async.csv
    ├── radar_adm1_timeseries_errors.csv
    ├── radar_adm1_timeseries_errors_async.csv
    ├── radar_adm1_timeseries_meta.csv
    ├── radar_adm1_timeseries_meta_async.csv
    ├── cloudflare_radar_adm1_all_countries_3_metrics.csv
    ├── cloudflare_radar_adm1_errors.csv
    ├── radar_adm1_analysis.xlsx
    ├── outputs_radar_adm1/                   # Données brutes ADM1 (JSON)
    ├── outputs_regions_world/                # Couverture ADM1 mondiale v1
    ├── outputs_regions_world_v2_light/       # Couverture ADM1 mondiale v2
    │
    ├── ── Données outages et piliers ───────────────────────────
    ├── radar_api_v4_outages.csv/.xlsx
    ├── radar_outages_events_by_country_52w.csv
    ├── radar_outages_events_global_52w.csv
    ├── radar_iqi_latency_by_country_52w.csv
    ├── radar_iqi_latency_global_52w.csv
    ├── radar_attacks_l3_ip_version_by_country.csv
    ├── radar_attacks_l3_ip_version_global.csv
    ├── vulnerability_index.csv
    ├── radar_piliers_data/                   # 7 piliers (JSON + Excel)
    │
    └── Archive/                             # Fichiers de collecte initiaux
        ├── radar_api_donnees_brutes_global.csv
        ├── radar_api_v4_donnees_brutes.csv
        └── radar_attacks_l3_ip_version.csv
```

---

## Données

Les données proviennent de l'**API Cloudflare Radar v4** (accès libre) et couvrent :

| Source | Variables | Couverture |
|--------|-----------|------------|
| BGP | Volume de routes, hijacks, leaks | Mondiale, hebdomadaire |
| Email | DMARC/DKIM/SPF, spam, phishing | Mondiale, hebdomadaire |
| HTTP | TLS 1.3/1.2/QUIC, IPv6, HTTP/3 | 252 pays, hebdomadaire |
| IQI | Bande passante (p25/p50/p75), latence DNS | 252 pays, hebdomadaire |
| Attaques L3 | Débit, protocole, version IP | Mondiale, hebdomadaire |
| Attaques L7 | Secteur cible, méthode HTTP | Mondiale, quotidienne |
| ADM1 | HTTP/IQI au niveau sous-national | Mondial, hebdomadaire |

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

# Exécuter une étude (exemple : Étude 11 — IEC/IExC)
cd scripts/outputs_complet
python etude11_vulnerabilite_pays.py
```

> **Note :** Pour collecter de nouvelles données Cloudflare Radar, vous aurez besoin d'une clé API gratuite obtenue sur [dash.cloudflare.com](https://dash.cloudflare.com/profile/api-tokens). Stockez-la dans un fichier `.env` (non versionné).

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

- **Séries temporelles** : ARIMA (sélection AIC), Mann-Kendall, ADF (stationnarité)
- **Causalité** : Test de Granger, cross-corrélation, corrélation de Pearson/Spearman
- **Tests non paramétriques** : Mann-Whitney U, Kruskal-Wallis, Cohen d
- **Apprentissage non supervisé** : k-Means (sélection silhouette), ACP (PCA)
- **Économétrie spatiale** : Régression log-log PIB/IQI, corrélations transnationales
- **Event study** : Fenêtres pré/post release navigateurs
- **Mémoire longue** : Exposant de Hurst (ADM1, L3 bytes)

---

## Rapports disponibles

| Document | Format | Description |
|----------|--------|-------------|
| [`rapport_synthese_10etudes.md`](scripts/outputs_complet/rapport_synthese_10etudes.md) | Markdown | **Synthèse principale — 10 études, 4 500 mots** |
| [`rapport_academique.md`](scripts/outputs_complet/rapport_academique.md) | Markdown/DOCX/PDF | Rapport académique complet |
| [`doc_technique_indices.md`](scripts/outputs_complet/doc_technique_indices.md) | Markdown/DOCX/PDF | Documentation ISE, IMP, IVC |
| `rapport_etude[1-11]_*.md` | Markdown + DOCX | 11 rapports d'études individuels |
| `rapport_phase_[A-L].md` | Markdown | 12 rapports de phases analytiques |

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

Vous êtes libre de partager, modifier et utiliser les données et analyses, à condition de citer la source :

> "Contains information from *Cloudflare Radar Security Dataset 2025–2026* by Issakha Thiam, available under ODC-By 1.0 — https://opendatacommons.org/licenses/by/1-0/"

Les données Cloudflare Radar sont également soumises aux [Conditions d'utilisation de Cloudflare](https://www.cloudflare.com/terms/).

---

*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*
