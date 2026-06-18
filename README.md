# Sécurité Internet Mondiale 2025–2026 — Analyse Cloudflare Radar

> **Analyse empirique multidimensionnelle de la sécurité internet mondiale à partir des données Cloudflare Radar API v4 — 18 études, 252 pays, 53 semaines.**

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
| 12 | Convergence pays | β-convergence confirmée (TLS 1.3 β=−0,804) ; les pays en retard rattrapent les leaders |
| 13 | Bot vs vulnérabilité | HTTP/3 ↔ bots (ρ=−0,615) ; TLS 1.3 attire bots (ρ=+0,337) — paradoxe de ciblage |
| 14 | OS legacy | Android → moins IPv6/BW (ρ=−0,311/−0,577) ; macOS → meilleures performances |
| 15 | Saisonnalité spectrale | BGP routes : cycle dominant 13,2 sem ; autres indicateurs : tendance longue (53 sem) |
| 16 | Secteurs L7 | Internet/Télécom en forte hausse (MK z=+6,80) ; Finance en forte baisse (z=−6,05) |
| 17 | Paradoxe résilience | R²=0,010 — vulnérabilité structurelle **n'explique pas** les chocs réalisés |
| 18 | Fracture mobile | Mobile → moins IPv6 (ρ=−0,261), moins BW (ρ=−0,531) ; Kruskal-Wallis p<0,0001 |

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
        ├── cleaned/                     # ── Données nettoyées (25 CSV) ──────
        │   ├── attacks_l3_bitrate_clean.csv
        │   ├── attacks_l3_ip_version_clean.csv
        │   ├── attacks_l3_protocol_clean.csv
        │   ├── attacks_l7_http_method_clean.csv
        │   ├── attacks_l7_http_version_clean.csv
        │   ├── attacks_l7_vertical_clean.csv
        │   ├── bgp_hijacks_clean.csv / bgp_leaks_clean.csv / bgp_timeseries_clean.csv
        │   ├── dns_timeseries_clean.csv
        │   ├── email_dkim_clean.csv / email_dmarc_clean.csv
        │   ├── email_malicious_clean.csv / email_spam_clean.csv
        │   ├── email_spf_clean.csv / email_spoof_clean.csv
        │   ├── http_bot_class_clean.csv / http_browser_family_clean.csv
        │   ├── http_device_type_clean.csv / http_http_version_clean.csv
        │   ├── http_ip_version_clean.csv / http_os_clean.csv
        │   ├── http_tls_version_clean.csv
        │   ├── iqi_bandwidth_clean.csv / iqi_dns_clean.csv
        │
        ├── phases/                      # ── Phases d'analyse A→L ────────────
        │   ├── phase_A_preparation.py   # Collecte et nettoyage des données
        │   ├── phase_B_descriptif.py    # Statistiques descriptives
        │   ├── phase_C_temporel.py      # Analyse temporelle (Mann-Kendall, ADF)
        │   ├── phase_D_geographique.py  # Analyse géographique (252 pays)
        │   ├── phase_E_attaques.py      # Attaques L3/L7
        │   ├── phase_F_email.py         # Sécurité email (DMARC/DKIM/SPF)
        │   ├── phase_G_bgp.py           # BGP hijacking et leaks
        │   ├── phase_H_correlations.py  # Corrélations et causalité de Granger
        │   ├── phase_I_clustering.py    # Clustering pays (k-Means)
        │   ├── phase_J_anomalies.py     # Détection d'anomalies
        │   ├── phase_K_network.py       # Analyse réseau (graphes ASN)
        │   ├── phase_L_synthese.py      # Synthèse finale
        │   └── rapport_phase_[A-L].md   # 12 rapports de phases
        │
        ├── synthese/                    # ── Rapports de synthèse ────────────
        │   ├── rapport_synthese_10etudes.md/.docx   # Synthèse principale
        │   ├── rapport_academique.md/.docx/.pdf     # Rapport académique
        │   └── doc_technique_indices.md/.docx/.pdf  # Documentation indices
        │
        ├── etude01_geopolitique/        # Disparités régionales TLS/IPv6
        │   ├── etude1_geopolitique.py
        │   ├── etude1_regions_boxplot.png / etude1_heatmap.png
        │   └── rapport_etude1_geopolitique.md/.docx
        │
        ├── etude02_prediction/          # Prédiction ARIMA ISE/IMP/IVC
        │   ├── etude2_prediction.py
        │   ├── etude2_forecast.png
        │   └── rapport_etude2_prediction.md/.docx
        │
        ├── etude03_weekends/            # Rythmes temporels des attaques
        │   ├── etude3_weekends.py
        │   ├── etude3_boxplot.png / etude3_timeline.png
        │   └── rapport_etude3_weekends.md/.docx
        │
        ├── etude04_cascade/             # Effet cascade email→BGP (Granger)
        │   ├── etude4_cascade.py
        │   ├── etude4_cascade.png
        │   └── rapport_etude4_cascade.md/.docx
        │
        ├── etude05_cve/                 # CVE critiques NVD vs BGP
        │   ├── etude5_cve.py
        │   ├── etude5_cve_vs_bgp.png / etude5_correlation_lags.png
        │   └── rapport_etude5_cve.md/.docx
        │
        ├── etude06_cisa/                # CISA KEV (254 vulnérabilités)
        │   ├── etude6_cisa.py
        │   ├── etude6_kev_timeline.png / etude6_vendors.png
        │   └── rapport_etude6_cisa.md/.docx
        │
        ├── etude07_browsers/            # Impact navigateurs sur protocoles
        │   ├── etude7_browsers.py
        │   ├── etude7_tls_timeline.png / etude7_http3_browsers.png
        │   └── rapport_etude7_browsers.md/.docx
        │
        ├── etude08_inegalites/          # Fracture numérique mondiale
        │   ├── etude8_inegalites.py
        │   ├── etude8_scatter_gdp_tls.png / etude8_boxplot_income.png
        │   └── rapport_etude8_inegalites.md/.docx
        │
        ├── etude09_clustering/          # Clustering k-Means (252 pays)
        │   ├── etude9_clustering.py
        │   ├── etude9_pca.png / etude9_elbow.png
        │   └── rapport_etude9_clustering.md/.docx
        │
        ├── etude10_iqi_proxy/           # IQI proxy économique (PIB/hab)
        │   ├── etude10_iqi_proxy.py
        │   ├── etude10_scatter_iqi_gdp.png
        │   └── rapport_etude10_iqi_proxy.md/.docx
        │
        ├── etude11_vulnerabilite_pays/  # IEC/IExC — Exposition vs Expérience
        │   ├── etude11_vulnerabilite_pays.py
        │   ├── etude11_heatmap_iec.png / etude11_heatmap_iexc.png
        │   ├── etude11_scatter_iec_iexc.png / etude11_series_globales.png
        │   ├── etude11_pays_semaine_vulnerabilite.csv
        │   └── rapport_etude11_vulnerabilite_pays.md
        │
        ├── etude12_convergence_pays/    # β/σ-convergence Mann-Kendall
        │   ├── etude12_convergence_pays.py
        │   ├── etude12_mk_tendances.png / etude12_beta_convergence.png / etude12_sigma_convergence.png
        │   ├── etude12_convergence_mk.csv
        │   └── rapport_etude12_convergence_pays.md
        │
        ├── etude13_bot_vulnerabilite/   # Trafic bot vs indicateurs sécurité
        │   ├── etude13_bot_vulnerabilite.py
        │   ├── etude13_bot_scatter.png / etude13_bot_classement.png / etude13_bot_timeseries.png
        │   ├── etude13_bot_pays.csv
        │   └── rapport_etude13_bot_vulnerabilite.md
        │
        ├── etude14_os_legacy/           # OS legacy vs sécurité
        │   ├── etude14_os_legacy.py
        │   ├── etude14_os_corr_heatmap.png / etude14_os_timeseries.png / etude14_windows_tls.png
        │   ├── etude14_os_pays.csv
        │   └── rapport_etude14_os_legacy.md
        │
        ├── etude15_saisonnalite_spectrale/  # FFT + décomposition STL
        │   ├── etude15_saisonnalite_spectrale.py
        │   ├── etude15_fft_spectres.png / etude15_series_tendance.png / etude15_residus_saisonniers.png
        │   └── rapport_etude15_saisonnalite_spectrale.md
        │
        ├── etude16_secteurs_l7/         # Secteurs ciblés attaques L7
        │   ├── etude16_secteurs_l7.py
        │   ├── etude16_l7_secteurs_stacked.png / etude16_l7_secteurs_series.png
        │   ├── etude16_l7_methodes.png / etude16_l7_barplot.png
        │   └── rapport_etude16_secteurs_l7.md
        │
        ├── etude17_paradoxe_resilience/ # Régression IExC ~ IEC + contrôles
        │   ├── etude17_paradoxe_resilience.py
        │   ├── etude17_paradoxe_iec_iexc.png / etude17_regression_iec_iexc.png / etude17_ols_coefficients.png
        │   └── rapport_etude17_paradoxe_resilience.md
        │
        └── etude18_mobile_desktop/      # Fracture mobile vs desktop
            ├── etude18_mobile_desktop.py
            ├── etude18_mobile_scatter.png / etude18_mobile_boxplot.png / etude18_mobile_top20.png
            ├── etude18_mobile_pays.csv
            └── rapport_etude18_mobile_desktop.md
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
- **Économétrie** : Régression log-log PIB/IQI, corrélations transnationales, OLS multiple
- **Event study** : Fenêtres pré/post release navigateurs
- **Analyse spectrale** : FFT (Transformée de Fourier), décomposition STL, MA(4)
- **Convergence** : β-convergence (OLS cross-section), σ-convergence (écart-type mondial)

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
