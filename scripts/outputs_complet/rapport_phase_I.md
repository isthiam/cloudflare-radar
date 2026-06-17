# Rapport Phase I — Clustering et Segmentation Géographique
**Cloudflare Radar Dataset — Juin 2025 / Juin 2026**  
**Auteur :** Issakha Thiam  
**Généré le :** 2026-06-16 22:17:38

---
## 1. Résumé Exécutif

| Indicateur | Valeur |
|---|---|
| Pays analysés (≥ 4 features valides) | **247** |
| Features utilisées | 8 (IPv6, HTTP/3, TLS1.3, Bot, Mobile, BW, DNS, BGP exp.) |
| Nombre de clusters (k silhouette) | **2** (statistiquement optimal) |
| Nombre de clusters retenu (analyse) | **4** (choix analytique) |
| Variance expliquée PC1+PC2+PC3 | **80.7%** |
| Score silhouette optimal | **0.5079** |
| IMP global moyen | 43.8 / 100 |
| IMP max / min | 58.1 / 21.8 |
| Pays avec BGP exposure > 1% | 19 |

---
## 2. Statistiques Descriptives des Features

| Feature | Moyenne | Médiane | Std | Min | Max | N pays |
|---|---:|---:|---:|---:|---:|---:|
| IPv6 | 19.85 | 15.53 | 19.33 | 0.02 | 98.11 | 247 |
| HTTP/3 | 25.40 | 26.88 | 7.67 | 0.00 | 40.35 | 247 |
| TLSv1.3 | 66.22 | 65.59 | 6.66 | 49.93 | 95.38 | 247 |
| bot | 20.44 | 15.72 | 14.21 | 7.32 | 90.69 | 247 |
| mobile | 48.80 | 51.01 | 13.78 | 2.92 | 75.79 | 247 |
| bw_p50 | 14.31 | 10.20 | 11.24 | 3.28 | 71.85 | 247 |
| dns_p50 | 92.51 | 79.65 | 51.96 | 22.77 | 349.83 | 247 |
| bgp_victim_pct | 0.46 | 0.08 | 2.10 | 0.01 | 29.23 | 247 |
| IMP | 43.81 | 43.48 | 5.57 | 21.84 | 58.05 | 247 |
| bgp_risk | 0.86 | 0.08 | 3.86 | 0.01 | 52.73 | 247 |

---
## 3. Analyse en Composantes Principales (PCA)

### 3.1 Variance Expliquée par Composante

| Composante | Variance expliquée (%) | Variance cumulée (%) |
|---|---:|---:|
| PC1 | 43.38% | 43.38% |
| PC2 | 24.58% | 67.96% |
| PC3 | 12.71% | 80.66% |
| PC4 | 9.06% | 89.73% |
| PC5 | 4.53% | 94.25% |
| PC6 | 3.48% | 97.73% |
| PC7 | 2.27% | 100.00% |

### 3.2 Loadings PCA (contribution des features)

> Clustering réalisé sur les **7 features protocolaires** (BGP exclu pour éviter l'effet levier des outliers US/CN).

| Feature | PC1 | PC2 | PC3 | Interprétation PC1 |
|---|---:|---:|---:|---|
| IPv6 | 0.256 | -0.082 | 0.932 | positif ↑ |
| HTTP/3 | -0.452 | -0.384 | 0.040 | négatif ↓ |
| TLSv1.3 | 0.426 | 0.318 | -0.063 | positif ↑ |
| bot | 0.473 | 0.183 | -0.237 | positif ↑ |
| mobile | -0.447 | 0.194 | 0.026 | négatif ↓ |
| bw_p50 | 0.265 | -0.563 | -0.262 | positif ↑ |
| dns_p50 | -0.232 | 0.597 | 0.004 | négatif ↓ |

---
## 4. Sélection du Nombre de Clusters (Méthode du Coude + Silhouette)

| k | Inertie | Score Silhouette | Score Davies-Bouldin |
|---:|---:|---:|---:|
| 2 | 927.6 | 0.5079 | 0.9845 |
| 3 | 669.9 | 0.3045 | 1.1113 |
| 4 | 544.4 | 0.2785 | 1.0948 ← **optimal** |
| 5 | 460.2 | 0.3024 | 1.0189 |
| 6 | 394.9 | 0.3048 | 1.0115 |
| 7 | 354.7 | 0.3037 | 0.9967 |

> **k=2** optimal par Silhouette. **k=4** retenu pour granularité analytique (k=2 trop grossier : US/CN/RU outliers BGP écrasent la structure).

---
## 5. Profils des Clusters

### 5.1 Caractéristiques Moyennes par Cluster

| Cluster | Nom | N pays | IPv6% | HTTP/3% | TLS1.3% | Bot% | Mobile% | BW p50 | DNS p50 | BGP exp.% | IMP |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | **Matures & Sécurisés** | 111 | 19.4 | 29.9 | 63.0 | 12.8 | 53.9 | 11.20 | 88.38 | 0.28 | **46.1** |
| 3 | **En développement avancé** | 62 | 25.3 | 25.5 | 66.5 | 24.8 | 38.5 | 26.32 | 48.30 | 1.14 | **43.1** |
| 0 | **Vulnérables intermédiaires** | 59 | 8.7 | 22.0 | 68.0 | 20.2 | 57.5 | 5.85 | 153.12 | 0.10 | **41.9** |
| 2 | **Sous-équipés & à risque** | 15 | 44.7 | 5.0 | 81.6 | 60.0 | 19.3 | 20.95 | 67.45 | 0.41 | **37.6** |

### 5.2 Interprétation des Clusters

#### Cluster 1 : Matures & Sécurisés (111 pays)

**Points forts :** HTTP/3 bon (29.9%) · TLS 1.3 dominant (63.0%)
**Points faibles :** **IMP faible (46.1/100)**

#### Cluster 3 : En développement avancé (62 pays)

**Points forts :** HTTP/3 bon (25.5%) · TLS 1.3 dominant (66.5%)
**Points faibles :** taux bot élevé (24.8%) · forte exposition BGP (1.14%) · **IMP faible (43.1/100)**

#### Cluster 0 : Vulnérables intermédiaires (59 pays)

**Points forts :** HTTP/3 bon (22.0%) · TLS 1.3 dominant (68.0%)
**Points faibles :** IPv6 très faible (8.7%) · taux bot élevé (20.2%) · **IMP faible (41.9/100)**

#### Cluster 2 : Sous-équipés & à risque (15 pays)

**Points forts :** IPv6 élevé (44.7%) · TLS 1.3 dominant (81.6%)
**Points faibles :** taux bot élevé (60.0%) · **IMP faible (37.6/100)**

---
## 6. Pays par Cluster

### 6.1 Cluster 1 — Matures & Sécurisés (111 pays)

| Rang | ISO2 | Pays | Région | IPv6% | HTTP/3% | TLS1.3% | Bot% | IMP | BGP exp.% |
|---:|---|---|---|---:|---:|---:|---:|---:|---:|
| 1 | IN | Inde | Asie | 64.8 | 27.0 | 66.8 | 14.9 | 58.1 | 4.445 |
| 2 | SA | Arabie saoudite | Moyen-Orient | 56.8 | 24.0 | 69.8 | 10.6 | 56.6 | 0.025 |
| 3 | BL | Saint-Barthélemy | ? | 58.4 | 31.6 | 64.3 | 8.6 | 55.8 | 0.075 |
| 4 | NP | Népal | Asie | 51.2 | 30.7 | 62.9 | 12.6 | 55.2 | 0.045 |
| 5 | NR | Nauru | Océanie | 52.1 | 30.3 | 55.4 | 13.1 | 54.8 | 0.075 |
| 6 | GR | Grèce | Europe | 47.3 | 37.0 | 58.2 | 10.5 | 54.3 | 0.060 |
| 7 | MX | Mexique | Amériques | 44.2 | 22.6 | 73.5 | 9.1 | 54.2 | 0.375 |
| 8 | GT | Guatemala | Amériques | 46.8 | 22.4 | 73.0 | 11.0 | 54.0 | 0.005 |
| 9 | LK | Sri Lanka | Asie | 47.2 | 39.2 | 55.9 | 9.7 | 53.9 | 0.005 |
| 10 | UY | Uruguay | Amériques | 52.3 | 29.7 | 64.1 | 13.5 | 53.9 | 0.075 |
| 11 | TH | Thaïlande | Asie | 42.5 | 32.7 | 62.5 | 10.9 | 53.8 | 0.686 |
| 12 | SR | Suriname | Amériques | 40.9 | 25.5 | 70.3 | 9.4 | 53.7 | 0.060 |
| 13 | PR | Porto Rico | Amériques | 45.7 | 27.1 | 67.5 | 9.4 | 53.6 | 0.035 |
| 14 | MF | Saint-Martin | ? | 42.8 | 30.7 | 65.1 | 7.6 | 52.9 | 0.005 |
| 15 | BR | Brésil | Amériques | 46.5 | 30.9 | 61.8 | 15.9 | 52.9 | 6.077 |
| 16 | NI | Nicaragua | Amériques | 35.8 | 25.9 | 69.9 | 10.0 | 52.6 | 0.080 |
| 17 | MP | MP | ? | 43.9 | 31.7 | 63.1 | 10.5 | 50.7 | 0.075 |
| 18 | MN | Mongolie | Asie | 36.4 | 38.5 | 56.4 | 11.8 | 50.6 | 0.015 |
| 19 | KI | Kiribati | Océanie | 49.0 | 25.1 | 64.9 | 22.0 | 50.5 | 0.075 |
| 20 | AI | Anguilla | Amériques | 39.1 | 25.6 | 68.7 | 15.8 | 50.2 | 0.075 |
| 21 | QA | Qatar | Moyen-Orient | 34.4 | 27.1 | 67.1 | 14.2 | 49.9 | 0.050 |
| 22 | BO | Bolivie | Amériques | 36.5 | 28.3 | 66.2 | 15.2 | 49.8 | 0.075 |
| 23 | DM | Dominique | Amériques | 30.5 | 30.1 | 65.1 | 10.3 | 49.4 | 0.075 |
| 24 | CK | CK | ? | 31.7 | 31.6 | 63.2 | 11.5 | 49.2 | 0.075 |
| 25 | GF | Guyane française | Amériques | 22.6 | 29.4 | 65.3 | 9.4 | 48.6 | 0.075 |
| 26 | DO | Rép. dominicaine | Amériques | 30.1 | 27.4 | 66.8 | 14.3 | 48.6 | 0.080 |
| 27 | BD | Bangladesh | Asie | 20.0 | 24.3 | 68.5 | 13.0 | 48.5 | 1.106 |
| 28 | KW | Koweït | Moyen-Orient | 23.9 | 28.3 | 65.4 | 8.5 | 48.5 | 0.070 |
| 29 | PE | Pérou | Amériques | 31.1 | 29.1 | 65.9 | 11.0 | 48.4 | 0.230 |
| 30 | FJ | Fidji | Océanie | 23.1 | 30.1 | 65.6 | 9.9 | 48.1 | 0.015 |
| 31 | PG | PNG | Océanie | 18.9 | 36.6 | 55.2 | 15.3 | 48.1 | 0.040 |
| 32 | TC | Turks-et-Caïcos | Amériques | 23.6 | 27.3 | 67.3 | 9.2 | 47.9 | 0.075 |
| 33 | SX | Sint Maarten | Amériques | 27.0 | 27.4 | 66.2 | 9.8 | 47.9 | 0.075 |
| 34 | PH | Philippines | Asie | 17.1 | 27.3 | 69.0 | 10.9 | 47.9 | 0.250 |
| 35 | NF | NF | ? | 43.4 | 23.9 | 62.3 | 22.6 | 47.7 | 0.075 |
| 36 | BT | Bhoutan | Asie | 25.8 | 31.7 | 62.6 | 16.9 | 47.7 | 0.075 |
| 37 | OM | Oman | Moyen-Orient | 20.2 | 25.6 | 67.9 | 11.6 | 47.6 | 0.395 |
| 38 | SV | El Salvador | Amériques | 16.5 | 25.9 | 69.8 | 7.8 | 47.3 | 0.015 |
| 39 | BW | Botswana | Afrique | 4.7 | 33.3 | 63.3 | 9.7 | 47.1 | 0.075 |
| 40 | LC | Sainte-Lucie | Amériques | 19.3 | 30.0 | 64.5 | 9.5 | 47.0 | 0.075 |
| 41 | PK | Pakistan | Asie | 22.5 | 27.6 | 62.6 | 14.2 | 46.8 | 0.646 |
| 42 | SN | Sénégal | Afrique | 25.4 | 25.4 | 65.6 | 22.4 | 46.5 | 0.005 |
| 43 | GP | Guadeloupe | Amériques | 11.6 | 30.2 | 65.9 | 7.3 | 46.5 | 0.075 |
| 44 | MV | Maldives | Asie | 15.1 | 30.5 | 64.5 | 9.3 | 46.5 | 0.005 |
| 45 | BS | Bahamas | Amériques | 25.9 | 25.2 | 61.2 | 11.4 | 46.5 | 0.075 |
| 46 | FM | Micronésie | Océanie | 16.2 | 35.6 | 59.1 | 11.9 | 46.4 | 0.075 |
| 47 | RE | La Réunion | Afrique | 16.4 | 37.6 | 57.1 | 8.7 | 46.3 | 0.005 |
| 48 | JM | Jamaïque | Amériques | 17.1 | 22.9 | 71.8 | 11.7 | 46.1 | 0.155 |
| 49 | KZ | Kazakhstan | Asie | 20.9 | 33.4 | 59.4 | 14.4 | 46.0 | 0.145 |
| 50 | MH | Îles Marshall | Océanie | 19.6 | 33.4 | 60.2 | 14.1 | 45.8 | 0.075 |
| 51 | NU | NU | ? | 21.0 | 29.0 | 65.2 | 13.7 | 45.8 | 0.075 |
| 52 | SO | Somalie | Afrique | 1.0 | 38.7 | 53.5 | 9.6 | 45.5 | 0.060 |
| 53 | TT | Trinité-et-Tobago | Amériques | 23.8 | 29.1 | 61.0 | 18.3 | 45.4 | 0.020 |
| 54 | HN | Honduras | Amériques | 16.0 | 24.2 | 69.8 | 15.5 | 45.3 | 0.015 |
| 55 | ID | Indonésie | Asie | 16.2 | 25.3 | 67.8 | 18.6 | 45.3 | 3.454 |
| 56 | TN | Tunisie | Afrique | 16.9 | 34.6 | 59.0 | 13.5 | 45.3 | 0.125 |
| 57 | MQ | Martinique | Amériques | 7.8 | 32.8 | 62.9 | 7.8 | 45.1 | 0.070 |
| 58 | CO | Colombie | Amériques | 16.8 | 28.7 | 65.8 | 13.6 | 44.9 | 0.916 |
| 59 | IT | Italie | Europe | 15.2 | 29.4 | 64.8 | 14.5 | 44.9 | 0.486 |
| 60 | VI | Îles Vierges américaines | Amériques | 13.7 | 30.3 | 63.6 | 9.5 | 44.7 | 0.040 |
| 61 | AO | Angola | Afrique | 12.5 | 24.3 | 67.3 | 20.2 | 44.7 | 0.005 |
| 62 | TR | Turquie | Europe | 15.3 | 25.5 | 64.7 | 13.6 | 44.5 | 1.307 |
| 63 | CR | Costa Rica | Amériques | 14.3 | 27.9 | 66.2 | 13.1 | 44.5 | 0.010 |
| 64 | BM | BM | ? | 15.7 | 28.6 | 63.6 | 9.9 | 44.3 | 0.075 |
| 65 | JO | Jordanie | Moyen-Orient | 17.5 | 32.4 | 59.5 | 17.6 | 44.2 | 0.365 |
| 66 | UG | Ouganda | Afrique | 2.0 | 28.7 | 64.2 | 9.1 | 43.9 | 0.831 |
| 67 | LA | Laos | Asie | 0.7 | 40.4 | 54.5 | 10.0 | 43.9 | 0.075 |
| 68 | VG | Îles Vierges britanniques | Amériques | 17.3 | 26.9 | 67.4 | 16.7 | 43.9 | 0.065 |
| 69 | BA | Bosnie-Herzégovine | Europe | 7.7 | 33.4 | 59.4 | 15.6 | 43.8 | 0.005 |
| 70 | CY | Chypre | Europe | 17.0 | 28.8 | 63.7 | 15.3 | 43.5 | 0.260 |
| 71 | WS | Samoa | Océanie | 7.7 | 33.1 | 59.1 | 11.9 | 43.2 | 0.005 |
| 72 | LS | Lesotho | Afrique | 0.6 | 36.8 | 55.5 | 10.6 | 43.2 | 0.075 |
| 73 | BB | Barbade | Amériques | 14.2 | 26.4 | 64.2 | 16.0 | 43.2 | 0.005 |
| 74 | PW | Palaos | Océanie | 2.0 | 32.9 | 62.6 | 10.1 | 43.1 | 0.075 |
| 75 | AM | Arménie | Asie | 6.8 | 37.7 | 56.5 | 12.2 | 43.1 | 0.175 |
| 76 | NC | Nouvelle-Calédonie | Océanie | 9.9 | 34.5 | 59.7 | 10.9 | 43.1 | 0.070 |
| 77 | VU | Vanuatu | Océanie | 14.1 | 29.4 | 62.0 | 15.4 | 43.1 | 0.075 |
| 78 | GE | Géorgie | Asie | 9.5 | 36.2 | 53.8 | 9.9 | 43.1 | 0.025 |
| 79 | GU | Guam | Océanie | 5.5 | 35.4 | 59.7 | 8.5 | 43.1 | 0.075 |
| 80 | ZM | Zambie | Afrique | 4.0 | 28.2 | 62.3 | 12.8 | 43.1 | 1.081 |
| 81 | BZ | Belize | Amériques | 26.8 | 23.1 | 60.7 | 22.0 | 43.0 | 0.005 |
| 82 | ME | Monténégro | Europe | 0.8 | 30.5 | 64.9 | 11.6 | 42.9 | 0.195 |
| 83 | GH | Ghana | Afrique | 2.0 | 24.7 | 69.5 | 8.7 | 42.9 | 0.230 |
| 84 | AG | Antigua-et-Barbuda | Amériques | 4.1 | 26.8 | 67.8 | 11.9 | 42.9 | 0.075 |
| 85 | AW | Aruba | Amériques | 2.5 | 29.7 | 64.8 | 7.6 | 42.9 | 0.005 |
| 86 | CV | Cap-Vert | Afrique | 3.4 | 28.8 | 65.1 | 13.7 | 42.9 | 0.075 |
| 87 | PF | Polynésie française | Océanie | 4.6 | 32.9 | 62.5 | 9.2 | 42.8 | 0.075 |
| 88 | UZ | Ouzbékistan | Asie | 9.0 | 29.6 | 62.7 | 17.9 | 42.7 | 0.005 |
| 89 | TL | Timor oriental | Asie | 6.3 | 31.2 | 57.0 | 15.2 | 42.7 | 0.075 |
| 90 | RS | Serbie | Europe | 5.9 | 31.6 | 61.5 | 15.8 | 42.6 | 0.055 |
| 91 | EG | Égypte | Afrique | 4.4 | 30.7 | 61.1 | 13.8 | 42.3 | 0.085 |
| 92 | LB | Liban | Moyen-Orient | 1.0 | 30.8 | 64.0 | 14.1 | 42.1 | 0.025 |
| 93 | HR | Croatie | Europe | 4.9 | 28.6 | 62.0 | 13.6 | 42.1 | 0.030 |
| 94 | BQ | Bonaire | Amériques | 3.0 | 30.4 | 64.4 | 9.3 | 41.9 | 0.005 |
| 95 | FO | Îles Féroé | Europe | 3.2 | 33.1 | 62.2 | 9.3 | 41.9 | 0.075 |
| 96 | MU | Maurice | Afrique | 1.6 | 35.9 | 57.1 | 13.1 | 41.5 | 0.010 |
| 97 | ZA | Afrique du Sud | Afrique | 2.8 | 27.3 | 67.3 | 16.6 | 41.5 | 1.332 |
| 98 | SB | Îles Salomon | Océanie | 15.1 | 26.5 | 59.4 | 20.9 | 41.4 | 0.030 |
| 99 | MK | MK | ? | 0.8 | 37.6 | 56.4 | 13.7 | 41.3 | 0.005 |
| 100 | KY | Îles Caïmans | Amériques | 3.1 | 29.6 | 63.7 | 9.6 | 41.3 | 0.005 |
| 101 | CW | Curaçao | Amériques | 7.1 | 27.9 | 63.2 | 16.4 | 41.2 | 0.010 |
| 102 | KG | Kirghizistan | Asie | 4.5 | 33.9 | 55.5 | 16.1 | 41.2 | 0.075 |
| 103 | UA | Ukraine | Europe | 9.7 | 34.4 | 56.5 | 18.5 | 41.1 | 1.602 |
| 104 | PS | Palestine | Moyen-Orient | 1.0 | 33.3 | 59.7 | 14.9 | 41.0 | 0.015 |
| 105 | BN | Brunéi | Asie | 1.1 | 28.3 | 64.9 | 13.1 | 40.9 | 0.005 |
| 106 | MG | Madagascar | Afrique | 6.7 | 28.9 | 60.7 | 9.8 | 40.9 | 0.015 |
| 107 | DZ | Algérie | Afrique | 0.5 | 29.5 | 60.1 | 16.0 | 40.7 | 0.015 |
| 108 | PM | Saint-Pierre-et-Miquelon | Amériques | 3.1 | 35.8 | 59.5 | 9.6 | 40.5 | 0.075 |
| 109 | AZ | Azerbaïdjan | Asie | 0.4 | 28.3 | 64.5 | 14.7 | 40.5 | 0.110 |
| 110 | IO | IO | ? | 33.0 | 14.6 | 50.0 | 9.7 | 40.3 | 0.075 |
| 111 | KH | Cambodge | Asie | 0.7 | 32.6 | 61.5 | 14.6 | 37.6 | 0.050 |

### 6.2 Cluster 3 — En développement avancé (62 pays)

| Rang | ISO2 | Pays | Région | IPv6% | HTTP/3% | TLS1.3% | Bot% | IMP | BGP exp.% |
|---:|---|---|---|---:|---:|---:|---:|---:|---:|
| 1 | PN | PN | ? | 80.4 | 29.7 | 56.3 | 25.8 | 54.5 | 0.075 |
| 2 | MY | Malaisie | Asie | 56.4 | 27.7 | 65.2 | 17.9 | 54.2 | 0.090 |
| 3 | UM | UM | ? | 93.6 | 24.3 | 62.7 | 40.8 | 52.9 | 0.075 |
| 4 | JP | Japon | Asie | 41.3 | 22.5 | 72.6 | 17.4 | 51.6 | 0.295 |
| 5 | TV | Tuvalu | Océanie | 61.5 | 22.3 | 70.2 | 28.3 | 51.2 | 0.075 |
| 6 | HU | Hongrie | Europe | 45.0 | 26.9 | 69.0 | 16.1 | 50.9 | 0.040 |
| 7 | MO | Macao | Asie | 38.3 | 33.6 | 59.2 | 16.7 | 49.6 | 0.075 |
| 8 | FR | France | Europe | 49.9 | 22.1 | 71.7 | 31.4 | 48.6 | 1.342 |
| 9 | PY | Paraguay | Amériques | 37.2 | 20.8 | 72.8 | 14.5 | 48.6 | 0.005 |
| 10 | VN | Viêt Nam | Asie | 40.6 | 25.4 | 69.3 | 24.5 | 48.5 | 0.691 |
| 11 | AE | Émirats arabes unis | Moyen-Orient | 35.6 | 23.6 | 69.5 | 15.4 | 48.0 | 0.180 |
| 12 | PT | Portugal | Europe | 33.1 | 27.1 | 67.4 | 15.2 | 47.9 | 0.025 |
| 13 | NO | Norvège | Europe | 34.4 | 28.8 | 65.3 | 18.3 | 47.5 | 0.260 |
| 14 | AR | Argentine | Amériques | 25.5 | 28.0 | 65.6 | 14.0 | 47.2 | 0.390 |
| 15 | SJ | Svalbard | Europe | 34.0 | 19.1 | 71.9 | 16.1 | 46.6 | 0.075 |
| 16 | TW | Taïwan | Asie | 37.1 | 30.9 | 60.9 | 21.1 | 46.6 | 0.546 |
| 17 | AT | Autriche | Europe | 31.6 | 27.3 | 67.0 | 19.1 | 46.6 | 0.185 |
| 18 | GB | Royaume-Uni | Europe | 30.8 | 21.9 | 70.5 | 21.0 | 46.1 | 5.286 |
| 19 | CZ | République tchèque | Europe | 26.8 | 28.7 | 65.9 | 17.0 | 45.7 | 0.646 |
| 20 | EE | Estonie | Europe | 32.2 | 30.0 | 63.8 | 21.4 | 45.4 | 0.135 |
| 21 | CA | Canada | Amériques | 30.7 | 25.2 | 67.7 | 20.6 | 45.3 | 0.771 |
| 22 | RO | Roumanie | Europe | 24.6 | 28.5 | 62.8 | 18.8 | 45.0 | 0.921 |
| 23 | NZ | Nouvelle-Zélande | Océanie | 21.8 | 30.8 | 63.8 | 12.8 | 44.9 | 0.035 |
| 24 | AX | Îles Åland | Europe | 29.2 | 31.4 | 59.9 | 15.3 | 44.9 | 0.075 |
| 25 | DK | Danemark | Europe | 20.9 | 32.1 | 63.6 | 15.1 | 44.7 | 0.536 |
| 26 | CL | Chili | Amériques | 18.2 | 29.2 | 64.5 | 15.0 | 44.7 | 0.075 |
| 27 | TK | Tokelau | Océanie | 33.7 | 22.8 | 67.9 | 25.3 | 44.5 | 0.075 |
| 28 | IL | Israël | Moyen-Orient | 39.2 | 23.1 | 69.6 | 32.2 | 44.3 | 0.661 |
| 29 | EC | Équateur | Amériques | 23.1 | 21.2 | 72.4 | 19.3 | 44.2 | 0.080 |
| 30 | CH | Suisse | Europe | 27.1 | 25.1 | 68.4 | 23.5 | 43.9 | 0.190 |
| 31 | KR | Corée du Sud | Asie | 18.8 | 27.6 | 67.4 | 21.3 | 43.7 | 0.175 |
| 32 | SK | Slovaquie | Europe | 10.3 | 29.9 | 66.2 | 13.2 | 43.5 | 0.060 |
| 33 | ES | Espagne | Europe | 10.9 | 23.8 | 71.5 | 13.8 | 43.4 | 1.021 |
| 34 | PL | Pologne | Europe | 15.6 | 27.8 | 67.3 | 16.3 | 43.4 | 1.632 |
| 35 | AU | Australie | Océanie | 25.1 | 26.6 | 64.6 | 20.6 | 43.2 | 1.582 |
| 36 | BG | Bulgarie | Europe | 15.2 | 27.2 | 67.3 | 20.7 | 43.2 | 0.731 |
| 37 | SI | Slovénie | Europe | 11.1 | 29.4 | 66.1 | 15.4 | 43.1 | 0.005 |
| 38 | BE | Belgique | Europe | 34.0 | 20.6 | 72.4 | 37.6 | 42.4 | 0.125 |
| 39 | SE | Suède | Europe | 24.4 | 22.4 | 70.8 | 28.6 | 41.9 | 0.951 |
| 40 | LV | Lettonie | Europe | 18.2 | 26.2 | 67.6 | 22.9 | 41.4 | 0.461 |
| 41 | MD | Moldavie | Europe | 11.0 | 33.9 | 58.9 | 20.2 | 41.3 | 0.175 |
| 42 | JE | Jersey | Europe | 3.8 | 29.2 | 62.9 | 11.1 | 41.3 | 0.005 |
| 43 | BH | Bahreïn | Moyen-Orient | 16.3 | 27.3 | 63.0 | 25.5 | 41.1 | 0.641 |
| 44 | IS | Islande | Europe | 11.9 | 28.5 | 65.7 | 19.0 | 41.0 | 0.005 |
| 45 | LI | Liechtenstein | Europe | 19.9 | 25.0 | 67.9 | 22.3 | 40.8 | 0.075 |
| 46 | DE | Allemagne | Europe | 34.7 | 17.0 | 74.3 | 45.6 | 40.6 | 2.057 |
| 47 | LT | Lituanie | Europe | 17.2 | 23.8 | 68.7 | 28.1 | 40.5 | 0.135 |
| 48 | CN | Chine | Asie | 30.9 | 17.9 | 69.5 | 38.9 | 40.0 | 10.557 |
| 49 | LU | Luxembourg | Europe | 20.7 | 19.5 | 72.4 | 36.9 | 39.8 | 0.546 |
| 50 | US | États-Unis | Amériques | 29.1 | 16.2 | 74.4 | 43.5 | 39.5 | 29.229 |
| 51 | SM | Saint-Marin | Europe | 1.6 | 31.9 | 61.5 | 13.2 | 39.3 | 0.075 |
| 52 | MC | Monaco | Europe | 3.6 | 27.0 | 68.9 | 17.0 | 38.8 | 0.075 |
| 53 | AD | Andorre | Europe | 2.0 | 26.6 | 67.0 | 20.0 | 38.1 | 0.075 |
| 54 | GG | Guernesey | Europe | 4.8 | 25.3 | 66.0 | 24.8 | 37.8 | 0.075 |
| 55 | MT | Malte | Europe | 1.2 | 25.4 | 66.0 | 20.6 | 37.0 | 0.005 |
| 56 | AL | Albanie | Europe | 5.3 | 24.7 | 62.2 | 37.4 | 35.8 | 0.060 |
| 57 | BY | Biélorussie | Europe | 5.7 | 18.6 | 72.1 | 39.4 | 34.3 | 0.095 |
| 58 | VA | VA | ? | 12.2 | 20.9 | 68.3 | 35.3 | 33.3 | 0.075 |
| 59 | XK | Kosovo | Europe | 4.1 | 23.3 | 57.6 | 46.6 | 32.4 | 0.075 |
| 60 | RU | Russie | Europe | 7.6 | 17.6 | 63.5 | 40.7 | 31.7 | 5.892 |
| 61 | IM | Île de Man | Europe | 8.6 | 13.6 | 49.9 | 54.3 | 26.0 | 0.010 |
| 62 | TM | Turkménistan | Asie | 0.0 | 35.3 | 62.8 | 75.3 | 25.5 | 0.075 |

### 6.3 Cluster 0 — Vulnérables intermédiaires (59 pays)

| Rang | ISO2 | Pays | Région | IPv6% | HTTP/3% | TLS1.3% | Bot% | IMP | BGP exp.% |
|---:|---|---|---|---:|---:|---:|---:|---:|---:|
| 1 | GY | Guyana | Amériques | 24.9 | 25.2 | 69.3 | 12.5 | 48.2 | 0.005 |
| 2 | TO | Tonga | Océanie | 28.4 | 25.2 | 69.3 | 14.6 | 48.1 | 0.075 |
| 3 | YT | Mayotte | Afrique | 23.9 | 30.8 | 62.7 | 12.6 | 47.5 | 0.075 |
| 4 | AS | AS | ? | 42.9 | 22.5 | 72.0 | 26.0 | 47.1 | 0.075 |
| 5 | SD | Soudan | Afrique | 12.2 | 27.1 | 64.2 | 13.9 | 46.4 | 0.295 |
| 6 | SZ | Eswatini | Afrique | 2.0 | 25.1 | 69.7 | 8.5 | 45.5 | 0.140 |
| 7 | MS | MS | ? | 34.5 | 16.0 | 77.8 | 14.4 | 45.5 | 0.005 |
| 8 | RW | Rwanda | Afrique | 17.3 | 25.2 | 67.8 | 10.2 | 45.4 | 0.115 |
| 9 | SS | Soudan du Sud | Afrique | 17.3 | 21.4 | 68.6 | 18.2 | 45.3 | 0.005 |
| 10 | CI | Côte d'Ivoire | Afrique | 17.6 | 23.6 | 66.6 | 19.2 | 44.7 | 0.075 |
| 11 | CG | Congo | Afrique | 22.6 | 24.8 | 62.6 | 25.8 | 44.3 | 0.005 |
| 12 | MW | Malawi | Afrique | 2.0 | 27.7 | 61.9 | 11.5 | 44.0 | 0.315 |
| 13 | ZW | Zimbabwe | Afrique | 15.5 | 17.6 | 73.0 | 13.1 | 43.7 | 0.025 |
| 14 | WF | WF | ? | 8.7 | 33.3 | 61.6 | 13.0 | 43.7 | 0.075 |
| 15 | GA | Gabon | Afrique | 20.7 | 22.8 | 68.5 | 28.9 | 43.6 | 0.010 |
| 16 | VC | Saint-Vincent | Amériques | 3.8 | 27.6 | 66.9 | 9.5 | 43.4 | 0.075 |
| 17 | CM | Cameroun | Afrique | 3.1 | 31.6 | 59.2 | 15.7 | 43.4 | 0.020 |
| 18 | YE | Yémen | Moyen-Orient | 2.1 | 11.8 | 77.9 | 9.8 | 43.2 | 0.010 |
| 19 | GD | Grenade | Amériques | 9.4 | 24.6 | 70.4 | 10.1 | 43.1 | 0.005 |
| 20 | PA | Panama | Amériques | 5.0 | 23.2 | 71.1 | 11.1 | 43.0 | 0.070 |
| 21 | LR | Libéria | Afrique | 3.7 | 19.1 | 71.6 | 14.2 | 43.0 | 0.005 |
| 22 | MZ | Mozambique | Afrique | 3.5 | 25.5 | 64.9 | 20.3 | 42.7 | 0.015 |
| 23 | ML | Mali | Afrique | 9.2 | 18.1 | 68.6 | 24.7 | 42.6 | 0.005 |
| 24 | CD | RDC | Afrique | 4.5 | 17.6 | 71.1 | 17.0 | 42.5 | 0.436 |
| 25 | FK | Malouines | Amériques | 21.3 | 11.5 | 75.2 | 25.3 | 42.4 | 0.005 |
| 26 | KE | Kenya | Afrique | 7.1 | 25.7 | 68.0 | 15.4 | 42.4 | 0.205 |
| 27 | BJ | Bénin | Afrique | 3.4 | 29.4 | 61.8 | 14.8 | 42.4 | 0.015 |
| 28 | GM | Gambie | Afrique | 0.4 | 13.9 | 77.7 | 18.0 | 42.3 | 0.075 |
| 29 | NG | Nigeria | Afrique | 4.6 | 16.4 | 76.1 | 21.8 | 42.2 | 0.405 |
| 30 | HT | Haïti | Amériques | 9.0 | 19.5 | 66.7 | 21.1 | 42.2 | 0.115 |
| 31 | TJ | Tadjikistan | Asie | 0.3 | 28.7 | 60.7 | 15.3 | 41.5 | 0.015 |
| 32 | VE | Venezuela | Amériques | 4.6 | 24.9 | 68.3 | 18.7 | 41.3 | 0.235 |
| 33 | TG | Togo | Afrique | 20.5 | 22.8 | 61.8 | 29.3 | 41.2 | 0.005 |
| 34 | TZ | Tanzanie | Afrique | 1.2 | 26.7 | 63.4 | 9.6 | 41.1 | 0.461 |
| 35 | SC | Seychelles | Afrique | 11.5 | 26.5 | 65.9 | 22.9 | 41.1 | 0.220 |
| 36 | IQ | Irak | Moyen-Orient | 2.5 | 22.9 | 70.7 | 18.7 | 41.0 | 0.280 |
| 37 | BF | Burkina Faso | Afrique | 11.8 | 19.9 | 65.9 | 23.0 | 40.8 | 0.075 |
| 38 | SL | Sierra Leone | Afrique | 3.1 | 20.2 | 68.5 | 16.3 | 40.8 | 0.005 |
| 39 | CU | Cuba | Amériques | 0.1 | 23.6 | 63.9 | 19.1 | 40.8 | 0.075 |
| 40 | CF | RCA | Afrique | 6.9 | 23.4 | 63.7 | 27.4 | 40.7 | 0.075 |
| 41 | DJ | Djibouti | Afrique | 2.7 | 27.6 | 63.2 | 26.4 | 40.6 | 0.005 |
| 42 | GN | Guinée | Afrique | 0.6 | 15.7 | 72.1 | 21.6 | 40.3 | 0.075 |
| 43 | TD | Tchad | Afrique | 12.4 | 18.1 | 66.8 | 31.9 | 40.2 | 0.005 |
| 44 | LY | Libye | Afrique | 1.1 | 22.3 | 69.6 | 21.2 | 39.9 | 0.010 |
| 45 | ET | Éthiopie | Afrique | 0.4 | 23.1 | 66.8 | 21.8 | 39.8 | 0.005 |
| 46 | BI | Burundi | Afrique | 5.7 | 19.0 | 66.4 | 21.7 | 39.6 | 0.075 |
| 47 | MR | Mauritanie | Afrique | 1.4 | 24.9 | 67.0 | 22.5 | 39.5 | 0.005 |
| 48 | MM | Myanmar | Asie | 10.0 | 15.1 | 72.4 | 29.3 | 39.3 | 0.015 |
| 49 | MA | Maroc | Afrique | 1.0 | 17.2 | 76.9 | 17.8 | 39.3 | 0.090 |
| 50 | KM | Comores | Afrique | 0.5 | 25.0 | 62.4 | 28.2 | 39.3 | 0.075 |
| 51 | SH | SH | ? | 6.3 | 16.7 | 76.1 | 15.9 | 39.2 | 0.075 |
| 52 | GL | Groenland | Amériques | 2.4 | 26.8 | 57.3 | 15.4 | 39.1 | 0.075 |
| 53 | KN | Saint-Kitts | Amériques | 2.7 | 28.2 | 65.3 | 32.5 | 38.9 | 0.075 |
| 54 | GW | Guinée-Bissau | Afrique | 1.7 | 12.6 | 72.8 | 31.8 | 38.6 | 0.075 |
| 55 | NE | Niger | Afrique | 13.1 | 15.0 | 61.9 | 32.0 | 38.0 | 0.180 |
| 56 | SY | Syrie | Moyen-Orient | 0.4 | 17.4 | 72.1 | 30.0 | 37.9 | 0.005 |
| 57 | ST | São Tomé-et-Príncipe | Afrique | 3.1 | 24.0 | 62.8 | 24.8 | 37.8 | 0.075 |
| 58 | AF | Afghanistan | Afrique | 4.4 | 12.0 | 75.9 | 30.5 | 36.4 | 0.856 |
| 59 | GQ | Guinée équatoriale | Afrique | 0.3 | 13.0 | 70.3 | 47.4 | 32.4 | 0.075 |

### 6.4 Cluster 2 — Sous-équipés & à risque (15 pays)

| Rang | ISO2 | Pays | Région | IPv6% | HTTP/3% | TLS1.3% | Bot% | IMP | BGP exp.% |
|---:|---|---|---|---:|---:|---:|---:|---:|---:|
| 1 | CC | CC | ? | 78.6 | 0.9 | 87.3 | 65.6 | 51.7 | 0.075 |
| 2 | CX | CX | ? | 98.1 | 0.0 | 82.0 | 63.9 | 48.6 | 0.075 |
| 3 | TF | Terres australes | ? | 98.0 | 0.6 | 80.7 | 54.2 | 48.6 | 0.075 |
| 4 | GS | GS | ? | 81.6 | 0.6 | 73.3 | 35.8 | 47.3 | 0.075 |
| 5 | ER | Érythrée | Afrique | 57.3 | 8.6 | 74.1 | 17.3 | 45.8 | 0.005 |
| 6 | KP | Corée du Nord | Asie | 73.3 | 5.4 | 90.6 | 71.7 | 44.8 | 0.075 |
| 7 | EH | Sahara occidental | Afrique | 69.4 | 2.5 | 69.1 | 33.7 | 44.6 | 0.075 |
| 8 | FI | Finlande | Europe | 32.2 | 14.1 | 78.3 | 57.4 | 37.1 | 0.115 |
| 9 | AQ | AQ | ? | 42.9 | 1.4 | 95.4 | 72.6 | 35.8 | 0.075 |
| 10 | NL | Pays-Bas | Europe | 14.6 | 11.1 | 76.8 | 61.1 | 31.6 | 1.246 |
| 11 | HK | Hong Kong | Asie | 3.7 | 9.7 | 80.4 | 55.8 | 29.4 | 2.338 |
| 12 | SG | Singapour | Asie | 6.6 | 6.9 | 78.4 | 74.0 | 26.2 | 0.911 |
| 13 | IE | Irlande | Europe | 10.2 | 8.2 | 70.3 | 70.1 | 25.7 | 0.170 |
| 14 | IR | Iran | Moyen-Orient | 3.1 | 2.8 | 92.7 | 76.5 | 25.2 | 0.756 |
| 15 | GI | Gibraltar | Europe | 0.2 | 2.8 | 94.1 | 90.7 | 21.8 | 0.010 |

---
## 7. Analyse Régionale

### 7.1 Statistiques Moyennes par Région

| Région | N pays | IPv6% | HTTP/3% | TLS1.3% | Bot% | IMP | BGP exp.% |
|---|---:|---:|---:|---:|---:|---:|---:|
| Autre | 21 | 46.1 | 20.3 | 68.9 | 27.2 | **46.5** | 0.065 |
| Amériques | 51 | 20.9 | 26.4 | 66.7 | 14.1 | **45.9** | 0.794 |
| Océanie | 18 | 22.7 | 30.2 | 62.3 | 15.3 | **45.9** | 0.145 |
| Asie | 34 | 22.8 | 28.0 | 64.7 | 22.4 | **44.6** | 0.804 |
| Moyen-Orient | 14 | 18.2 | 23.6 | 69.2 | 21.4 | **43.6** | 0.249 |
| Afrique | 57 | 9.2 | 23.8 | 66.0 | 19.1 | **42.3** | 0.154 |
| Europe | 52 | 17.4 | 25.3 | 66.5 | 25.6 | **41.2** | 0.572 |

### 7.2 Répartition Clusters × Régions

| Région | CEn développement avancé | CMatures & Sécurisés | CSous-équipés & à risque | CVulnérables intermédiaires | Total |
|---|---:|---:|---:|---:|---:|
| Afrique | — | 16 | 2 | 39 | 57 |
| Amériques | 6 | 35 | — | 10 | 51 |
| Asie | 8 | 21 | 3 | 2 | 34 |
| Autre | 3 | 9 | 5 | 4 | 21 |
| Europe | 38 | 10 | 4 | — | 52 |
| Moyen-Orient | 3 | 7 | 1 | 3 | 14 |
| Océanie | 4 | 13 | — | 1 | 18 |

> **Légende :**
> C1 = Matures & Sécurisés
> C3 = En développement avancé
> C0 = Vulnérables intermédiaires
> C2 = Sous-équipés & à risque

---
## 8. Classements Pays

### 8.1 Top 20 Pays par IMP (Index de Maturité Protocolaire)

| Rang | ISO2 | Pays | Région | Cluster | IPv6% | HTTP/3% | TLS1.3% | IMP |
|---:|---|---|---|---|---:|---:|---:|---:|
| 1 | IN | Inde | Asie | Matures & Sécurisés | 64.8 | 27.0 | 66.8 | **58.1** |
| 2 | SA | Arabie saoudite | Moyen-Orient | Matures & Sécurisés | 56.8 | 24.0 | 69.8 | **56.6** |
| 3 | BL | Saint-Barthélemy | ? | Matures & Sécurisés | 58.4 | 31.6 | 64.3 | **55.8** |
| 4 | NP | Népal | Asie | Matures & Sécurisés | 51.2 | 30.7 | 62.9 | **55.2** |
| 5 | NR | Nauru | Océanie | Matures & Sécurisés | 52.1 | 30.3 | 55.4 | **54.8** |
| 6 | PN | PN | ? | En développement avancé | 80.4 | 29.7 | 56.3 | **54.5** |
| 7 | GR | Grèce | Europe | Matures & Sécurisés | 47.3 | 37.0 | 58.2 | **54.3** |
| 8 | MX | Mexique | Amériques | Matures & Sécurisés | 44.2 | 22.6 | 73.5 | **54.2** |
| 9 | MY | Malaisie | Asie | En développement avancé | 56.4 | 27.7 | 65.2 | **54.2** |
| 10 | GT | Guatemala | Amériques | Matures & Sécurisés | 46.8 | 22.4 | 73.0 | **54.0** |
| 11 | LK | Sri Lanka | Asie | Matures & Sécurisés | 47.2 | 39.2 | 55.9 | **53.9** |
| 12 | UY | Uruguay | Amériques | Matures & Sécurisés | 52.3 | 29.7 | 64.1 | **53.9** |
| 13 | TH | Thaïlande | Asie | Matures & Sécurisés | 42.5 | 32.7 | 62.5 | **53.8** |
| 14 | SR | Suriname | Amériques | Matures & Sécurisés | 40.9 | 25.5 | 70.3 | **53.7** |
| 15 | PR | Porto Rico | Amériques | Matures & Sécurisés | 45.7 | 27.1 | 67.5 | **53.6** |
| 16 | MF | Saint-Martin | ? | Matures & Sécurisés | 42.8 | 30.7 | 65.1 | **52.9** |
| 17 | BR | Brésil | Amériques | Matures & Sécurisés | 46.5 | 30.9 | 61.8 | **52.9** |
| 18 | UM | UM | ? | En développement avancé | 93.6 | 24.3 | 62.7 | **52.9** |
| 19 | NI | Nicaragua | Amériques | Matures & Sécurisés | 35.8 | 25.9 | 69.9 | **52.6** |
| 20 | CC | CC | ? | Sous-équipés & à risque | 78.6 | 0.9 | 87.3 | **51.7** |

### 8.2 Bottom 20 Pays par IMP

| Rang | ISO2 | Pays | Région | Cluster | IPv6% | HTTP/3% | TLS1.3% | IMP |
|---:|---|---|---|---|---:|---:|---:|---:|
| 1 | GI | Gibraltar | Europe | Sous-équipés & à risque | 0.2 | 2.8 | 94.1 | **21.8** |
| 2 | IR | Iran | Moyen-Orient | Sous-équipés & à risque | 3.1 | 2.8 | 92.7 | **25.2** |
| 3 | TM | Turkménistan | Asie | En développement avancé | 0.0 | 35.3 | 62.8 | **25.5** |
| 4 | IE | Irlande | Europe | Sous-équipés & à risque | 10.2 | 8.2 | 70.3 | **25.7** |
| 5 | IM | Île de Man | Europe | En développement avancé | 8.6 | 13.6 | 49.9 | **26.0** |
| 6 | SG | Singapour | Asie | Sous-équipés & à risque | 6.6 | 6.9 | 78.4 | **26.2** |
| 7 | HK | Hong Kong | Asie | Sous-équipés & à risque | 3.7 | 9.7 | 80.4 | **29.4** |
| 8 | NL | Pays-Bas | Europe | Sous-équipés & à risque | 14.6 | 11.1 | 76.8 | **31.6** |
| 9 | RU | Russie | Europe | En développement avancé | 7.6 | 17.6 | 63.5 | **31.7** |
| 10 | XK | Kosovo | Europe | En développement avancé | 4.1 | 23.3 | 57.6 | **32.4** |
| 11 | GQ | Guinée équatoriale | Afrique | Vulnérables intermédiaires | 0.3 | 13.0 | 70.3 | **32.4** |
| 12 | VA | VA | ? | En développement avancé | 12.2 | 20.9 | 68.3 | **33.3** |
| 13 | BY | Biélorussie | Europe | En développement avancé | 5.7 | 18.6 | 72.1 | **34.3** |
| 14 | AQ | AQ | ? | Sous-équipés & à risque | 42.9 | 1.4 | 95.4 | **35.8** |
| 15 | AL | Albanie | Europe | En développement avancé | 5.3 | 24.7 | 62.2 | **35.8** |
| 16 | AF | Afghanistan | Afrique | Vulnérables intermédiaires | 4.4 | 12.0 | 75.9 | **36.4** |
| 17 | MT | Malte | Europe | En développement avancé | 1.2 | 25.4 | 66.0 | **37.0** |
| 18 | FI | Finlande | Europe | Sous-équipés & à risque | 32.2 | 14.1 | 78.3 | **37.1** |
| 19 | KH | Cambodge | Asie | Matures & Sécurisés | 0.7 | 32.6 | 61.5 | **37.6** |
| 20 | ST | São Tomé-et-Príncipe | Afrique | Vulnérables intermédiaires | 3.1 | 24.0 | 62.8 | **37.8** |

### 8.3 Top 20 Pays par Exposition BGP

| Rang | ISO2 | Pays | Région | Cluster | BGP victime% | BGP hijackeur% | BGP risk |
|---:|---|---|---|---|---:|---:|---:|
| 1 | US | États-Unis | Amériques | En développement avancé | 29.229 | 23.502 | 52.731 |
| 2 | CN | Chine | Asie | En développement avancé | 10.557 | 9.971 | 20.529 |
| 3 | BR | Brésil | Amériques | Matures & Sécurisés | 6.077 | 5.146 | 11.223 |
| 4 | RU | Russie | Europe | En développement avancé | 5.892 | 5.366 | 11.258 |
| 5 | GB | Royaume-Uni | Europe | En développement avancé | 5.286 | 3.859 | 9.146 |
| 6 | IN | Inde | Asie | Matures & Sécurisés | 4.445 | 5.071 | 9.516 |
| 7 | ID | Indonésie | Asie | Matures & Sécurisés | 3.454 | 3.284 | 6.738 |
| 8 | HK | Hong Kong | Asie | Sous-équipés & à risque | 2.338 | 3.554 | 5.892 |
| 9 | DE | Allemagne | Europe | En développement avancé | 2.057 | 2.183 | 4.240 |
| 10 | PL | Pologne | Europe | En développement avancé | 1.632 | 1.507 | 3.139 |
| 11 | UA | Ukraine | Europe | Matures & Sécurisés | 1.602 | 1.071 | 2.673 |
| 12 | AU | Australie | Océanie | En développement avancé | 1.582 | 1.226 | 2.808 |
| 13 | FR | France | Europe | En développement avancé | 1.342 | 1.126 | 2.468 |
| 14 | ZA | Afrique du Sud | Afrique | Matures & Sécurisés | 1.332 | 0.776 | 2.107 |
| 15 | TR | Turquie | Europe | Matures & Sécurisés | 1.307 | 1.422 | 2.728 |
| 16 | NL | Pays-Bas | Europe | Sous-équipés & à risque | 1.246 | 1.822 | 3.069 |
| 17 | BD | Bangladesh | Asie | Matures & Sécurisés | 1.106 | 1.026 | 2.132 |
| 18 | ZM | Zambie | Afrique | Matures & Sécurisés | 1.081 | 1.026 | 2.107 |
| 19 | ES | Espagne | Europe | En développement avancé | 1.021 | 1.111 | 2.132 |
| 20 | SE | Suède | Europe | En développement avancé | 0.951 | 0.896 | 1.847 |

---
## 9. Corrélations Features × IMP

| Feature | r Spearman vs IMP | p-value | Contribution |
|---|---:|---:|---|
| IPv6 | 0.7359 | 0.0000 ✅ | forte ↑ |
| HTTP/3 | 0.2775 | 0.0000 ✅ | modérée ↑ |
| TLSv1.3 | -0.0375 | 0.5575  | faible |
| bot | -0.4376 | 0.0000 ✅ | modérée ↓ |
| mobile | 0.2343 | 0.0002 ✅ | modérée ↑ |
| bw_p50 | 0.0743 | 0.2446  | faible |
| dns_p50 | -0.0076 | 0.9053  | faible |
| bgp_victim_pct | 0.0162 | 0.8005  | faible |
| bgp_risk | 0.0279 | 0.6622  | faible |

---
## 10. Findings et Recommandations

### 10.1 Profils de Vulnérabilité Identifiés

**Matures & Sécurisés** (111 pays, 45% de l'échantillon) :
- IMP moyen : 46.1/100
- IPv6 : 19.4% · HTTP/3 : 29.9% · TLS 1.3 : 63.0%
- Exposition BGP (victime) : 0.279%

**En développement avancé** (62 pays, 25% de l'échantillon) :
- IMP moyen : 43.1/100
- IPv6 : 25.3% · HTTP/3 : 25.5% · TLS 1.3 : 66.5%
- Exposition BGP (victime) : 1.140%

**Vulnérables intermédiaires** (59 pays, 24% de l'échantillon) :
- IMP moyen : 41.9/100
- IPv6 : 8.7% · HTTP/3 : 22.0% · TLS 1.3 : 68.0%
- Exposition BGP (victime) : 0.103%

**Sous-équipés & à risque** (15 pays, 6% de l'échantillon) :
- IMP moyen : 37.6/100
- IPv6 : 44.7% · HTTP/3 : 5.0% · TLS 1.3 : 81.6%
- Exposition BGP (victime) : 0.405%

### 10.2 Observations Clés

1. **Fracture numérique protocoles :** L'écart d'IMP entre le cluster le plus mature et le moins avancé reflète une inégalité systémique d'adoption des protocoles modernes.

2. **BGP exposure concentrée :** Les grandes économies internet (US, CN, EU) concentrent la majorité des événements BGP — à la fois comme hijackeurs et victimes — indépendamment du niveau de maturité protocolaire.

3. **Mobile vs. Infrastructure :** Les pays avec fort taux mobile (Afrique, Asie du Sud) peuvent montrer un IPv6 faible mais un HTTP/3 paradoxalement élevé (adoption plus rapide des nouvelles piles réseau mobiles).

4. **Clusters régionaux :** L'Europe du Nord et l'Asie de l'Est dominent les clusters matures ; l'Afrique subsaharienne et certains pays d'Asie centrale constituent l'essentiel du cluster vulnérable.

5. **TLS 1.3 universellement stable :** Contrairement à IPv6 et HTTP/3, TLS 1.3 montre peu de variance inter-clusters — suggérant une adoption relativement uniforme, probablement pilotée par les grands CDNs (Cloudflare, Akamai).

---
*Rapport généré automatiquement par `phase_I_clustering.py` le 2026-06-16 22:17:39.*  
*Sources : Cloudflare Radar API v4 — 25 datasets nettoyés.*  
*Prochaine étape : Phase J — Détection d'anomalies consolidée.*