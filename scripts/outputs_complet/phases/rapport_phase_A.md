# Rapport Phase A — Préparation et Qualité des Données
**Cloudflare Radar Dataset — Juin 2025 / Juin 2026**  
**Auteur :** Issakha Thiam  
**Généré le :** 2026-06-16 12:40:44  
**Python :** 3.13 | pandas 2.2.3 | numpy 2.2.4

---
## 1. Résumé Exécutif

| Métrique | Valeur |
|---|---|
| Fichiers analysés | **25** |
| Fichiers sans problème | **10** (40.0%) |
| Fichiers avec avertissements | **15** (60.0%) |
| Fichiers en erreur | **0** |
| Lignes totales (brut) | **161,518** |
| Cellules totales | **1,406,384** |
| Valeurs manquantes totales | **20,482** (1.46%) |
| Doublons détectés | **1** |
| Répertoire nettoyé | `cleaned/` (25 CSV générés) |

### 1.1 Statut par fichier

| Fichier | Lignes | Colonnes | Taille Ko | Statut | Avertissements |
|---|---:|---:|---:|---|---|
| `attacks_l3_bitrate` | 53 | 7 | 4.0 | ✅ OK | — |
| `attacks_l3_ip_version` | 53 | 4 | 2.7 | ✅ OK | — |
| `attacks_l3_protocol` | 53 | 6 | 3.5 | ⚠️ AVERTISSEMENTS | 2 lignes (3.77%) avec somme % hors [99,101] |
| `attacks_l7_http_method` | 85 | 24 | 11.6 | ⚠️ AVERTISSEMENTS | 1020 valeurs manquantes (50.0% du total) |
| `attacks_l7_http_version` | 85 | 24 | 7.2 | ⚠️ AVERTISSEMENTS | 1615 valeurs manquantes (79.17% du total) |
| `attacks_l7_vertical` | 85 | 24 | 11.6 | ⚠️ AVERTISSEMENTS | 1020 valeurs manquantes (50.0% du total) |
| `bgp_hijacks` | 20,000 | 18 | 9911.5 | ⚠️ AVERTISSEMENTS | 388 valeurs manquantes (0.11% du total) |
| `bgp_leaks` | 20,000 | 13 | 2772.5 | ⚠️ AVERTISSEMENTS | 1 doublons (0.005%) |
| `bgp_timeseries` | 53 | 2 | 1.9 | ✅ OK | — |
| `dns_timeseries` | 52 | 2 | 1.6 | ✅ OK | — |
| `email_dmarc` | 53 | 5 | 2.9 | ✅ OK | — |
| `email_dkim` | 53 | 5 | 2.9 | ✅ OK | — |
| `email_spf` | 53 | 5 | 2.9 | ✅ OK | — |
| `email_malicious` | 53 | 4 | 2.7 | ✅ OK | — |
| `email_spam` | 53 | 4 | 2.4 | ✅ OK | — |
| `email_spoof` | 53 | 4 | 2.5 | ✅ OK | — |
| `http_bot_class` | 13,409 | 4 | 577.1 | ⚠️ AVERTISSEMENTS | 583 valeurs manquantes (1.09% du total) |
| `http_browser_family` | 13,409 | 12 | 1376.1 | ⚠️ AVERTISSEMENTS | 2703 valeurs manquantes (1.68% du total) |
| `http_device_type` | 13,409 | 5 | 684.3 | ⚠️ AVERTISSEMENTS | 848 valeurs manquantes (1.26% du total) |
| `http_http_version` | 13,409 | 5 | 703.4 | ⚠️ AVERTISSEMENTS | 848 valeurs manquantes (1.26% du total) |
| `http_ip_version` | 13,409 | 4 | 572.6 | ⚠️ AVERTISSEMENTS | 583 valeurs manquantes (1.09% du total) |
| `http_os` | 13,409 | 9 | 1141.3 | ⚠️ AVERTISSEMENTS | 1908 valeurs manquantes (1.58% du total) |
| `http_tls_version` | 13,409 | 7 | 901.1 | ⚠️ AVERTISSEMENTS | 1378 valeurs manquantes (1.47% du total) |
| `iqi_bandwidth` | 13,409 | 6 | 796.9 | ⚠️ AVERTISSEMENTS | 3794 valeurs manquantes (4.72% du total) |
| `iqi_dns` | 13,409 | 6 | 746.3 | ⚠️ AVERTISSEMENTS | 3794 valeurs manquantes (4.72% du total) |

---
## 2. A1 — Audit de Complétude

### attacks_l3_bitrate
- **Lignes :** 53 | **Colonnes :** 7 | **Manquants totaux :** 0 (0.0%)

_Aucune valeur manquante._

### attacks_l3_ip_version
- **Lignes :** 53 | **Colonnes :** 4 | **Manquants totaux :** 0 (0.0%)

_Aucune valeur manquante._

### attacks_l3_protocol
- **Lignes :** 53 | **Colonnes :** 6 | **Manquants totaux :** 0 (0.0%)

_Aucune valeur manquante._

### attacks_l7_http_method
- **Lignes :** 85 | **Colonnes :** 24 | **Manquants totaux :** 1,020 (50.0%)

| Colonne | Manquants | % manquant |
|---|---:|---:|
| `Computer and Electronics` | 85 | 100.0% |
| `Internet and Telecom` | 85 | 100.0% |
| `Shopping & General Merchandise` | 85 | 100.0% |
| `Finance` | 85 | 100.0% |
| `Gambling` | 85 | 100.0% |
| `News, Media, and Publications` | 85 | 100.0% |
| `Business and Industry` | 85 | 100.0% |
| `Professional Services` | 85 | 100.0% |
| `Art, Entertainment & Recreation` | 85 | 100.0% |
| `HTTP/2` | 85 | 100.0% |
| `HTTP/1.x` | 85 | 100.0% |
| `HTTP/3` | 85 | 100.0% |

### attacks_l7_http_version
- **Lignes :** 85 | **Colonnes :** 24 | **Manquants totaux :** 1,615 (79.17%)

| Colonne | Manquants | % manquant |
|---|---:|---:|
| `Computer and Electronics` | 85 | 100.0% |
| `Internet and Telecom` | 85 | 100.0% |
| `other` | 85 | 100.0% |
| `Shopping & General Merchandise` | 85 | 100.0% |
| `Finance` | 85 | 100.0% |
| `Gambling` | 85 | 100.0% |
| `News, Media, and Publications` | 85 | 100.0% |
| `Business and Industry` | 85 | 100.0% |
| `Professional Services` | 85 | 100.0% |
| `Art, Entertainment & Recreation` | 85 | 100.0% |
| `GET` | 85 | 100.0% |
| `POST` | 85 | 100.0% |
| `HEAD` | 85 | 100.0% |
| `OPTIONS` | 85 | 100.0% |
| `PATCH` | 85 | 100.0% |
| `DELETE` | 85 | 100.0% |
| `PUT` | 85 | 100.0% |
| `UNKNOWN` | 85 | 100.0% |
| `ACL` | 85 | 100.0% |

### attacks_l7_vertical
- **Lignes :** 85 | **Colonnes :** 24 | **Manquants totaux :** 1,020 (50.0%)

| Colonne | Manquants | % manquant |
|---|---:|---:|
| `GET` | 85 | 100.0% |
| `POST` | 85 | 100.0% |
| `HEAD` | 85 | 100.0% |
| `OPTIONS` | 85 | 100.0% |
| `PATCH` | 85 | 100.0% |
| `DELETE` | 85 | 100.0% |
| `PUT` | 85 | 100.0% |
| `UNKNOWN` | 85 | 100.0% |
| `ACL` | 85 | 100.0% |
| `HTTP/2` | 85 | 100.0% |
| `HTTP/1.x` | 85 | 100.0% |
| `HTTP/3` | 85 | 100.0% |

### bgp_hijacks
- **Lignes :** 20,000 | **Colonnes :** 18 | **Manquants totaux :** 388 (0.11%)

| Colonne | Manquants | % manquant |
|---|---:|---:|
| `hijacker_country` | 388 | 1.94% |

### bgp_leaks
- **Lignes :** 20,000 | **Colonnes :** 13 | **Manquants totaux :** 0 (0.0%)

_Aucune valeur manquante._

### bgp_timeseries
- **Lignes :** 53 | **Colonnes :** 2 | **Manquants totaux :** 0 (0.0%)

_Aucune valeur manquante._

### dns_timeseries
- **Lignes :** 52 | **Colonnes :** 2 | **Manquants totaux :** 0 (0.0%)

_Aucune valeur manquante._

### email_dmarc
- **Lignes :** 53 | **Colonnes :** 5 | **Manquants totaux :** 0 (0.0%)

_Aucune valeur manquante._

### email_dkim
- **Lignes :** 53 | **Colonnes :** 5 | **Manquants totaux :** 0 (0.0%)

_Aucune valeur manquante._

### email_spf
- **Lignes :** 53 | **Colonnes :** 5 | **Manquants totaux :** 0 (0.0%)

_Aucune valeur manquante._

### email_malicious
- **Lignes :** 53 | **Colonnes :** 4 | **Manquants totaux :** 0 (0.0%)

_Aucune valeur manquante._

### email_spam
- **Lignes :** 53 | **Colonnes :** 4 | **Manquants totaux :** 0 (0.0%)

_Aucune valeur manquante._

### email_spoof
- **Lignes :** 53 | **Colonnes :** 4 | **Manquants totaux :** 0 (0.0%)

_Aucune valeur manquante._

### http_bot_class
- **Lignes :** 13,409 | **Colonnes :** 4 | **Manquants totaux :** 583 (1.09%)

| Colonne | Manquants | % manquant |
|---|---:|---:|
| `human` | 265 | 1.98% |
| `bot` | 265 | 1.98% |
| `country_iso2` | 53 | 0.4% |

### http_browser_family
- **Lignes :** 13,409 | **Colonnes :** 12 | **Manquants totaux :** 2,703 (1.68%)

| Colonne | Manquants | % manquant |
|---|---:|---:|
| `chrome` | 265 | 1.98% |
| `safari` | 265 | 1.98% |
| `edge` | 265 | 1.98% |
| `firefox` | 265 | 1.98% |
| `samsung` | 265 | 1.98% |
| `opera` | 265 | 1.98% |
| `ucbrowser` | 265 | 1.98% |
| `yandex` | 265 | 1.98% |
| `brave` | 265 | 1.98% |
| `coccoc` | 265 | 1.98% |
| `country_iso2` | 53 | 0.4% |

### http_device_type
- **Lignes :** 13,409 | **Colonnes :** 5 | **Manquants totaux :** 848 (1.26%)

| Colonne | Manquants | % manquant |
|---|---:|---:|
| `desktop` | 265 | 1.98% |
| `mobile` | 265 | 1.98% |
| `other` | 265 | 1.98% |
| `country_iso2` | 53 | 0.4% |

### http_http_version
- **Lignes :** 13,409 | **Colonnes :** 5 | **Manquants totaux :** 848 (1.26%)

| Colonne | Manquants | % manquant |
|---|---:|---:|
| `HTTP/2` | 265 | 1.98% |
| `HTTP/1.x` | 265 | 1.98% |
| `HTTP/3` | 265 | 1.98% |
| `country_iso2` | 53 | 0.4% |

### http_ip_version
- **Lignes :** 13,409 | **Colonnes :** 4 | **Manquants totaux :** 583 (1.09%)

| Colonne | Manquants | % manquant |
|---|---:|---:|
| `IPv6` | 265 | 1.98% |
| `IPv4` | 265 | 1.98% |
| `country_iso2` | 53 | 0.4% |

### http_os
- **Lignes :** 13,409 | **Colonnes :** 9 | **Manquants totaux :** 1,908 (1.58%)

| Colonne | Manquants | % manquant |
|---|---:|---:|
| `WINDOWS` | 265 | 1.98% |
| `ANDROID` | 265 | 1.98% |
| `MACOSX` | 265 | 1.98% |
| `IOS` | 265 | 1.98% |
| `LINUX` | 265 | 1.98% |
| `CHROMEOS` | 265 | 1.98% |
| `SMART_TV` | 265 | 1.98% |
| `country_iso2` | 53 | 0.4% |

### http_tls_version
- **Lignes :** 13,409 | **Colonnes :** 7 | **Manquants totaux :** 1,378 (1.47%)

| Colonne | Manquants | % manquant |
|---|---:|---:|
| `TLS 1.3` | 265 | 1.98% |
| `TLS QUIC` | 265 | 1.98% |
| `TLS 1.2` | 265 | 1.98% |
| `TLS 1.1` | 265 | 1.98% |
| `TLS 1.0` | 265 | 1.98% |
| `country_iso2` | 53 | 0.4% |

### iqi_bandwidth
- **Lignes :** 13,409 | **Colonnes :** 6 | **Manquants totaux :** 3,794 (4.72%)

| Colonne | Manquants | % manquant |
|---|---:|---:|
| `p25` | 1,247 | 9.3% |
| `p50` | 1,247 | 9.3% |
| `p75` | 1,247 | 9.3% |
| `country_iso2` | 53 | 0.4% |

### iqi_dns
- **Lignes :** 13,409 | **Colonnes :** 6 | **Manquants totaux :** 3,794 (4.72%)

| Colonne | Manquants | % manquant |
|---|---:|---:|
| `p75` | 1,247 | 9.3% |
| `p50` | 1,247 | 9.3% |
| `p25` | 1,247 | 9.3% |
| `country_iso2` | 53 | 0.4% |

---
## 3. A2 — Cohérence des Distributions (Sommes %)

Tolérance : ±1 point (somme attendue = 100). `zero_rows` = lignes avec toutes valeurs à 0.

| Fichier | Colonnes vérifiées | Lignes OK | Lignes zéro | Lignes invalides | Somme moy. | Somme min | Somme max |
|---|---|---:|---:|---:|---:|---:|---:|
| `attacks_l3_bitrate` | `UNDER_500_MBPS`, `_1_GBPS_TO_10_GBPS`, `_500_MBPS_TO_1_GBPS`, `_10_GBPS_TO_100_GBPS` +1 | 53 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| `attacks_l3_ip_version` | `IPv4`, `IPv6` | 53 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| `attacks_l3_protocol` | `UDP`, `TCP`, `GRE`, `ICMP` | 51 | 0 | 2 | 99.7233 | 97.5611 | 99.9998 |
| `attacks_l7_http_method` | `GET`, `POST`, `HEAD`, `OPTIONS` +5 | 85 | 0 | 0 | 99.9998 | 99.999 | 100.0 |
| `attacks_l7_http_version` | `Computer and Electronics`, `Internet and Telecom`, `other`, `Shopping & General Merchandise` +18 | 85 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| `attacks_l7_vertical` | `Computer and Electronics`, `Internet and Telecom`, `other`, `Shopping & General Merchandise` +18 | 85 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| `email_dmarc` | `PASS`, `NONE`, `FAIL` | 53 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| `email_dkim` | `PASS`, `NONE`, `FAIL` | 53 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| `email_spf` | `PASS`, `NONE`, `FAIL` | 53 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| `email_malicious` | `NOT_MALICIOUS`, `MALICIOUS` | 53 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| `email_spam` | `NOT_SPAM`, `SPAM` | 53 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| `email_spoof` | `NOT_SPOOF`, `SPOOF` | 53 | 0 | 0 | 100.0 | 100.0 | 100.0 |
| `http_bot_class` | `human`, `bot` | 13,113 | 296 | 0 | 97.7925 | 0.0 | 100.0 |
| `http_browser_family` | `chrome`, `safari`, `edge`, `firefox` +6 | 13,106 | 303 | 0 | 97.7403 | 0.0 | 100.0 |
| `http_device_type` | `desktop`, `mobile`, `other` | 13,111 | 298 | 0 | 97.7776 | 0.0 | 100.0 |
| `http_http_version` | `HTTP/2`, `HTTP/1.x`, `HTTP/3` | 13,114 | 295 | 0 | 97.8 | 0.0 | 100.0 |
| `http_ip_version` | `IPv6`, `IPv4` | 13,102 | 307 | 0 | 97.7105 | 0.0 | 100.0 |
| `http_os` | `WINDOWS`, `ANDROID`, `MACOSX`, `IOS` +3 | 13,106 | 303 | 0 | 97.7403 | 0.0 | 100.0 |
| `http_tls_version` | `TLS 1.3`, `TLS QUIC`, `TLS 1.2`, `TLS 1.1` +1 | 13,113 | 296 | 0 | 97.7925 | 0.0 | 100.0 |

---
## 4. A3 — Analyse des Doublons

| Fichier | Doublons | % |
|---|---:|---:|
| `attacks_l3_bitrate` |  0 | 0.0% |
| `attacks_l3_ip_version` |  0 | 0.0% |
| `attacks_l3_protocol` |  0 | 0.0% |
| `attacks_l7_http_method` |  0 | 0.0% |
| `attacks_l7_http_version` |  0 | 0.0% |
| `attacks_l7_vertical` |  0 | 0.0% |
| `bgp_hijacks` |  0 | 0.0% |
| `bgp_leaks` | ⚠️ 1 | 0.005% |
| `bgp_timeseries` |  0 | 0.0% |
| `dns_timeseries` |  0 | 0.0% |
| `email_dmarc` |  0 | 0.0% |
| `email_dkim` |  0 | 0.0% |
| `email_spf` |  0 | 0.0% |
| `email_malicious` |  0 | 0.0% |
| `email_spam` |  0 | 0.0% |
| `email_spoof` |  0 | 0.0% |
| `http_bot_class` |  0 | 0.0% |
| `http_browser_family` |  0 | 0.0% |
| `http_device_type` |  0 | 0.0% |
| `http_http_version` |  0 | 0.0% |
| `http_ip_version` |  0 | 0.0% |
| `http_os` |  0 | 0.0% |
| `http_tls_version` |  0 | 0.0% |
| `iqi_bandwidth` |  0 | 0.0% |
| `iqi_dns` |  0 | 0.0% |

---
## 5. A4 — Plages Temporelles

| Fichier | Date min | Date max | Nb dates distinctes | Timestamps invalides |
|---|---|---|---:|---:|
| `attacks_l3_bitrate` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |
| `attacks_l3_ip_version` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |
| `attacks_l3_protocol` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |
| `attacks_l7_http_method` | 2026-03-17 00:00:00+00:00 | 2026-06-09 00:00:00+00:00 | 85 | 0 |
| `attacks_l7_http_version` | 2026-03-17 00:00:00+00:00 | 2026-06-09 00:00:00+00:00 | 85 | 0 |
| `attacks_l7_vertical` | 2026-03-17 00:00:00+00:00 | 2026-06-09 00:00:00+00:00 | 85 | 0 |
| `bgp_hijacks` | 2025-12-04 06:23:35.266000+00:00 | 2026-06-09 15:21:19.798000+00:00 | 19,783 | 23 |
| `bgp_leaks` | 2026-03-02 03:27:05+00:00 | 2026-06-09 14:13:07+00:00 | 19,427 | 0 |
| `bgp_timeseries` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |
| `dns_timeseries` | 2025-06-09 00:00:00+00:00 | 2026-06-01 00:00:00+00:00 | 52 | 0 |
| `email_dmarc` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |
| `email_dkim` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |
| `email_spf` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |
| `email_malicious` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |
| `email_spam` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |
| `email_spoof` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |
| `http_bot_class` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |
| `http_browser_family` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |
| `http_device_type` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |
| `http_http_version` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |
| `http_ip_version` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |
| `http_os` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |
| `http_tls_version` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |
| `iqi_bandwidth` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |
| `iqi_dns` | 2025-06-09 00:00:00+00:00 | 2026-06-08 00:00:00+00:00 | 53 | 0 |

---
## 6. A5 — Couverture Géographique

| Fichier | Pays uniques | Échantillon de pays |
|---|---:|---|
| `http_bot_class` | 252 | AD, AE, AF, AG, AI, AL, AM, AN… |
| `http_browser_family` | 252 | AD, AE, AF, AG, AI, AL, AM, AN… |
| `http_device_type` | 252 | AD, AE, AF, AG, AI, AL, AM, AN… |
| `http_http_version` | 252 | AD, AE, AF, AG, AI, AL, AM, AN… |
| `http_ip_version` | 252 | AD, AE, AF, AG, AI, AL, AM, AN… |
| `http_os` | 252 | AD, AE, AF, AG, AI, AL, AM, AN… |
| `http_tls_version` | 252 | AD, AE, AF, AG, AI, AL, AM, AN… |
| `iqi_bandwidth` | 252 | AD, AE, AF, AG, AI, AL, AM, AN… |
| `iqi_dns` | 252 | AD, AE, AF, AG, AI, AL, AM, AN… |

---
## 7. A6 — Parsing des Colonnes JSON (BGP)

### bgp_hijacks
**Actions effectuées :**
- 'min_hijack_ts' converti en datetime UTC (23 valeurs invalides)
- peer_asns → peer_asns_count (int) + peer_asns_list
- prefixes → prefixes_count (int) + prefixes_list
- victim_asns → victim_asns_count (int)
- victim_countries → victim_countries_count + victim_countries_list
- tags → tags_total_score + tags_count + tags_names
- timestamps → datetime UTC
- hijacker_country : 388 null → 'UNKNOWN'

**Statistiques des champs JSON parsés (comptes d'éléments) :**

| Champ | N valides | Moyenne | Médiane | Min | Max | Manquants |
|---|---:|---:|---:|---:|---:|---:|
| `peer_asns` | 20,000 | 7.1178 | 2.0 | 1.0 | 60.0 | 0 |
| `prefixes` | 20,000 | 3.795 | 1.0 | 1.0 | 15129.0 | 0 |
| `tags` | 20,000 | 4.4432 | 4.0 | 4.0 | 12.0 | 0 |
| `victim_asns` | 20,000 | 1.2874 | 1.0 | 1.0 | 1611.0 | 0 |
| `victim_countries` | 20,000 | 1.1092 | 1.0 | 1.0 | 138.0 | 0 |

### bgp_leaks
**Actions effectuées :**
- 'detected_ts' converti en datetime UTC (0 valeurs invalides)
- 1 doublons supprimés (clé: id)
- countries → countries_list + countries_count + countries_unique
- leak_seg → leak_seg_list + leak_seg_len (longueur de la chaîne ASN)
- timestamps → datetime UTC

**Statistiques des champs JSON parsés (comptes d'éléments) :**

| Champ | N valides | Moyenne | Médiane | Min | Max | Manquants |
|---|---:|---:|---:|---:|---:|---:|
| `countries` | 19,999 | 2.9912 | 3.0 | 2.0 | 3.0 | 0 |

---
## 8. A7 — Statistiques Descriptives par Variable

Statistiques calculées sur données **brutes** (avant nettoyage).

### attacks_l3_bitrate
*Type :* `timeseries_pct` | *Lignes :* 53

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `UNDER_500_MBPS` | 53 | 0 | 57.1248 | 55.5444 | 20.2146 | 1.6455 | 27.3491 | 44.841 | 69.7505 | 95.6114 | 99.9089 | 0.04 | 0.4338 |
| `_1_GBPS_TO_10_GBPS` | 53 | 0 | 24.823 | 21.5383 | 19.4201 | 0.0 | 0.0 | 13.2758 | 33.7218 | 62.4386 | 94.9972 | 1.2796 | 2.541 |
| `_500_MBPS_TO_1_GBPS` | 53 | 0 | 13.7409 | 12.52 | 9.9696 | 0.0 | 0.0755 | 7.8776 | 17.6156 | 31.907 | 44.04 | 1.1706 | 1.7364 |
| `_10_GBPS_TO_100_GBPS` | 53 | 0 | 4.2441 | 1.2006 | 7.7601 | 0.0 | 0.0 | 0.1645 | 3.3424 | 24.3912 | 33.235 | 2.4053 | 4.9883 |
| `OVER_100_GBPS` | 53 | 0 | 0.0672 | 0.0159 | 0.1291 | 0.0002 | 0.0015 | 0.0046 | 0.0684 | 0.222 | 0.6694 | 3.5999 | 14.0291 |

### attacks_l3_ip_version
*Type :* `timeseries_pct` | *Lignes :* 53

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `IPv4` | 53 | 0 | 99.729 | 99.7863 | 0.2796 | 98.4389 | 99.3238 | 99.6792 | 99.9031 | 99.9699 | 99.9869 | -2.8554 | 10.2228 |
| `IPv6` | 53 | 0 | 0.271 | 0.2137 | 0.2796 | 0.0131 | 0.0301 | 0.0969 | 0.3208 | 0.6762 | 1.5611 | 2.8554 | 10.2228 |

### attacks_l3_protocol
*Type :* `timeseries_pct` | *Lignes :* 53

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `UDP` | 53 | 0 | 73.9597 | 75.619 | 13.4107 | 39.1675 | 47.0572 | 64.9348 | 82.914 | 93.6718 | 98.9328 | -0.5173 | 0.0725 |
| `TCP` | 53 | 0 | 24.9206 | 22.4632 | 13.5674 | 1.0225 | 5.2191 | 16.65 | 34.3885 | 52.6471 | 60.7676 | 0.5961 | 0.1054 |
| `GRE` | 53 | 0 | 0.7031 | 0.1719 | 2.9768 | 0.0 | 0.0 | 0.0214 | 0.3331 | 1.5497 | 21.7191 | 7.0305 | 50.4419 |
| `ICMP` | 53 | 0 | 0.1399 | 0.0354 | 0.322 | 0.0015 | 0.005 | 0.0133 | 0.0843 | 0.634 | 1.7992 | 3.9463 | 16.656 |

### attacks_l7_http_method
*Type :* `timeseries_pct` | *Lignes :* 85

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `GET` | 85 | 0 | 81.9889 | 81.6518 | 2.7143 | 76.6025 | 77.4507 | 80.3164 | 83.947 | 86.1011 | 88.5041 | 0.1612 | -0.4375 |
| `POST` | 85 | 0 | 14.6876 | 14.6523 | 2.8862 | 8.1202 | 10.7118 | 12.5711 | 16.7149 | 19.9912 | 20.4521 | 0.1572 | -0.5853 |
| `HEAD` | 85 | 0 | 2.4032 | 2.4256 | 0.6498 | 1.053 | 1.4564 | 1.932 | 2.8 | 3.4722 | 4.0492 | 0.1658 | -0.4032 |
| `OPTIONS` | 85 | 0 | 0.506 | 0.482 | 0.1523 | 0.2811 | 0.3302 | 0.414 | 0.5479 | 0.7099 | 1.3697 | 2.5533 | 11.8019 |
| `PATCH` | 85 | 0 | 0.1601 | 0.1584 | 0.0326 | 0.086 | 0.1132 | 0.1357 | 0.1845 | 0.2139 | 0.241 | 0.3041 | -0.1903 |
| `DELETE` | 85 | 0 | 0.1185 | 0.1193 | 0.0217 | 0.0779 | 0.0846 | 0.1028 | 0.1325 | 0.1549 | 0.1854 | 0.4675 | 0.2684 |
| `PUT` | 85 | 0 | 0.1099 | 0.1089 | 0.0199 | 0.0658 | 0.0783 | 0.096 | 0.1245 | 0.1401 | 0.1679 | 0.1859 | 0.0583 |
| `UNKNOWN` | 85 | 0 | 0.0252 | 0.0073 | 0.1324 | 0.0026 | 0.004 | 0.0052 | 0.0106 | 0.0336 | 1.2265 | 9.1128 | 83.6425 |
| `ACL` | 85 | 0 | 0.0004 | 0.0002 | 0.0004 | 0.0 | 0.0001 | 0.0001 | 0.0004 | 0.0011 | 0.002 | 2.631 | 7.6117 |

### attacks_l7_http_version
*Type :* `timeseries_pct` | *Lignes :* 85

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `HTTP/2` | 85 | 0 | 52.9446 | 53.2754 | 5.6785 | 43.0143 | 44.6937 | 47.464 | 58.5336 | 60.4862 | 61.6911 | -0.1181 | -1.4042 |
| `HTTP/1.x` | 85 | 0 | 41.0167 | 40.0631 | 5.5426 | 31.8855 | 33.9772 | 36.0208 | 46.1325 | 49.2662 | 51.6479 | 0.217 | -1.3339 |
| `HTTP/3` | 85 | 0 | 6.0388 | 5.9724 | 0.7702 | 4.3477 | 4.7837 | 5.5154 | 6.4489 | 7.2905 | 7.9878 | 0.2085 | -0.0892 |

### attacks_l7_vertical
*Type :* `timeseries_pct` | *Lignes :* 85

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `Computer and Electronics` | 85 | 0 | 22.7621 | 22.6833 | 2.5832 | 18.1388 | 19.3514 | 20.7142 | 23.8847 | 27.2181 | 33.0439 | 0.9677 | 2.0194 |
| `Internet and Telecom` | 85 | 0 | 22.4454 | 21.395 | 3.9536 | 14.8463 | 16.6577 | 19.5295 | 24.6481 | 29.509 | 30.4759 | 0.3808 | -0.7406 |
| `other` | 85 | 0 | 9.5435 | 8.6947 | 2.7453 | 6.1115 | 6.6813 | 7.999 | 10.118 | 15.1956 | 20.4542 | 1.8596 | 4.0775 |
| `Shopping & General Merchandise` | 85 | 0 | 11.5114 | 10.9018 | 2.0082 | 8.6245 | 9.3312 | 10.1465 | 12.1214 | 15.2562 | 19.2385 | 1.5139 | 2.5143 |
| `Finance` | 85 | 0 | 8.8809 | 7.6385 | 2.7257 | 5.9526 | 6.1792 | 6.7893 | 10.3753 | 14.1243 | 15.9016 | 1.0194 | -0.1265 |
| `Gambling` | 85 | 0 | 8.5914 | 7.9879 | 2.9676 | 2.8187 | 4.4989 | 6.7296 | 10.5499 | 14.1959 | 18.1274 | 0.6623 | 0.3082 |
| `News, Media, and Publications` | 85 | 0 | 6.1976 | 6.197 | 1.5735 | 2.9764 | 3.8173 | 5.342 | 6.8754 | 8.3545 | 12.2849 | 0.9607 | 2.6087 |
| `Business and Industry` | 85 | 0 | 2.776 | 2.5032 | 0.7536 | 1.9325 | 2.0476 | 2.2484 | 2.9752 | 4.2097 | 5.9468 | 1.66 | 3.1457 |
| `Professional Services` | 85 | 0 | 4.217 | 3.6897 | 1.8477 | 2.4426 | 2.7253 | 3.2686 | 4.4681 | 6.6617 | 14.7871 | 3.7505 | 17.9867 |
| `Art, Entertainment & Recreation` | 85 | 0 | 3.0745 | 3.7107 | 1.4441 | 0.3008 | 0.4506 | 1.8889 | 4.0468 | 4.5125 | 6.4364 | -0.6571 | -0.677 |

### bgp_timeseries
*Type :* `timeseries_numeric` | *Lignes :* 53

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `values` | 53 | 0 | 11970274698.4528 | 11309324528.0 | 2874387120.9611 | 6139854290.0 | 9134853148.0 | 10489344275.0 | 12833324067.0 | 16900338177.4 | 25499721429.0 | 2.2729 | 8.8885 |

### dns_timeseries
*Type :* `timeseries_numeric` | *Lignes :* 52

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `values` | 52 | 0 | 0.7587 | 0.7452 | 0.1186 | 0.5809 | 0.6126 | 0.6479 | 0.8365 | 0.9535 | 1.0 | 0.3778 | -0.9633 |

### email_dmarc
*Type :* `timeseries_pct` | *Lignes :* 53

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `PASS` | 53 | 0 | 87.916 | 88.0665 | 1.9768 | 79.2246 | 85.5061 | 87.1517 | 88.9601 | 90.8786 | 91.7055 | -1.5935 | 6.3287 |
| `NONE` | 53 | 0 | 6.7779 | 6.656 | 1.4449 | 4.6231 | 4.8745 | 5.737 | 7.8367 | 9.4396 | 10.8663 | 0.7318 | 0.067 |
| `FAIL` | 53 | 0 | 5.3061 | 4.6533 | 2.0876 | 2.8679 | 3.3304 | 4.0588 | 6.1745 | 8.408 | 14.9781 | 2.3078 | 7.9045 |

### email_dkim
*Type :* `timeseries_pct` | *Lignes :* 53

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `PASS` | 53 | 0 | 89.4109 | 89.3933 | 1.8144 | 84.1244 | 86.2753 | 88.4224 | 90.2538 | 92.8691 | 93.1691 | -0.1264 | 0.8813 |
| `NONE` | 53 | 0 | 8.8915 | 8.9481 | 1.8278 | 5.5022 | 5.7589 | 7.7045 | 9.8578 | 11.7481 | 14.092 | 0.246 | 0.2391 |
| `FAIL` | 53 | 0 | 1.6976 | 1.4364 | 0.576 | 0.9343 | 1.134 | 1.3187 | 2.0658 | 2.6261 | 3.9222 | 1.5117 | 2.9003 |

### email_spf
*Type :* `timeseries_pct` | *Lignes :* 53

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `PASS` | 53 | 0 | 79.0015 | 79.172 | 2.2305 | 74.2084 | 75.0077 | 77.5464 | 80.6859 | 82.0307 | 82.4171 | -0.3401 | -0.7122 |
| `NONE` | 53 | 0 | 4.7298 | 4.2956 | 1.4806 | 2.722 | 3.1898 | 3.7322 | 5.2137 | 7.4645 | 9.8207 | 1.5738 | 2.6323 |
| `FAIL` | 53 | 0 | 16.2687 | 15.7622 | 2.1738 | 12.9528 | 13.8235 | 14.7676 | 16.8644 | 20.6433 | 22.4926 | 1.1577 | 0.803 |

### email_malicious
*Type :* `timeseries_pct` | *Lignes :* 53

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `NOT_MALICIOUS` | 53 | 0 | 89.1978 | 91.6702 | 6.5125 | 68.5425 | 75.9499 | 86.5638 | 94.2445 | 95.1643 | 95.5762 | -1.4098 | 1.5777 |
| `MALICIOUS` | 53 | 0 | 10.8022 | 8.3298 | 6.5125 | 4.4238 | 4.8357 | 5.7555 | 13.4362 | 24.0501 | 31.4575 | 1.4098 | 1.5777 |

### email_spam
*Type :* `timeseries_pct` | *Lignes :* 53

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `NOT_SPAM` | 53 | 0 | 93.7691 | 94.1223 | 1.6389 | 88.3005 | 90.8196 | 92.96 | 94.8077 | 95.5316 | 96.5917 | -1.2676 | 2.5665 |
| `SPAM` | 53 | 0 | 6.2309 | 5.8777 | 1.6389 | 3.4083 | 4.4684 | 5.1923 | 7.04 | 9.1804 | 11.6995 | 1.2676 | 2.5665 |

### email_spoof
*Type :* `timeseries_pct` | *Lignes :* 53

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `NOT_SPOOF` | 53 | 0 | 82.8458 | 84.8505 | 6.2451 | 61.7568 | 70.1473 | 80.8245 | 86.9506 | 88.5265 | 90.9054 | -1.6276 | 2.6708 |
| `SPOOF` | 53 | 0 | 17.1542 | 15.1495 | 6.2451 | 9.0946 | 11.4735 | 13.0494 | 19.1755 | 29.8527 | 38.2432 | 1.6276 | 2.6708 |

### http_bot_class
*Type :* `geo_pct` | *Lignes :* 13,409

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `human` | 13,144 | 265 | 79.3467 | 84.4706 | 16.3737 | 0.0 | 43.5371 | 77.6608 | 88.6026 | 92.2939 | 100.0 | -2.6027 | 7.4966 |
| `bot` | 13,144 | 265 | 20.4175 | 15.4827 | 15.9436 | 0.0 | 7.6554 | 11.3645 | 22.2337 | 55.8152 | 100.0 | 2.5676 | 7.3857 |

### http_browser_family
*Type :* `geo_pct` | *Lignes :* 13,409

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `chrome` | 13,144 | 265 | 71.511 | 73.4945 | 13.7565 | 0.0 | 49.3824 | 62.5 | 81.1989 | 89.9494 | 100.0 | -1.0145 | 2.7232 |
| `safari` | 13,144 | 265 | 13.778 | 12.4593 | 8.8638 | 0.0 | 2.2504 | 6.9561 | 18.8962 | 29.5847 | 100.0 | 1.0603 | 2.8037 |
| `edge` | 13,144 | 265 | 6.3806 | 5.4334 | 4.2519 | 0.0 | 1.4256 | 3.4608 | 8.325 | 14.0978 | 58.8235 | 1.8779 | 8.1179 |
| `firefox` | 13,144 | 265 | 4.3149 | 2.8295 | 6.6033 | 0.0 | 0.6901 | 1.8169 | 4.9319 | 10.5757 | 100.0 | 8.5349 | 94.3738 |
| `samsung` | 13,144 | 265 | 2.2165 | 2.0104 | 1.4594 | 0.0 | 0.1275 | 1.2405 | 2.9371 | 4.723 | 33.3333 | 2.0696 | 20.5861 |
| `opera` | 13,144 | 265 | 1.3346 | 1.1812 | 1.3978 | 0.0 | 0.0 | 0.7519 | 1.6299 | 2.7684 | 62.5 | 15.6234 | 491.8625 |
| `ucbrowser` | 13,144 | 265 | 0.0998 | 0.0226 | 0.3079 | 0.0 | 0.0 | 0.0057 | 0.0758 | 0.4141 | 6.25 | 9.3095 | 111.1938 |
| `yandex` | 13,144 | 265 | 0.0537 | 0.0028 | 0.863 | 0.0 | 0.0 | 0.0 | 0.0077 | 0.0523 | 50.0 | 34.6502 | 1494.3154 |
| `brave` | 13,144 | 265 | 0.0214 | 0.0008 | 0.0833 | 0.0 | 0.0 | 0.0 | 0.0123 | 0.1005 | 3.7563 | 15.7871 | 457.3802 |
| `coccoc` | 13,144 | 265 | 0.0003 | 0.0 | 0.0024 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0005 | 0.1022 | 23.8761 | 816.5854 |

### http_device_type
*Type :* `geo_pct` | *Lignes :* 13,409

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `desktop` | 13,144 | 265 | 50.8996 | 48.8076 | 14.9549 | 0.0 | 30.431 | 41.9314 | 57.492 | 79.942 | 100.0 | 0.8437 | 1.7159 |
| `mobile` | 13,144 | 265 | 48.8074 | 51.0814 | 14.9384 | 0.0 | 19.3065 | 42.3037 | 57.9616 | 69.3719 | 100.0 | -0.9806 | 1.6171 |
| `other` | 13,144 | 265 | 0.0419 | 0.022 | 0.0971 | 0.0 | 0.0 | 0.0075 | 0.0507 | 0.1381 | 6.6667 | 31.5977 | 1818.0238 |

### http_http_version
*Type :* `geo_pct` | *Lignes :* 13,409

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `HTTP/2` | 13,144 | 265 | 54.1011 | 54.645 | 10.8394 | 0.0 | 37.7858 | 49.4817 | 59.2616 | 68.8321 | 100.0 | -0.6349 | 6.0664 |
| `HTTP/1.x` | 13,144 | 265 | 20.2618 | 16.9194 | 12.4179 | 0.0 | 10.0 | 13.5799 | 21.6886 | 43.8828 | 100.0 | 2.8847 | 11.2553 |
| `HTTP/3` | 13,144 | 265 | 25.4088 | 26.7308 | 8.5812 | 0.0 | 7.946 | 22.14 | 30.551 | 36.8882 | 82.8431 | -0.7326 | 2.2528 |

### http_ip_version
*Type :* `geo_pct` | *Lignes :* 13,409

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `IPv6` | 13,144 | 265 | 19.7764 | 14.6234 | 20.8239 | 0.0 | 0.3873 | 3.8226 | 28.3359 | 57.9724 | 100.0 | 1.7975 | 3.7921 |
| `IPv4` | 13,144 | 265 | 79.9041 | 85.2619 | 21.2803 | 0.0 | 40.7789 | 71.3297 | 96.1091 | 99.5696 | 100.0 | -1.8131 | 3.7609 |

### http_os
*Type :* `geo_pct` | *Lignes :* 13,409

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `WINDOWS` | 13,144 | 265 | 34.9869 | 34.3106 | 14.5668 | 0.0 | 14.1759 | 26.6926 | 40.0554 | 59.5947 | 100.0 | 1.4477 | 4.5795 |
| `ANDROID` | 13,144 | 265 | 40.0754 | 37.8287 | 19.0513 | 0.0 | 12.6076 | 26.3224 | 53.1186 | 75.6782 | 100.0 | 0.3558 | -0.3396 |
| `MACOSX` | 13,144 | 265 | 7.0481 | 5.5905 | 5.6764 | 0.0 | 0.7571 | 3.0332 | 10.1598 | 16.4275 | 100.0 | 2.7494 | 24.8945 |
| `IOS` | 13,144 | 265 | 15.2736 | 14.6634 | 8.4319 | 0.0 | 3.0134 | 8.9384 | 20.5563 | 30.0135 | 100.0 | 0.5587 | 1.2164 |
| `LINUX` | 13,144 | 265 | 1.7049 | 1.3011 | 2.2855 | 0.0 | 0.22 | 0.8681 | 2.01 | 4.0141 | 100.0 | 16.1619 | 475.0994 |
| `CHROMEOS` | 13,144 | 265 | 0.5435 | 0.1873 | 1.2622 | 0.0 | 0.0 | 0.0706 | 0.5084 | 2.1079 | 46.5176 | 10.357 | 222.1437 |
| `SMART_TV` | 13,144 | 265 | 0.0786 | 0.0428 | 0.1607 | 0.0 | 0.0 | 0.0147 | 0.0936 | 0.2594 | 8.3333 | 20.6972 | 792.8686 |

### http_tls_version
*Type :* `geo_pct` | *Lignes :* 13,409

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `TLS 1.3` | 13,144 | 265 | 66.2217 | 65.6537 | 9.5643 | 0.0 | 55.2045 | 61.8075 | 69.6459 | 80.5824 | 100.0 | -0.3591 | 9.8445 |
| `TLS QUIC` | 13,144 | 265 | 26.2475 | 27.6176 | 8.7469 | 0.0 | 8.3808 | 22.8981 | 31.5251 | 37.9015 | 84.0796 | -0.7819 | 2.2931 |
| `TLS 1.2` | 13,144 | 265 | 6.8004 | 5.6457 | 4.7253 | 0.0 | 2.5641 | 4.3355 | 8.1102 | 14.0027 | 77.7778 | 4.099 | 32.0974 |
| `TLS 1.1` | 13,144 | 265 | 0.1655 | 0.0052 | 2.6478 | 0.0 | 0.0 | 0.0013 | 0.0149 | 0.0851 | 96.7742 | 25.4164 | 745.586 |
| `TLS 1.0` | 13,144 | 265 | 0.329 | 0.0126 | 3.5706 | 0.0 | 0.0 | 0.0062 | 0.0289 | 0.2881 | 91.1765 | 16.7915 | 311.5535 |

### iqi_bandwidth
*Type :* `geo_numeric` | *Lignes :* 13,409

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `p25` | 12,162 | 1,247 | 8.6382 | 6.1397 | 11.0815 | 1.0144 | 2.4479 | 3.8222 | 11.1577 | 21.2347 | 948.349 | 51.0139 | 4256.8402 |
| `p50` | 12,162 | 1,247 | 14.5006 | 9.8805 | 15.1897 | 1.3975 | 3.6837 | 6.0328 | 19.241 | 36.8807 | 948.349 | 20.9011 | 1185.8073 |
| `p75` | 12,162 | 1,247 | 25.5772 | 17.0217 | 23.9074 | 1.5359 | 5.4311 | 9.7763 | 36.2833 | 66.4082 | 948.349 | 6.9709 | 198.3945 |

### iqi_dns
*Type :* `geo_numeric` | *Lignes :* 13,409

| Variable | N | Manq. | Moyenne | Médiane | Éc.-type | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `p75` | 12,162 | 1,247 | 145.2871 | 124.3414 | 82.8918 | 1.0 | 49.7619 | 80.7617 | 194.6966 | 298.521 | 816.25 | 1.2694 | 2.6049 |
| `p50` | 12,162 | 1,247 | 93.0939 | 77.4869 | 57.5436 | 1.0 | 30.0344 | 48.7807 | 125.1528 | 198.114 | 734.0 | 1.7049 | 6.5859 |
| `p25` | 12,162 | 1,247 | 61.9364 | 48.4464 | 44.6095 | 1.0 | 18.9748 | 28.6101 | 83.537 | 146.8431 | 678.5 | 2.1651 | 10.7035 |

---
## 9. A8 — Données Nettoyées : Récapitulatif

| Fichier | Lignes brutes | Lignes nettoyées | Colonnes brutes | Nouvelles colonnes | Fichier CSV |
|---|---:|---:|---:|---|---|
| `attacks_l3_bitrate` | 53 | 53 (=) | 7 | — | `cleaned/attacks_l3_bitrate_clean.csv` |
| `attacks_l3_ip_version` | 53 | 53 (=) | 4 | — | `cleaned/attacks_l3_ip_version_clean.csv` |
| `attacks_l3_protocol` | 53 | 53 (=) | 6 | — | `cleaned/attacks_l3_protocol_clean.csv` |
| `attacks_l7_http_method` | 85 | 85 (=) | 24 | — | `cleaned/attacks_l7_http_method_clean.csv` |
| `attacks_l7_http_version` | 85 | 85 (=) | 24 | — | `cleaned/attacks_l7_http_version_clean.csv` |
| `attacks_l7_vertical` | 85 | 85 (=) | 24 | — | `cleaned/attacks_l7_vertical_clean.csv` |
| `bgp_hijacks` | 20,000 | 20,000 (=) | 18 | `peer_asns_count`, `peer_asns_list`, `prefixes_count`, `prefixes_list` +6 | `cleaned/bgp_hijacks_clean.csv` |
| `bgp_leaks` | 20,000 | 19,999 (-1) | 13 | `countries_list`, `countries_count`, `countries_unique`, `leak_seg_list` +1 | `cleaned/bgp_leaks_clean.csv` |
| `bgp_timeseries` | 53 | 53 (=) | 2 | — | `cleaned/bgp_timeseries_clean.csv` |
| `dns_timeseries` | 52 | 52 (=) | 2 | — | `cleaned/dns_timeseries_clean.csv` |
| `email_dmarc` | 53 | 53 (=) | 5 | — | `cleaned/email_dmarc_clean.csv` |
| `email_dkim` | 53 | 53 (=) | 5 | — | `cleaned/email_dkim_clean.csv` |
| `email_spf` | 53 | 53 (=) | 5 | — | `cleaned/email_spf_clean.csv` |
| `email_malicious` | 53 | 53 (=) | 4 | — | `cleaned/email_malicious_clean.csv` |
| `email_spam` | 53 | 53 (=) | 4 | — | `cleaned/email_spam_clean.csv` |
| `email_spoof` | 53 | 53 (=) | 4 | — | `cleaned/email_spoof_clean.csv` |
| `http_bot_class` | 13,409 | 13,409 (=) | 4 | — | `cleaned/http_bot_class_clean.csv` |
| `http_browser_family` | 13,409 | 13,409 (=) | 12 | — | `cleaned/http_browser_family_clean.csv` |
| `http_device_type` | 13,409 | 13,409 (=) | 5 | — | `cleaned/http_device_type_clean.csv` |
| `http_http_version` | 13,409 | 13,409 (=) | 5 | — | `cleaned/http_http_version_clean.csv` |
| `http_ip_version` | 13,409 | 13,409 (=) | 4 | — | `cleaned/http_ip_version_clean.csv` |
| `http_os` | 13,409 | 13,409 (=) | 9 | — | `cleaned/http_os_clean.csv` |
| `http_tls_version` | 13,409 | 13,409 (=) | 7 | — | `cleaned/http_tls_version_clean.csv` |
| `iqi_bandwidth` | 13,409 | 13,409 (=) | 6 | — | `cleaned/iqi_bandwidth_clean.csv` |
| `iqi_dns` | 13,409 | 13,409 (=) | 6 | — | `cleaned/iqi_dns_clean.csv` |

---
## 10. A9 — Récapitulatif des Problèmes et Recommandations

| Fichier | Problème(s) détecté(s) |
|---|---|
| `attacks_l3_protocol` | 2 lignes (3.77%) avec somme % hors [99,101] |
| `attacks_l7_http_method` | 1020 valeurs manquantes (50.0% du total) |
| `attacks_l7_http_version` | 1615 valeurs manquantes (79.17% du total) |
| `attacks_l7_vertical` | 1020 valeurs manquantes (50.0% du total) |
| `bgp_hijacks` | 388 valeurs manquantes (0.11% du total) |
| `bgp_leaks` | 1 doublons (0.005%) |
| `http_bot_class` | 583 valeurs manquantes (1.09% du total) |
| `http_browser_family` | 2703 valeurs manquantes (1.68% du total) |
| `http_device_type` | 848 valeurs manquantes (1.26% du total) |
| `http_http_version` | 848 valeurs manquantes (1.26% du total) |
| `http_ip_version` | 583 valeurs manquantes (1.09% du total) |
| `http_os` | 1908 valeurs manquantes (1.58% du total) |
| `http_tls_version` | 1378 valeurs manquantes (1.47% du total) |
| `iqi_bandwidth` | 3794 valeurs manquantes (4.72% du total) |
| `iqi_dns` | 3794 valeurs manquantes (4.72% du total) |

### Recommandations pour la suite

1. **IQI (bandwidth & DNS)** : les valeurs manquantes sur p25/p50/p75 correspondent aux pays sans données Cloudflare — les exclure des analyses par pays ou les remplacer par `NaN` marqué.
2. **BGP hijacks / leaks** : les colonnes JSON sont désormais parsées dans `cleaned/`. Utiliser `*_count` pour les analyses numériques et `*_list` pour les analyses réseau.
3. **Sommes % légèrement hors [99,101]** : les lignes concernées sont des semaines à trafic très faible ; les conserver mais signaler dans les analyses.
4. **hijacker_country null** : remplacé par `'UNKNOWN'` dans le fichier nettoyé.
5. **Timestamps BGP** : tous convertis en UTC — utiliser `min_hijack_ts` comme référence temporelle principale pour les hijacks.
6. **Colonnes list Python** : exclues des CSV nettoyés pour compatibilité ; rechargées depuis le brut si nécessaire (phases G/K).

---
*Rapport généré automatiquement par `phase_A_preparation.py` le 2026-06-16 12:40:44.*  
*Données nettoyées disponibles dans : `E:\Webscraping\cloudflare_radar_vulnerabilite\scripts\outputs_complet\cleaned`*