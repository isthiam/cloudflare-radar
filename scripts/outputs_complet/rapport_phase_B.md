# Rapport Phase B — Statistiques Descriptives Globales
**Cloudflare Radar Dataset — Juin 2025 / Juin 2026**  
**Chercheur :** Issakha Thiam — Université Clermont Auvergne  
**Généré le :** 2026-06-16 12:47:35  
**Données source :** répertoire `cleaned/` (25 fichiers CSV nettoyés — Phase A)

---
## 1. Résumé Exécutif — Chiffres Clés

### Attaques Réseau
| Indicateur | Valeur |
|---|---|
| Protocole L3 dominant (52 semaines) | **UDP 74.0%** vs TCP 24.9% |
| Part des attaques L3 > 100 Gbps (moy.) | **0.067%** |
| Méthode HTTP L7 dominante (85 jours) | **GET 82.0%** vs POST 14.7% |
| Secteur le plus attaqué (L7) | **Informatique/Électronique** (~22.8%) |

### Sécurité Email
| Indicateur | Valeur |
|---|---|
| DMARC PASS (moy. annuelle) | **87.9%** |
| DKIM PASS (moy. annuelle) | **89.4%** |
| SPF PASS (moy. annuelle) | **79.0%** |
| Taux de spam (moy.) | **6.2%** |
| Taux de spoofing (moy.) | **17.2%** |
| Taux malicieux (moy.) | **10.8%** |

### Infrastructure & Protocoles (253 pays, 52 semaines)
| Indicateur | Valeur |
|---|---|
| Trafic bot global (moy. par pays) | **20.4%** |
| Part IPv6 global (moy. par pays) | **19.8%** |
| Part TLS 1.3 global (moy. par pays) | **66.2%** |
| Part HTTP/2 global (moy. par pays) | **54.1%** |
| Part HTTP/3 global (moy. par pays) | **25.4%** |
| Navigateur dominant : Chrome (moy.) | **71.5%** |
| Navigateur n°2 : Safari (moy.) | **13.8%** |
| Appareil dominant : Mobile (moy.) | **48.8%** vs Desktop 50.9% |
| Bande passante médiane mondiale | **9.9 Mbps** (médiane des médianes pays) |
| Latence DNS médiane mondiale | **77.5 ms** (médiane des médianes pays) |

### Incidents BGP
| Indicateur | Valeur |
|---|---|
| Hijacks analysés | **20,000** |
| Leaks analysés | **19,999** |
| Durée médiane d'un hijack | **6946 secondes** |
| Score de confiance moyen (hijacks) | **6.01/16** |

---
## 2. Attaques Couche 3 (L3)

### 2.1 Distribution de la Taille des Attaques L3 (bitrate)
*52 semaines, granularité hebdomadaire. Valeurs en % du trafic d'attaque.*

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `< 500 Mbps` | 53 | 0 | 57.1248 | 55.5444 | 20.2146 | 35.39 | 1.6455 | 27.3491 | 44.841 | 69.7505 | 95.6114 | 99.9089 | 0.04 | 0.4338 |
| `500 Mbps – 1 Gbps` | 53 | 0 | 13.7409 | 12.52 | 9.9696 | 72.55 | 0.0 | 0.0755 | 7.8776 | 17.6156 | 31.907 | 44.04 | 1.1706 | 1.7364 |
| `1 – 10 Gbps` | 53 | 0 | 24.823 | 21.5383 | 19.4201 | 78.23 | 0.0 | 0.0 | 13.2758 | 33.7218 | 62.4386 | 94.9972 | 1.2796 | 2.541 |
| `10 – 100 Gbps` | 53 | 0 | 4.2441 | 1.2006 | 7.7601 | 182.85 | 0.0 | 0.0 | 0.1645 | 3.3424 | 24.3912 | 33.235 | 2.4053 | 4.9883 |
| `> 100 Gbps` | 53 | 0 | 0.0672 | 0.0159 | 0.1291 | 192.2 | 0.0002 | 0.0015 | 0.0046 | 0.0684 | 0.222 | 0.6694 | 3.5999 | 14.0291 |

**Profil visuel (moyenne annuelle) :**

| Catégorie | Moy. % | Distribution |
|---|---:|---|
| < 500 Mbps | 57.12% | `███████████░░░░░░░░░` |
| 500 Mbps – 1 Gbps | 13.74% | `███░░░░░░░░░░░░░░░░░` |
| 1 – 10 Gbps | 24.82% | `█████░░░░░░░░░░░░░░░` |
| 10 – 100 Gbps | 4.24% | `█░░░░░░░░░░░░░░░░░░░` |
| > 100 Gbps | 0.07% | `░░░░░░░░░░░░░░░░░░░░` |

> **Observation :** 57.1% des attaques L3 sont sous 500 Mbps (volumétrie limitée), mais les méga-attaques (>100 Gbps) représentent en moyenne 0.067% (pic observé : 0.669%). Les attaques 1–10 Gbps constituent la deuxième catégorie (24.8% en moyenne).

### 2.2 Répartition Protocolaire des Attaques L3
*52 semaines, granularité hebdomadaire. Valeurs en %.*

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `UDP` | 53 | 0 | 73.9597 | 75.619 | 13.4107 | 18.13 | 39.1675 | 47.0572 | 64.9348 | 82.914 | 93.6718 | 98.9328 | -0.5173 | 0.0725 |
| `TCP` | 53 | 0 | 24.9206 | 22.4632 | 13.5674 | 54.44 | 1.0225 | 5.2191 | 16.65 | 34.3885 | 52.6471 | 60.7676 | 0.5961 | 0.1054 |
| `GRE` | 53 | 0 | 0.7031 | 0.1719 | 2.9768 | 423.41 | 0.0 | 0.0 | 0.0214 | 0.3331 | 1.5497 | 21.7191 | 7.0305 | 50.4419 |
| `ICMP` | 53 | 0 | 0.1399 | 0.0354 | 0.322 | 230.14 | 0.0015 | 0.005 | 0.0133 | 0.0843 | 0.634 | 1.7992 | 3.9463 | 16.656 |

**Profil visuel (moyenne annuelle) :**

| Protocole | Moy. % | Min % | Max % | Distribution |
|---|---:|---:|---:|---|
| UDP | 73.96% | 39.17% | 98.93% | `███████████████░░░░░` |
| TCP | 24.92% | 1.02% | 60.77% | `█████░░░░░░░░░░░░░░░` |
| GRE | 0.70% | 0.00% | 21.72% | `░░░░░░░░░░░░░░░░░░░░` |
| ICMP | 0.14% | 0.00% | 1.80% | `░░░░░░░░░░░░░░░░░░░░` |

> **Observation :** UDP domine massivement à 74.0% (CV=18.1%), caractéristique des attaques volumétriques par réflexion/amplification. TCP représente 24.9% avec une variabilité notable (CV=54.4%). GRE (0.70%) et ICMP (0.14%) restent marginaux.

### 2.3 Version IP dans les Attaques L3

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `IPv4` | 53 | 0 | 99.729 | 99.7863 | 0.2796 | 0.28 | 98.4389 | 99.3238 | 99.6792 | 99.9031 | 99.9699 | 99.9869 | -2.8554 | 10.2228 |
| `IPv6` | 53 | 0 | 0.271 | 0.2137 | 0.2796 | 103.19 | 0.0131 | 0.0301 | 0.0969 | 0.3208 | 0.6762 | 1.5611 | 2.8554 | 10.2228 |

> **Observation :** IPv4 représente 99.73% du vecteur d'attaque L3. IPv6 (moy. 0.27%) est très peu utilisé comme vecteur d'attaque, alors qu'il représente 19.8% du trafic légitime par pays — les attaquants restent principalement sur IPv4.

---
## 3. Attaques Couche 7 (L7)

### 3.1 Méthodes HTTP d'Attaque L7
*85 jours (granularité quotidienne). Valeurs en %.*

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `GET` | 85 | 0 | 81.9889 | 81.6518 | 2.7143 | 3.31 | 76.6025 | 77.4507 | 80.3164 | 83.947 | 86.1011 | 88.5041 | 0.1612 | -0.4375 |
| `POST` | 85 | 0 | 14.6876 | 14.6523 | 2.8862 | 19.65 | 8.1202 | 10.7118 | 12.5711 | 16.7149 | 19.9912 | 20.4521 | 0.1572 | -0.5853 |
| `HEAD` | 85 | 0 | 2.4032 | 2.4256 | 0.6498 | 27.04 | 1.053 | 1.4564 | 1.932 | 2.8 | 3.4722 | 4.0492 | 0.1658 | -0.4032 |
| `OPTIONS` | 85 | 0 | 0.506 | 0.482 | 0.1523 | 30.1 | 0.2811 | 0.3302 | 0.414 | 0.5479 | 0.7099 | 1.3697 | 2.5533 | 11.8019 |
| `PATCH` | 85 | 0 | 0.1601 | 0.1584 | 0.0326 | 20.35 | 0.086 | 0.1132 | 0.1357 | 0.1845 | 0.2139 | 0.241 | 0.3041 | -0.1903 |
| `DELETE` | 85 | 0 | 0.1185 | 0.1193 | 0.0217 | 18.3 | 0.0779 | 0.0846 | 0.1028 | 0.1325 | 0.1549 | 0.1854 | 0.4675 | 0.2684 |
| `PUT` | 85 | 0 | 0.1099 | 0.1089 | 0.0199 | 18.09 | 0.0658 | 0.0783 | 0.096 | 0.1245 | 0.1401 | 0.1679 | 0.1859 | 0.0583 |
| `UNKNOWN` | 85 | 0 | 0.0252 | 0.0073 | 0.1324 | 524.4 | 0.0026 | 0.004 | 0.0052 | 0.0106 | 0.0336 | 1.2265 | 9.1128 | 83.6425 |
| `ACL` | 85 | 0 | 0.0004 | 0.0002 | 0.0004 | 105.72 | 0.0 | 0.0001 | 0.0001 | 0.0004 | 0.0011 | 0.002 | 2.631 | 7.6117 |

**Profil visuel (moyenne sur 85 jours) :**

| Méthode | Moy. % | Distribution |
|---|---:|---|
| GET | 81.989% | `████████████████░░░░` |
| POST | 14.688% | `███░░░░░░░░░░░░░░░░░` |
| HEAD | 2.403% | `░░░░░░░░░░░░░░░░░░░░` |
| OPTIONS | 0.506% | `░░░░░░░░░░░░░░░░░░░░` |
| PATCH | 0.160% | `░░░░░░░░░░░░░░░░░░░░` |
| DELETE | 0.118% | `░░░░░░░░░░░░░░░░░░░░` |
| PUT | 0.110% | `░░░░░░░░░░░░░░░░░░░░` |
| UNKNOWN | 0.025% | `░░░░░░░░░░░░░░░░░░░░` |
| ACL | 0.000% | `░░░░░░░░░░░░░░░░░░░░` |

> **Observation :** GET représente 82.0% des requêtes DDoS L7 (CV=3.3%), POST 14.7%. HEAD (2.40%) peut indiquer de la reconnaissance préalable. Les méthodes destructives (PUT, DELETE, PATCH) représentent ensemble 0.388% — essentiellement négligeable.

### 3.2 Versions HTTP dans les Attaques L7

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `HTTP/2` | 85 | 0 | 52.9446 | 53.2754 | 5.6785 | 10.73 | 43.0143 | 44.6937 | 47.464 | 58.5336 | 60.4862 | 61.6911 | -0.1181 | -1.4042 |
| `HTTP/1.x` | 85 | 0 | 41.0167 | 40.0631 | 5.5426 | 13.51 | 31.8855 | 33.9772 | 36.0208 | 46.1325 | 49.2662 | 51.6479 | 0.217 | -1.3339 |
| `HTTP/3` | 85 | 0 | 6.0388 | 5.9724 | 0.7702 | 12.75 | 4.3477 | 4.7837 | 5.5154 | 6.4489 | 7.2905 | 7.9878 | 0.2085 | -0.0892 |

**Comparaison attaques L7 vs trafic légitime (HTTP par pays) :**

| Version HTTP | Attaques L7 (moy.) | Trafic légitime (moy. mondial) | Écart |
|---|---:|---:|---:|
| HTTP/2 | 52.94% | 54.1% | -1.16% |
| HTTP/1.x | 41.02% | N/D | — |
| HTTP/3 | 6.04% | 25.4% | -19.36% |

### 3.3 Secteurs d'Activité Ciblés par les Attaques L7
*85 jours. Répartition quotidienne des attaques par verticale.*

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `Computer and Electronics` | 85 | 0 | 22.7621 | 22.6833 | 2.5832 | 11.35 | 18.1388 | 19.3514 | 20.7142 | 23.8847 | 27.2181 | 33.0439 | 0.9677 | 2.0194 |
| `Internet and Telecom` | 85 | 0 | 22.4454 | 21.395 | 3.9536 | 17.61 | 14.8463 | 16.6577 | 19.5295 | 24.6481 | 29.509 | 30.4759 | 0.3808 | -0.7406 |
| `other` | 85 | 0 | 9.5435 | 8.6947 | 2.7453 | 28.77 | 6.1115 | 6.6813 | 7.999 | 10.118 | 15.1956 | 20.4542 | 1.8596 | 4.0775 |
| `Shopping & General Merchandise` | 85 | 0 | 11.5114 | 10.9018 | 2.0082 | 17.45 | 8.6245 | 9.3312 | 10.1465 | 12.1214 | 15.2562 | 19.2385 | 1.5139 | 2.5143 |
| `Finance` | 85 | 0 | 8.8809 | 7.6385 | 2.7257 | 30.69 | 5.9526 | 6.1792 | 6.7893 | 10.3753 | 14.1243 | 15.9016 | 1.0194 | -0.1265 |
| `Gambling` | 85 | 0 | 8.5914 | 7.9879 | 2.9676 | 34.54 | 2.8187 | 4.4989 | 6.7296 | 10.5499 | 14.1959 | 18.1274 | 0.6623 | 0.3082 |
| `News, Media, and Publications` | 85 | 0 | 6.1976 | 6.197 | 1.5735 | 25.39 | 2.9764 | 3.8173 | 5.342 | 6.8754 | 8.3545 | 12.2849 | 0.9607 | 2.6087 |
| `Business and Industry` | 85 | 0 | 2.776 | 2.5032 | 0.7536 | 27.15 | 1.9325 | 2.0476 | 2.2484 | 2.9752 | 4.2097 | 5.9468 | 1.66 | 3.1457 |
| `Professional Services` | 85 | 0 | 4.217 | 3.6897 | 1.8477 | 43.81 | 2.4426 | 2.7253 | 3.2686 | 4.4681 | 6.6617 | 14.7871 | 3.7505 | 17.9867 |
| `Art, Entertainment & Recreation` | 85 | 0 | 3.0745 | 3.7107 | 1.4441 | 46.97 | 0.3008 | 0.4506 | 1.8889 | 4.0468 | 4.5125 | 6.4364 | -0.6571 | -0.677 |

**Ranking des secteurs (% moyen d'attaques reçues) :**

| Rang | Secteur | Moy. % | Min % | Max % | Distribution |
|---:|---|---:|---:|---:|---|
| 1 | Computer and Electronics | 22.76% | 18.14% | 33.04% | `███████████████░░░░░` |
| 2 | Internet and Telecom | 22.45% | 14.85% | 30.48% | `███████████████░░░░░` |
| 3 | Shopping & General Merchandise | 11.51% | 8.62% | 19.24% | `████████░░░░░░░░░░░░` |
| 4 | other | 9.54% | 6.11% | 20.45% | `██████░░░░░░░░░░░░░░` |
| 5 | Finance | 8.88% | 5.95% | 15.90% | `██████░░░░░░░░░░░░░░` |
| 6 | Gambling | 8.59% | 2.82% | 18.13% | `██████░░░░░░░░░░░░░░` |
| 7 | News, Media, and Publications | 6.20% | 2.98% | 12.28% | `████░░░░░░░░░░░░░░░░` |
| 8 | Professional Services | 4.22% | 2.44% | 14.79% | `███░░░░░░░░░░░░░░░░░` |
| 9 | Art, Entertainment & Recreation | 3.07% | 0.30% | 6.44% | `██░░░░░░░░░░░░░░░░░░` |
| 10 | Business and Industry | 2.78% | 1.93% | 5.95% | `██░░░░░░░░░░░░░░░░░░` |

---
## 4. Sécurité Email

### 4.1 DMARC (Domain-based Message Authentication)
*53 semaines. Valeurs en %.*

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `DMARC PASS` | 53 | 0 | 87.916 | 88.0665 | 1.9768 | 2.25 | 79.2246 | 85.5061 | 87.1517 | 88.9601 | 90.8786 | 91.7055 | -1.5935 | 6.3287 |
| `DMARC NONE` | 53 | 0 | 6.7779 | 6.656 | 1.4449 | 21.32 | 4.6231 | 4.8745 | 5.737 | 7.8367 | 9.4396 | 10.8663 | 0.7318 | 0.067 |
| `DMARC FAIL` | 53 | 0 | 5.3061 | 4.6533 | 2.0876 | 39.34 | 2.8679 | 3.3304 | 4.0588 | 6.1745 | 8.408 | 14.9781 | 2.3078 | 7.9045 |

### 4.2 DKIM (DomainKeys Identified Mail)

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `DKIM PASS` | 53 | 0 | 89.4109 | 89.3933 | 1.8144 | 2.03 | 84.1244 | 86.2753 | 88.4224 | 90.2538 | 92.8691 | 93.1691 | -0.1264 | 0.8813 |
| `DKIM NONE` | 53 | 0 | 8.8915 | 8.9481 | 1.8278 | 20.56 | 5.5022 | 5.7589 | 7.7045 | 9.8578 | 11.7481 | 14.092 | 0.246 | 0.2391 |
| `DKIM FAIL` | 53 | 0 | 1.6976 | 1.4364 | 0.576 | 33.93 | 0.9343 | 1.134 | 1.3187 | 2.0658 | 2.6261 | 3.9222 | 1.5117 | 2.9003 |

### 4.3 SPF (Sender Policy Framework)

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `SPF PASS` | 53 | 0 | 79.0015 | 79.172 | 2.2305 | 2.82 | 74.2084 | 75.0077 | 77.5464 | 80.6859 | 82.0307 | 82.4171 | -0.3401 | -0.7122 |
| `SPF NONE` | 53 | 0 | 4.7298 | 4.2956 | 1.4806 | 31.3 | 2.722 | 3.1898 | 3.7322 | 5.2137 | 7.4645 | 9.8207 | 1.5738 | 2.6323 |
| `SPF FAIL` | 53 | 0 | 16.2687 | 15.7622 | 2.1738 | 13.36 | 12.9528 | 13.8235 | 14.7676 | 16.8644 | 20.6433 | 22.4926 | 1.1577 | 0.803 |

### 4.4 Tableau Comparatif DMARC / DKIM / SPF

| Protocole | PASS moy. | PASS min | PASS max | FAIL moy. | FAIL max | NONE moy. |
|---|---:|---:|---:|---:|---:|---:|
| **DMARC** | **87.92%** | 79.22% | 91.71% | 5.31% | 14.98% | 6.78% |
| **DKIM** | **89.41%** | 84.12% | 93.17% | 1.7% | 3.92% | 8.89% |
| **SPF** | **79.0%** | 74.21% | 82.42% | 16.27% | 22.49% | 4.73% |

### 4.5 Spam, Spoofing et Courrier Malicieux

| Indicateur | N° positif (moy.) | N° positif (min) | N° positif (max) | Éc.-type | CV% |
|---|---:|---:|---:|---:|---:|
| **Spam** | 6.23% | 3.41% | 11.70% | 1.639 | 26.3% |
| **Spoofing** | 17.15% | 9.09% | 38.24% | 6.245 | 36.4% |
| **Malicieux** | 10.80% | 4.42% | 31.46% | 6.512 | 60.3% |

### 4.6 Matrice de Corrélation (Spearman) entre Indicateurs Email

| | `DMARC_FAIL` | `DKIM_FAIL` | `SPF_FAIL` | `SPAM` | `SPOOF` | `MALICIEUX` |
|---| ---:| ---:| ---:| ---:| ---:| ---:|
| `DMARC_FAIL` | 1.0 | 0.203 | 0.556 | 0.154 | 0.012 | -0.134 |
| `DKIM_FAIL` | 0.203 | 1.0 | -0.107 | -0.219 | 0.462 | 0.402 |
| `SPF_FAIL` | 0.556 | -0.107 | 1.0 | 0.54 | -0.505 | -0.641 |
| `SPAM` | 0.154 | -0.219 | 0.54 | 1.0 | -0.232 | -0.471 |
| `SPOOF` | 0.012 | 0.462 | -0.505 | -0.232 | 1.0 | 0.92 |
| `MALICIEUX` | -0.134 | 0.402 | -0.641 | -0.471 | 0.92 | 1.0 |

> **Lecture :** valeurs proches de 1 = corrélation positive forte, -1 = corrélation inverse forte.

---
## 5. BGP (Border Gateway Protocol)

### 5.1 BGP Timeseries — Volume Hebdomadaire de Routes

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `Volume BGP (routes)` | 53 | 0 | 11970274698.4528 | 11309324528.0 | 2874387120.9611 | 24.01 | 6139854290.0 | 9134853148.0 | 10489344275.0 | 12833324067.0 | 16900338177.4 | 25499721429.0 | 2.2729 | 8.8885 |

> **Couverture :** 2025-06-09 → 2026-06-08 (53 semaines)  
> **Volume :** moyenne 11,970,274,698 | min 6,139,854,290 | max 25,499,721,429  
> **Tendance :** variation semaine 1 → semaine 53 : **-33.3%**

### 5.2 BGP Hijacks — Statistiques Descriptives (20 000 événements)

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `duration` | 20,000 | 0 | 58974.5822 | 6945.5 | 151309.555 | 256.57 | 0.0 | 0.0 | 260.0 | 81384.5 | 235858.8 | 9121558.0 | 20.9555 | 889.9149 |
| `hijack_msgs_count` | 20,000 | 0 | 120.7662 | 5.0 | 6221.1822 | 5151.42 | 1.0 | 1.0 | 2.0 | 21.0 | 146.0 | 835526.0 | 123.9303 | 16358.3143 |
| `peer_ip_count` | 20,000 | 0 | 8.1472 | 2.0 | 13.6835 | 167.95 | 1.0 | 1.0 | 1.0 | 8.0 | 50.0 | 116.0 | 2.5718 | 6.3697 |
| `on_going_count` | 20,000 | 0 | 15.8558 | 1.0 | 160.8793 | 1014.64 | 0.0 | 0.0 | 0.0 | 3.0 | 51.0 | 14747.0 | 49.8136 | 3804.8971 |
| `confidence_score` | 20,000 | 0 | 6.0067 | 4.0 | 3.5216 | 58.63 | 1.0 | 2.0 | 4.0 | 8.0 | 12.0 | 12.0 | 0.486 | -1.1504 |
| `peer_asns_count` | 20,000 | 0 | 7.1178 | 2.0 | 11.768 | 165.33 | 1.0 | 1.0 | 1.0 | 7.0 | 44.0 | 60.0 | 2.4784 | 5.2768 |
| `prefixes_count` | 20,000 | 0 | 3.795 | 1.0 | 107.4398 | 2831.09 | 1.0 | 1.0 | 1.0 | 2.0 | 10.0 | 15129.0 | 139.5419 | 19642.7432 |
| `victim_asns_count` | 20,000 | 0 | 1.2874 | 1.0 | 11.4142 | 886.58 | 1.0 | 1.0 | 1.0 | 1.0 | 2.0 | 1611.0 | 140.2683 | 19781.6005 |
| `victim_countries_count` | 20,000 | 0 | 1.1092 | 1.0 | 1.0849 | 97.82 | 1.0 | 1.0 | 1.0 | 1.0 | 2.0 | 138.0 | 101.386 | 12680.882 |
| `tags_total_score` | 20,000 | 0 | 5.7356 | 4.0 | 3.4281 | 59.77 | -4.0 | 2.0 | 2.0 | 8.0 | 12.0 | 12.0 | 0.5456 | -0.9889 |
| `tags_count` | 20,000 | 0 | 4.4432 | 4.0 | 1.0205 | 22.97 | 4.0 | 4.0 | 4.0 | 4.0 | 7.0 | 12.0 | 2.94 | 9.5256 |

**Distribution de la durée des hijacks :**

| Catégorie | Nombre | % | Barre |
|---|---:|---:|---|
| Instantané (0s) | 2,263 | 11.31% | `██░░░░░░░░░░░░░` |
| < 1 min | 1,513 | 7.57% | `█░░░░░░░░░░░░░░` |
| 1 min – 1h | 5,387 | 26.93% | `████░░░░░░░░░░░` |
| 1h – 24h | 6,114 | 30.57% | `█████░░░░░░░░░░` |
| > 24h | 4,723 | 23.61% | `████░░░░░░░░░░░` |

**Distribution du score de confiance (0 = incertain, 16+ = très confiant) :**

| Niveau | Nombre | % |
|---|---:|---:|
| Faible (0–3) | 4,519 | 22.59% |
| Modérée (4–7) | 7,277 | 36.38% |
| Élevée (8+) | 8,204 | 41.02% |

**Top 15 pays d'origine des hijacks :**

| Rang | Pays | Nombre | % |
|---:|---|---:|---:|
| 1 | US | 4,698 | 23.49% |
| 2 | CN | 1,993 | 9.96% |
| 3 | RU | 1,072 | 5.36% |
| 4 | BR | 1,029 | 5.14% |
| 5 | IN | 1,016 | 5.08% |
| 6 | GB | 772 | 3.86% |
| 7 | HK | 711 | 3.56% |
| 8 | ID | 657 | 3.29% |
| 9 | DE | 436 | 2.18% |
| 10 | UNKNOWN | 388 | 1.94% |
| 11 | NL | 364 | 1.82% |
| 12 | PL | 302 | 1.51% |
| 13 | TR | 284 | 1.42% |
| 14 | AU | 245 | 1.23% |
| 15 | FR | 225 | 1.12% |

### 5.3 BGP Leaks — Statistiques Descriptives (19 999 événements)

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `leak_count` | 19,999 | 0 | 15946.9849 | 62.0 | 437783.7199 | 2745.24 | 1.0 | 2.0 | 12.0 | 315.0 | 4714.0 | 22897341.0 | 41.7079 | 1874.0643 |
| `peer_count` | 19,999 | 0 | 27.233 | 11.0 | 33.1272 | 121.64 | 1.0 | 1.0 | 3.0 | 41.0 | 102.0 | 233.0 | 1.5738 | 2.1999 |
| `prefix_count` | 19,999 | 0 | 50.4916 | 2.0 | 1798.0215 | 3561.03 | 1.0 | 1.0 | 1.0 | 4.0 | 32.0 | 247324.0 | 130.3727 | 17892.0248 |
| `origin_count` | 19,999 | 0 | 8.8776 | 1.0 | 138.8844 | 1564.44 | 1.0 | 1.0 | 1.0 | 2.0 | 7.0 | 16933.0 | 92.5949 | 11047.1839 |
| `leak_seg_len` | 19,999 | 0 | 3.0 | 3.0 | 0.0 | 0.0 | 3.0 | 3.0 | 3.0 | 3.0 | 3.0 | 3.0 | 0.0 | 0.0 |
| `countries_count` | 19,999 | 0 | 2.9912 | 3.0 | 0.0931 | 3.11 | 2.0 | 3.0 | 3.0 | 3.0 | 3.0 | 3.0 | -10.5501 | 109.3165 |

**Statut des événements de leak :**

| Statut | Nombre | % |
|---|---:|---:|
| Terminé | 19,417 | 97.09% |
| En cours | 582 | 2.91% |

**Types de leak :**

| Type | Nombre | % |
|---|---:|---:|
| 1 | 19,999 | 100.0% |

**Top 15 ASNs à l'origine des leaks :**

| Rang | ASN | Nombre de leaks |
|---:|---|---:|
| 1 | AS199310 | 252 |
| 2 | AS30990 | 233 |
| 3 | AS268624 | 151 |
| 4 | AS25145 | 148 |
| 5 | AS7473 | 139 |
| 6 | AS136897 | 138 |
| 7 | AS4761 | 126 |
| 8 | AS37440 | 108 |
| 9 | AS4775 | 107 |
| 10 | AS18001 | 102 |
| 11 | AS9927 | 94 |
| 12 | AS28663 | 94 |
| 13 | AS205941 | 93 |
| 14 | AS24812 | 93 |
| 15 | AS37133 | 90 |

---
## 6. DNS Timeseries

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `Métrique DNS` | 52 | 0 | 0.7587 | 0.7452 | 0.1186 | 15.63 | 0.5809 | 0.6126 | 0.6479 | 0.8365 | 0.9535 | 1.0 | 0.3778 | -0.9633 |

> **Couverture :** 2025-06-09 → 2026-06-01 (52 semaines)  
> **Plage :** 0.5809 – 1.0000 (ratio normalisé 0-1)  
> **Tendance :** variation S1 → S52 : **+71.97%**  
> **Interprétation :** métrique Cloudflare normalisée — valeur proche de 1 = qualité/volume optimal.

---
## 7. Métriques HTTP par Pays (253 pays × 53 semaines)

> **Note :** les statistiques ci-dessous portent sur l'ensemble des observations pays×semaine (~13 000 lignes par fichier, données 252 pays distincts).

### 7.1 Trafic Bot vs Humain

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `Trafic humain` | 13,144 | 265 | 79.3467 | 84.4706 | 16.3737 | 20.64 | 0.0 | 43.5371 | 77.6608 | 88.6026 | 92.2939 | 100.0 | -2.6027 | 7.4966 |
| `Trafic bot` | 13,144 | 265 | 20.4175 | 15.4827 | 15.9436 | 78.09 | 0.0 | 7.6554 | 11.3645 | 22.2337 | 55.8152 | 100.0 | 2.5676 | 7.3857 |

> **Observation :** le trafic bot varie de 0.0% à 100.0% selon les pays et semaines (CV = 78.1%). La distribution est fortement asymétrique (skew = 2.57) : la plupart des pays ont peu de bots mais quelques-uns ont des pics élevés.

### 7.2 Parts de Marché des Navigateurs

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `Chrome` | 13,144 | 265 | 71.511 | 73.4945 | 13.7565 | 19.24 | 0.0 | 49.3824 | 62.5 | 81.1989 | 89.9494 | 100.0 | -1.0145 | 2.7232 |
| `Safari` | 13,144 | 265 | 13.778 | 12.4593 | 8.8638 | 64.33 | 0.0 | 2.2504 | 6.9561 | 18.8962 | 29.5847 | 100.0 | 1.0603 | 2.8037 |
| `Edge` | 13,144 | 265 | 6.3806 | 5.4334 | 4.2519 | 66.64 | 0.0 | 1.4256 | 3.4608 | 8.325 | 14.0978 | 58.8235 | 1.8779 | 8.1179 |
| `Firefox` | 13,144 | 265 | 4.3149 | 2.8295 | 6.6033 | 153.04 | 0.0 | 0.6901 | 1.8169 | 4.9319 | 10.5757 | 100.0 | 8.5349 | 94.3738 |
| `Samsung` | 13,144 | 265 | 2.2165 | 2.0104 | 1.4594 | 65.84 | 0.0 | 0.1275 | 1.2405 | 2.9371 | 4.723 | 33.3333 | 2.0696 | 20.5861 |
| `Opera` | 13,144 | 265 | 1.3346 | 1.1812 | 1.3978 | 104.74 | 0.0 | 0.0 | 0.7519 | 1.6299 | 2.7684 | 62.5 | 15.6234 | 491.8625 |
| `Ucbrowser` | 13,144 | 265 | 0.0998 | 0.0226 | 0.3079 | 308.44 | 0.0 | 0.0 | 0.0057 | 0.0758 | 0.4141 | 6.25 | 9.3095 | 111.1938 |
| `Yandex` | 13,144 | 265 | 0.0537 | 0.0028 | 0.863 | 1606.26 | 0.0 | 0.0 | 0.0 | 0.0077 | 0.0523 | 50.0 | 34.6502 | 1494.3154 |
| `Brave` | 13,144 | 265 | 0.0214 | 0.0008 | 0.0833 | 389.93 | 0.0 | 0.0 | 0.0 | 0.0123 | 0.1005 | 3.7563 | 15.7871 | 457.3802 |
| `Coccoc` | 13,144 | 265 | 0.0003 | 0.0 | 0.0024 | 874.81 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0005 | 0.1022 | 23.8761 | 816.5854 |

**Ranking (moyenne mondiale, toutes observations) :**

| Rang | Navigateur | Moy. % | Médiane % | Barre |
|---:|---|---:|---:|---|
| 1 | Chrome | 71.51% | 73.49% | `██████████████░░░░░░` |
| 2 | Safari | 13.78% | 12.46% | `███░░░░░░░░░░░░░░░░░` |
| 3 | Edge | 6.38% | 5.43% | `█░░░░░░░░░░░░░░░░░░░` |
| 4 | Firefox | 4.31% | 2.83% | `█░░░░░░░░░░░░░░░░░░░` |
| 5 | Samsung | 2.22% | 2.01% | `░░░░░░░░░░░░░░░░░░░░` |
| 6 | Opera | 1.33% | 1.18% | `░░░░░░░░░░░░░░░░░░░░` |
| 7 | Ucbrowser | 0.10% | 0.02% | `░░░░░░░░░░░░░░░░░░░░` |
| 8 | Yandex | 0.05% | 0.00% | `░░░░░░░░░░░░░░░░░░░░` |
| 9 | Brave | 0.02% | 0.00% | `░░░░░░░░░░░░░░░░░░░░` |
| 10 | Coccoc | 0.00% | 0.00% | `░░░░░░░░░░░░░░░░░░░░` |

### 7.3 Systèmes d'Exploitation

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `WINDOWS` | 13,144 | 265 | 34.9869 | 34.3106 | 14.5668 | 41.63 | 0.0 | 14.1759 | 26.6926 | 40.0554 | 59.5947 | 100.0 | 1.4477 | 4.5795 |
| `ANDROID` | 13,144 | 265 | 40.0754 | 37.8287 | 19.0513 | 47.54 | 0.0 | 12.6076 | 26.3224 | 53.1186 | 75.6782 | 100.0 | 0.3558 | -0.3396 |
| `MACOSX` | 13,144 | 265 | 7.0481 | 5.5905 | 5.6764 | 80.54 | 0.0 | 0.7571 | 3.0332 | 10.1598 | 16.4275 | 100.0 | 2.7494 | 24.8945 |
| `IOS` | 13,144 | 265 | 15.2736 | 14.6634 | 8.4319 | 55.21 | 0.0 | 3.0134 | 8.9384 | 20.5563 | 30.0135 | 100.0 | 0.5587 | 1.2164 |
| `LINUX` | 13,144 | 265 | 1.7049 | 1.3011 | 2.2855 | 134.06 | 0.0 | 0.22 | 0.8681 | 2.01 | 4.0141 | 100.0 | 16.1619 | 475.0994 |
| `CHROMEOS` | 13,144 | 265 | 0.5435 | 0.1873 | 1.2622 | 232.25 | 0.0 | 0.0 | 0.0706 | 0.5084 | 2.1079 | 46.5176 | 10.357 | 222.1437 |
| `SMART_TV` | 13,144 | 265 | 0.0786 | 0.0428 | 0.1607 | 204.48 | 0.0 | 0.0 | 0.0147 | 0.0936 | 0.2594 | 8.3333 | 20.6972 | 792.8686 |

**Ranking (moyenne mondiale) :**

| Rang | OS | Moy. % | Médiane % | Barre |
|---:|---|---:|---:|---|
| 1 | ANDROID | 40.08% | 37.83% | `████████░░░░░░░░░░░░` |
| 2 | WINDOWS | 34.99% | 34.31% | `███████░░░░░░░░░░░░░` |
| 3 | IOS | 15.27% | 14.66% | `███░░░░░░░░░░░░░░░░░` |
| 4 | MACOSX | 7.05% | 5.59% | `█░░░░░░░░░░░░░░░░░░░` |
| 5 | LINUX | 1.70% | 1.30% | `░░░░░░░░░░░░░░░░░░░░` |
| 6 | CHROMEOS | 0.54% | 0.19% | `░░░░░░░░░░░░░░░░░░░░` |
| 7 | SMART_TV | 0.08% | 0.04% | `░░░░░░░░░░░░░░░░░░░░` |

### 7.4 Types d'Appareils

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `Desktop` | 13,144 | 265 | 50.8996 | 48.8076 | 14.9549 | 29.38 | 0.0 | 30.431 | 41.9314 | 57.492 | 79.942 | 100.0 | 0.8437 | 1.7159 |
| `Mobile` | 13,144 | 265 | 48.8074 | 51.0814 | 14.9384 | 30.61 | 0.0 | 19.3065 | 42.3037 | 57.9616 | 69.3719 | 100.0 | -0.9806 | 1.6171 |
| `Other` | 13,144 | 265 | 0.0419 | 0.022 | 0.0971 | 231.78 | 0.0 | 0.0 | 0.0075 | 0.0507 | 0.1381 | 6.6667 | 31.5977 | 1818.0238 |

> **Observation :** mobile représente 48.8% du trafic mondial en moyenne (95.9% du niveau desktop). La variabilité est très élevée selon les pays (CV mobile = 30.6%).

### 7.5 Adoption IPv6 par Pays

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `IPv6` | 13,144 | 265 | 19.7764 | 14.6234 | 20.8239 | 105.3 | 0.0 | 0.3873 | 3.8226 | 28.3359 | 57.9724 | 100.0 | 1.7975 | 3.7921 |
| `IPv4` | 13,144 | 265 | 79.9041 | 85.2619 | 21.2803 | 26.63 | 0.0 | 40.7789 | 71.3297 | 96.1091 | 99.5696 | 100.0 | -1.8131 | 3.7609 |

**Top 20 pays avec le plus fort taux d'adoption IPv6 :**

| Rang | Pays | Taux IPv6 moy. % |
|---:|---|---:|
| 1 | CX | 98.11% |
| 2 | TF | 98.00% |
| 3 | UM | 93.63% |
| 4 | GS | 81.55% |
| 5 | PN | 80.41% |
| 6 | CC | 78.57% |
| 7 | KP | 73.34% |
| 8 | EH | 69.36% |
| 9 | IN | 64.85% |
| 10 | TV | 61.54% |
| 11 | BL | 58.41% |
| 12 | ER | 57.28% |
| 13 | SA | 56.85% |
| 14 | MY | 56.43% |
| 15 | UY | 52.34% |
| 16 | NR | 52.06% |
| 17 | NP | 51.23% |
| 18 | FR | 49.87% |
| 19 | KI | 49.01% |
| 20 | GR | 47.28% |

**Bottom 10 pays avec le plus faible taux d'adoption IPv6 :**

| Rang | Pays | Taux IPv6 moy. % |
|---:|---|---:|
| 1 | DZ | 0.49% |
| 2 | SY | 0.45% |
| 3 | ET | 0.44% |
| 4 | GM | 0.44% |
| 5 | AZ | 0.38% |
| 6 | TJ | 0.33% |
| 7 | GQ | 0.32% |
| 8 | GI | 0.17% |
| 9 | CU | 0.13% |
| 10 | TM | 0.02% |

### 7.6 Versions TLS

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `TLS 1.3` | 13,144 | 265 | 66.2217 | 65.6537 | 9.5643 | 14.44 | 0.0 | 55.2045 | 61.8075 | 69.6459 | 80.5824 | 100.0 | -0.3591 | 9.8445 |
| `TLS QUIC` | 13,144 | 265 | 26.2475 | 27.6176 | 8.7469 | 33.32 | 0.0 | 8.3808 | 22.8981 | 31.5251 | 37.9015 | 84.0796 | -0.7819 | 2.2931 |
| `TLS 1.2` | 13,144 | 265 | 6.8004 | 5.6457 | 4.7253 | 69.49 | 0.0 | 2.5641 | 4.3355 | 8.1102 | 14.0027 | 77.7778 | 4.099 | 32.0974 |
| `TLS 1.1` | 13,144 | 265 | 0.1655 | 0.0052 | 2.6478 | 1599.51 | 0.0 | 0.0 | 0.0013 | 0.0149 | 0.0851 | 96.7742 | 25.4164 | 745.586 |
| `TLS 1.0` | 13,144 | 265 | 0.329 | 0.0126 | 3.5706 | 1085.26 | 0.0 | 0.0 | 0.0062 | 0.0289 | 0.2881 | 91.1765 | 16.7915 | 311.5535 |

> **Protocoles obsolètes :** 29 pays présentent un taux TLS 1.0 > 5% sur au moins une semaine. 13 pays présentent un taux TLS 1.1 > 5%. TLS 1.3 (moy. 66.2%) et QUIC (moy. 26.2%) dominent.

### 7.7 Versions HTTP

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `HTTP/2` | 13,144 | 265 | 54.1011 | 54.645 | 10.8394 | 20.04 | 0.0 | 37.7858 | 49.4817 | 59.2616 | 68.8321 | 100.0 | -0.6349 | 6.0664 |
| `HTTP/1.x` | 13,144 | 265 | 20.2618 | 16.9194 | 12.4179 | 61.29 | 0.0 | 10.0 | 13.5799 | 21.6886 | 43.8828 | 100.0 | 2.8847 | 11.2553 |
| `HTTP/3` | 13,144 | 265 | 25.4088 | 26.7308 | 8.5812 | 33.77 | 0.0 | 7.946 | 22.14 | 30.551 | 36.8882 | 82.8431 | -0.7326 | 2.2528 |

> **Observation :** HTTP/2 domine (54.1% moy.), HTTP/3 est déjà à 25.4% moy. HTTP/1.x reste à 20.3% moy. mais avec une très forte variabilité (CV = 61.3%) — certains pays ou semaines dépendent encore massivement du protocole legacy.

---
## 8. Qualité Internet — IQI (253 pays × 53 semaines)

### 8.1 Bande Passante (IQI Bandwidth, Mbps)

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `BW p25` | 12,162 | 1,247 | 8.6382 | 6.1397 | 11.0815 | 128.28 | 1.0144 | 2.4479 | 3.8222 | 11.1577 | 21.2347 | 948.349 | 51.0139 | 4256.8402 |
| `BW p50` | 12,162 | 1,247 | 14.5006 | 9.8805 | 15.1897 | 104.75 | 1.3975 | 3.6837 | 6.0328 | 19.241 | 36.8807 | 948.349 | 20.9011 | 1185.8073 |
| `BW p75` | 12,162 | 1,247 | 25.5772 | 17.0217 | 23.9074 | 93.47 | 1.5359 | 5.4311 | 9.7763 | 36.2833 | 66.4082 | 948.349 | 6.9709 | 198.3945 |

**Top 20 pays avec la meilleure bande passante médiane (Mbps) :**

| Rang | Pays | BW médiane moy. (Mbps) |
|---:|---|---:|
| 1 | VA | 71.85 |
| 2 | TF | 65.21 |
| 3 | MO | 56.47 |
| 4 | KR | 55.30 |
| 5 | HK | 54.03 |
| 6 | SG | 52.39 |
| 7 | AX | 49.68 |
| 8 | MC | 45.94 |
| 9 | SM | 43.29 |
| 10 | LI | 41.80 |
| 11 | NL | 36.57 |
| 12 | LU | 35.83 |
| 13 | SE | 35.44 |
| 14 | CH | 34.33 |
| 15 | NO | 33.71 |
| 16 | JP | 33.54 |
| 17 | DK | 33.34 |
| 18 | JE | 33.21 |
| 19 | FR | 33.14 |
| 20 | IL | 31.78 |

**Bottom 15 pays avec la plus faible bande passante médiane (Mbps) :**

| Rang | Pays | BW médiane moy. (Mbps) |
|---:|---|---:|
| 1 | BI | 3.86 |
| 2 | CF | 3.79 |
| 3 | GN | 3.76 |
| 4 | AF | 3.70 |
| 5 | SL | 3.69 |
| 6 | LR | 3.67 |
| 7 | WF | 3.65 |
| 8 | GQ | 3.61 |
| 9 | TD | 3.60 |
| 10 | NE | 3.59 |
| 11 | YE | 3.52 |
| 12 | SY | 3.42 |
| 13 | CM | 3.28 |
| 14 | NF | 2.81 |
| 15 | KP | 2.15 |

> **Couverture :** 241 pays ont des données de bande passante, 11 pays n'ont aucune donnée (territoires isolés, pas de présence Cloudflare).

### 8.2 Qualité DNS (IQI DNS, ms)

| Variable | N | N manq. | Moyenne | Médiane | Éc.-type | CV% | Min | P5 | P25 | P75 | P95 | Max | Asymétrie | Aplatissement |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `DNS p25` | 12,162 | 1,247 | 61.9364 | 48.4464 | 44.6095 | 72.02 | 1.0 | 18.9748 | 28.6101 | 83.537 | 146.8431 | 678.5 | 2.1651 | 10.7035 |
| `DNS p50` | 12,162 | 1,247 | 93.0939 | 77.4869 | 57.5436 | 61.81 | 1.0 | 30.0344 | 48.7807 | 125.1528 | 198.114 | 734.0 | 1.7049 | 6.5859 |
| `DNS p75` | 12,162 | 1,247 | 145.2871 | 124.3414 | 82.8918 | 57.05 | 1.0 | 49.7619 | 80.7617 | 194.6966 | 298.521 | 816.25 | 1.2694 | 2.6049 |

**Top 20 pays avec la meilleure latence DNS (médiane la plus faible, ms) :**

| Rang | Pays | Latence DNS médiane moy. (ms) |
|---:|---|---:|
| 1 | TF | 8.00 |
| 2 | KR | 22.77 |
| 3 | MO | 24.54 |
| 4 | MC | 26.20 |
| 5 | AD | 28.00 |
| 6 | CH | 28.29 |
| 7 | CN | 28.49 |
| 8 | GB | 28.52 |
| 9 | SM | 29.03 |
| 10 | JE | 29.45 |
| 11 | LU | 29.56 |
| 12 | SE | 29.95 |
| 13 | AX | 30.01 |
| 14 | HK | 30.04 |
| 15 | SG | 31.00 |
| 16 | GG | 31.49 |
| 17 | IE | 31.58 |
| 18 | ES | 32.31 |
| 19 | DE | 33.10 |
| 20 | FR | 33.73 |

**Top 15 pays avec la latence DNS la plus élevée (ms) :**

| Rang | Pays | Latence DNS médiane moy. (ms) |
|---:|---|---:|
| 1 | WF | 349.83 |
| 2 | NF | 344.10 |
| 3 | ER | 267.96 |
| 4 | YE | 243.32 |
| 5 | KM | 239.54 |
| 6 | SS | 225.20 |
| 7 | CU | 217.77 |
| 8 | TJ | 214.08 |
| 9 | GQ | 211.40 |
| 10 | GW | 210.71 |
| 11 | CF | 206.20 |
| 12 | LR | 199.27 |
| 13 | AS | 194.18 |
| 14 | YT | 192.14 |
| 15 | TK | 186.19 |

> **Corrélation Spearman bande passante ~ latence DNS (par pays) : -0.854**  
> Corrélation négative modérée à forte : les pays avec une meilleure bande passante ont tendance à avoir une latence DNS plus faible.

---
## 9. Synthèse — Faits Saillants et Findings Clés

### 9.1 Attaques Réseau
- **L3 :** UDP représente **74.0%** du vecteur d'attaque (amplification/réflexion). Les petites attaques (<500 Mbps) sont les plus fréquentes (**57%**) mais les méga-attaques (>100 Gbps) existent (moy. 0.067%, pic 0.669%).
- **L7 :** GET domine à **82.0%**. L'Informatique/Électronique subit **22.8%** des attaques applicatives. HTTP/2 et HTTP/1.x sont les protocoles d'attaque principaux.
- **IPv4 vs IPv6 :** les attaques L3 sont à **99.7%** IPv4, soit bien plus que la part IPv4 dans le trafic légitime (80.2%) — les attaquants évitent IPv6.

### 9.2 Sécurité Email
- DMARC est le protocole le plus efficace : **87.9%** PASS, mais SPF reste défaillant (**16.3%** FAIL), ce qui laisse une surface d'attaque réelle.
- **6.2%** du trafic email est du spam, **17.2%** du spoofing, **10.8%** malicieux — ces métriques sont corrélées entre elles.

### 9.3 Protocoles Web & Infrastructure
- TLS 1.3 (**66.2% moy.**) est désormais dominant ; les protocoles obsolètes (TLS 1.0/1.1) subsistent dans quelques pays à infrastructure vieillissante.
- HTTP/3 atteint **25.4% moy.** — adoption significative mais hétérogène (CV élevé).
- IPv6 : **19.8%** moy. mondial, mais la médiane est 14.6% — distribution très asymétrique (quelques pays très avancés tirent la moyenne vers le haut).
- Chrome (**71.5%**) et Android (**40.1%**) dominent le Web mondial ; le mobile (**48.8%**) talonne le desktop (**50.9%**).

### 9.4 BGP & Routage
- **6946s** de durée médiane pour un hijack BGP — la plupart sont brefs (18.7% < 1 minute).
- Score de confiance moyen **6.01/16** — les événements à haute confiance (8+) représentent 41.0% des hijacks.
- Chaque hijack implique en moyenne 3.8 préfixes IP et 7.1 ASNs pairs.

### 9.5 Qualité Internet Mondiale
- Bande passante : médiane mondiale **9.9 Mbps** mais distribution log-normale (skew = 20.9) — forte inégalité entre pays.
- Latence DNS : médiane mondiale **77.5 ms** avec des valeurs jusqu'à 734 ms dans les pays les plus défavorisés.
- **11** pays sans données IQI : territoires isolés ou non couverts par Cloudflare.

---
*Rapport généré automatiquement par `phase_B_descriptif.py` le 2026-06-16 12:47:35.*  
*Prochaine étape : Phase C — Analyse temporelle (séries chronologiques, STL, ARIMA).*