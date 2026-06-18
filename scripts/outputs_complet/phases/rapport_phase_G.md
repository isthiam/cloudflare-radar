# Rapport Phase G — Analyse BGP Hijacks & Leaks
**Cloudflare Radar Dataset — Déc. 2025 / Juin 2026**  
**Auteur :** Issakha Thiam  
**Généré le :** 2026-06-16 16:22:07

---
## 1. Résumé Exécutif

| Jeu de données | Période | Événements | Pays hijackeurs | ASNs hijackeurs |
|---|---|---:|---:|---:|
| BGP Hijacks | 2025-12-04 → 2026-06-09 | 20,000 | 141 | 2,219 |
| BGP Leaks   | 2026-03-02 → 2026-06-09 | 19,999 | 145 | 1,848 |

**Métriques clés :**

| Indicateur | Valeur |
|---|---|
| Durée moyenne d'un hijack | 16.4 h (médiane : 1.9 h) |
| Durée maximale d'un hijack | 2533.8 h = 106 jours |
| Confidence score moyen | 6.01 / 12 |
| Hijacks confiance élevée (≥ 8) | 8,204 (41.0%) |
| Hijacks avec RPKI invalide | 11,252 (56.3%) |
| Hijacks avec IRR invalide | 15,307 (76.5%) |
| Hijacks bogon prefix | 233 (1.2%) |
| Préfixes max hijackés (1 event) | 15,129 |
| ASNs victimes uniques | 4,082 |
| Pays victimes uniques | 174 |
| Leaks encore actifs | 582 (2.9%) |
| Longueur moyenne leak_seg | 3.00 ASNs |

---
## 2. BGP Hijacks — Vue d'Ensemble

### 2.1 Distribution du Score de Confiance

> Score Cloudflare : 1=très faible, 4=faible, 8=probable, 10=fort, 12=certain.

| Score | Nb événements | % Total | Interprétation | Barre |
|---:|---:|---:|---|---|
| 1 | 160 | 0.8% | Très faible — probable faux positif | [..............................] |
| 2 | 4,359 | 21.8% | Faible | [##########....................] |
| 4 | 6,587 | 32.9% | Modéré | [################..............] |
| 5 | 2 | 0.0% | Modéré+ | [..............................] |
| 6 | 680 | 3.4% | Probable | [#.............................] |
| 7 | 8 | 0.0% | Probable+ | [..............................] |
| 8 | 3,679 | 18.4% | Fort — hijack probable | [#########.....................] |
| 10 | 1,485 | 7.4% | Très fort | [###...........................] |
| 12 | 3,040 | 15.2% | Certain — hijack confirmé | [#######.......................] |

### 2.2 Statistiques Descriptives — Durée des Hijacks

| Statistique | Durée (heures) | Durée (jours) |
|---|---:|---:|
| Minimum | 0.00 | 0.00 |
| P25 | 0.07 | 0.00 |
| Médiane | 1.93 | 0.08 |
| Moyenne | 16.38 | 0.68 |
| P75 | 22.61 | 0.94 |
| P90 | 50.96 | 2.12 |
| P95 | 65.52 | 2.73 |
| Maximum | 2533.77 | 105.57 |

### 2.3 Distribution de Sévérité

> Sévérité = confidence_score × log(1+prefixes) × log(1+durée_h)

| Catégorie | Nb | % | Conf. moy. | Préf. moy. | Durée moy. (h) |
|---|---:|---:|---:|---:|---:|
| **Critique** | 3,746 | 18.7% | 9.0 | 11.5 | 47.0 |
| **Élevée** | 2,824 | 14.1% | 6.1 | 2.9 | 30.6 |
| **Modérée** | 2,576 | 12.9% | 4.7 | 2.1 | 19.3 |
| **Faible** | 2,230 | 11.2% | 4.9 | 1.8 | 6.1 |
| **Négligeable** | 8,624 | 43.1% | 5.4 | 1.8 | 0.2 |

### 2.4 Statistiques des Préfixes Hijackés

| Statistique | Préfixes | Victimes ASNs | Victimes pays |
|---|---:|---:|---:|
| Min | 1.00 | 1.00 | 1.00 |
| Médiane | 1.00 | 1.00 | 1.00 |
| Moyenne | 3.79 | 1.29 | 1.11 |
| Max | 15129.00 | 1611.00 | 138.00 |
| Std | 107.44 | 11.41 | 1.08 |

**Top événement par préfixes :** 15,129 préfixes en 1 seul hijack
**Top événement victimes ASNs :** 1,611 ASNs victimes en 1 seul hijack
**Top événement victimes pays :** 138 pays victimes en 1 seul hijack

---
## 3. Analyse Tags IRR & RPKI

> **IRR** (Internet Routing Registry) : base de données de routage.  
> **RPKI** (Resource Public Key Infrastructure) : validation cryptographique des origines AS.  
> Un préfixe RPKI-invalid dans le nouveau hijack indique une violation ROA (Route Origin Authorization).

### 3.1 Fréquence des Tags (toutes occurrences)

| Rang | Tag | Nb occurrences | % événements | Score moyen | Signification |
|---:|---|---:|---:|---:|---|
| 1 | `irr_new_origin_invalid` | 15,307 | 76.5% | 4.0 | Nouveau noeud non enregistré en IRR |
| 2 | `rpki_new_origin_invalid` | 11,252 | 56.3% | 8.0 | ⚠️ RPKI ROA violation — attaque probable |
| 3 | `irr_old_origin_valid` | 10,606 | 53.0% | 0.0 | Ancien noeud enregistré en IRR (légitime) |
| 4 | `rpki_old_origin_valid` | 10,326 | 51.6% | 0.0 | Ancien noeud validé RPKI (légitime) |
| 5 | `rpki_new_origin_unknown` | 9,464 | 47.3% | 0.0 | RPKI inconnu pour nouveau noeud |
| 6 | `rpki_old_origin_unknown` | 9,464 | 47.3% | 0.0 | RPKI inconnu pour ancien noeud |
| 7 | `irr_old_origin_invalid` | 7,347 | 36.7% | -2.0 | Ancien noeud invalide IRR |
| 8 | `irr_old_origin_unknown` | 4,415 | 22.1% | 0.0 | Ancien noeud inconnu IRR |
| 9 | `irr_new_origin_unknown` | 4,415 | 22.1% | 0.0 | Nouveau noeud inconnu IRR |
| 10 | `irr_new_origin_valid` | 2,059 | 10.3% | -4.0 | Nouveau noeud valide IRR (mais change) |
| 11 | `asrel_new_origin_provider` | 1,444 | 7.2% | -4.0 | Fournisseur AS devient origine |
| 12 | `asrel_sibling_origins` | 1,264 | 6.3% | -4.0 | ASNs frères — même organisation |
| 13 | `rpki_old_origin_invalid` | 1,206 | 6.0% | -2.0 | Ancien noeud RPKI invalide |
| 14 | `bogon_old_origin` | 233 | 1.2% | -1.0 | 🚨 Adresse bogon en ancien préfixe |
| 15 | `asrel_new_origin_customer` | 55 | 0.3% | -2.0 | Client AS devient origine |
| 16 | `asrel_new_origin_peer` | 7 | 0.0% | -2.0 | Pair AS devient origine |

### 3.2 Couverture RPKI vs IRR

| Indicateur | Nb événements | % du total |
|---|---:|---:|
| RPKI new origin INVALID (violation ROA) | 11,252 | 56.3% |
| IRR new origin INVALID | 15,307 | 76.5% |
| RPKI old origin VALID (origine légitime connue) | 10,326 | 51.6% |
| Bogon prefix détecté | 233 | 1.2% |
| RPKI ET IRR tous deux invalides | 6,559 | 32.8% |

### 3.3 Analyse des Hijacks Haute Confiance (score ≥ 8)

**8,204 événements (41.0%) à confiance ≥ 8**

| Statistique | Valeur |
|---|---|
| Durée moyenne | 18.9 h |
| Préfixes moyens | 5.1 |
| Victimes ASNs moyennes | 1.6 |
| Victimes pays moyennes | 1.2 |
| RPKI invalide | 100.0% |
| IRR invalide | 71.8% |
| Top pays hijackeur | US (1,720) |

---
## 4. Top ASNs Hijackeurs

### 4.1 Top 30 ASNs Hijackeurs par Volume

| Rang | ASN hijackeur | Pays | Nb events | % total | Conf. moy. | Dur. moy. (h) | Préf. méd. |
|---:|---:|---|---:|---:|---:|---:|---:|
| 1 | AS6453 | États-Unis | 141 | 0.70% | 11.5 | 18.9 | 2 |
| 2 | AS134542 | Chine | 131 | 0.66% | 2.0 | 11.5 | 1 |
| 3 | AS58519 | Chine | 127 | 0.64% | 2.0 | 11.5 | 1 |
| 4 | AS131284 | Afghanistan | 121 | 0.60% | 9.5 | 31.4 | 2 |
| 5 | AS10753 | États-Unis | 115 | 0.57% | 3.2 | 13.6 | 12 |
| 6 | AS136958 | Chine | 112 | 0.56% | 6.1 | 30.4 | 7 |
| 7 | AS45820 | Inde | 109 | 0.55% | 4.0 | 22.8 | 1 |
| 8 | AS12668 | Russie | 109 | 0.55% | 4.0 | 11.3 | 1 |
| 9 | AS138421 | Chine | 108 | 0.54% | 6.3 | 35.1 | 8 |
| 10 | AS1031 | Inconnu | 108 | 0.54% | 5.1 | 20.5 | 1 |
| 11 | AS4811 | Chine | 107 | 0.53% | 3.4 | 25.9 | 38 |
| 12 | AS7029 | États-Unis | 107 | 0.53% | 5.0 | 13.6 | 3 |
| 13 | AS23724 | Chine | 106 | 0.53% | 2.2 | 20.1 | 11 |
| 14 | AS9009 | Royaume-Uni | 106 | 0.53% | 8.9 | 20.0 | 1 |
| 15 | AS4847 | Chine | 106 | 0.53% | 2.4 | 16.1 | 17 |
| 16 | AS199524 | Luxembourg | 105 | 0.53% | 9.8 | 18.5 | 3 |
| 17 | AS36901 | Ouganda | 103 | 0.52% | 4.0 | 25.5 | 2 |
| 18 | AS45102 | États-Unis | 102 | 0.51% | 5.8 | 16.4 | 2 |
| 19 | AS17621 | Chine | 102 | 0.51% | 4.9 | 35.8 | 35 |
| 20 | AS45629 | Thaïlande | 102 | 0.51% | 11.8 | 30.7 | 2 |
| 21 | AS17025 | États-Unis | 101 | 0.51% | 2.0 | 7.9 | 12 |
| 22 | AS140716 | Chine | 100 | 0.50% | 4.0 | 33.1 | 4 |
| 23 | AS140570 | Hong Kong | 98 | 0.49% | 7.6 | 9.8 | 2 |
| 24 | AS58466 | Chine | 96 | 0.48% | 2.0 | 16.1 | 2 |
| 25 | AS4766 | Corée du Sud | 94 | 0.47% | 2.2 | 15.6 | 2 |
| 26 | AS24203 | Indonésie | 93 | 0.46% | 8.0 | 32.7 | 1 |
| 27 | AS4816 | Chine | 91 | 0.46% | 2.0 | 12.4 | 3 |
| 28 | AS9802 | Chine | 91 | 0.46% | 4.0 | 31.8 | 4 |
| 29 | AS37154 | Zambie | 89 | 0.45% | 4.0 | 27.7 | 1 |
| 30 | AS136255 | Myanmar | 89 | 0.45% | 10.0 | 28.7 | 1 |

### 4.2 ASNs Hijackeurs avec Haute Confiance (score ≥ 8, Top 20)

| Rang | ASN | Pays | Nb events haute conf. | Conf. moy. | Préf. moy. |
|---:|---:|---|---:|---:|---:|
| 1 | AS6453 | États-Unis | 133 | 12.0 | 2.7 |
| 2 | AS199524 | Luxembourg | 102 | 10.0 | 3.3 |
| 3 | AS45629 | Thaïlande | 102 | 11.8 | 1.9 |
| 4 | AS131284 | Afghanistan | 99 | 10.7 | 3.7 |
| 5 | AS9009 | Royaume-Uni | 98 | 9.5 | 2.9 |
| 6 | AS24203 | Indonésie | 93 | 8.0 | 1.4 |
| 7 | AS136255 | Myanmar | 89 | 10.0 | 1.0 |
| 8 | AS262186 | Colombie | 83 | 10.4 | 1.6 |
| 9 | AS26042 | Inconnu | 77 | 11.7 | 2.4 |
| 10 | AS136958 | Chine | 76 | 8.0 | 6.3 |
| 11 | AS141864 | Inde | 76 | 8.0 | 1.0 |
| 12 | AS4800 | Indonésie | 72 | 12.0 | 2.0 |
| 13 | AS133296 | Inde | 72 | 11.6 | 2.1 |
| 14 | AS17816 | Chine | 70 | 8.0 | 4.3 |
| 15 | AS138421 | Chine | 68 | 8.0 | 7.4 |
| 16 | AS38738 | Viêt Nam | 65 | 8.1 | 1.0 |
| 17 | AS6461 | États-Unis | 63 | 12.0 | 2.2 |
| 18 | AS37661 | Nigeria | 62 | 12.0 | 1.0 |
| 19 | AS264886 | Brésil | 62 | 8.0 | 1.2 |
| 20 | AS28640 | Brésil | 61 | 8.0 | 1.0 |

---
## 5. Analyse Géographique BGP Hijacks

### 5.1 Top 30 Pays Hijackeurs

| Rang | Pays | ISO2 | Nb events | % | Conf. moy. | Dur. moy. (h) | Conf≥8 | RPKI inv% |
|---:|---|---|---:|---:|---:|---:|---:|---:|
| 1 | États-Unis | US | 4,698 | 23.5% | 5.7 | 13.4 | 1,720 | 50.6% |
| 2 | Chine | CN | 1,993 | 10.0% | 3.8 | 22.7 | 405 | 23.2% |
| 3 | Russie | RU | 1,072 | 5.4% | 4.8 | 12.5 | 247 | 29.5% |
| 4 | Brésil | BR | 1,029 | 5.1% | 7.0 | 18.0 | 740 | 97.4% |
| 5 | Inde | IN | 1,016 | 5.1% | 6.8 | 21.5 | 506 | 81.6% |
| 6 | Royaume-Uni | GB | 772 | 3.9% | 5.0 | 11.7 | 250 | 54.8% |
| 7 | Hong Kong | HK | 711 | 3.6% | 6.1 | 14.6 | 288 | 62.9% |
| 8 | Indonésie | ID | 657 | 3.3% | 7.9 | 24.3 | 473 | 95.9% |
| 9 | Allemagne | DE | 436 | 2.2% | 7.6 | 15.4 | 232 | 60.8% |
| 10 | Pays-Bas | NL | 364 | 1.8% | 6.9 | 8.6 | 184 | 66.8% |
| 11 | Pologne | PL | 302 | 1.5% | 4.4 | 11.7 | 39 | 20.5% |
| 12 | Turquie | TR | 284 | 1.4% | 8.7 | 9.6 | 202 | 82.0% |
| 13 | Australie | AU | 245 | 1.2% | 5.5 | 9.4 | 81 | 46.5% |
| 14 | France | FR | 225 | 1.1% | 6.6 | 14.1 | 102 | 50.7% |
| 15 | Espagne | ES | 222 | 1.1% | 6.4 | 7.7 | 86 | 61.7% |
| 16 | Ukraine | UA | 214 | 1.1% | 5.4 | 27.4 | 48 | 27.6% |
| 17 | Zambie | ZM | 206 | 1.0% | 4.0 | 31.3 | 0 | 0.0% |
| 18 | Bangladesh | BD | 205 | 1.0% | 8.7 | 21.1 | 143 | 100.0% |
| 19 | Colombie | CO | 188 | 0.9% | 8.2 | 12.7 | 147 | 94.1% |
| 20 | Suède | SE | 179 | 0.9% | 3.4 | 14.9 | 15 | 9.5% |
| 21 | Afghanistan | AF | 177 | 0.9% | 10.2 | 32.5 | 154 | 87.0% |
| 22 | Afrique du Sud | ZA | 156 | 0.8% | 3.5 | 19.0 | 7 | 75.0% |
| 23 | Corée du Sud | KR | 155 | 0.8% | 4.4 | 12.2 | 48 | 93.5% |
| 24 | Thaïlande | TH | 150 | 0.8% | 10.1 | 24.1 | 128 | 100.0% |
| 25 | Pakistan | PK | 147 | 0.7% | 6.1 | 22.1 | 56 | 52.4% |
| 26 | Tanzanie | TZ | 145 | 0.7% | 4.7 | 35.4 | 24 | 16.6% |
| 27 | Singapour | SG | 144 | 0.7% | 5.6 | 10.6 | 30 | 77.8% |
| 28 | Lituanie | LT | 143 | 0.7% | 3.8 | 15.2 | 21 | 67.1% |
| 29 | Bulgarie | BG | 141 | 0.7% | 5.8 | 10.1 | 48 | 42.6% |
| 30 | Viêt Nam | VN | 139 | 0.7% | 7.7 | 3.7 | 111 | 100.0% |

### 5.2 Top 30 Pays Victimes

| Rang | Pays | ISO2 | Nb occurrences | % victimisations |
|---:|---|---|---:|---:|
| 1 | États-Unis | US | 5,848 | 26.4% |
| 2 | Chine | CN | 2,110 | 9.5% |
| 3 | Brésil | BR | 1,215 | 5.5% |
| 4 | Russie | RU | 1,177 | 5.3% |
| 5 | Royaume-Uni | GB | 1,056 | 4.8% |
| 6 | Inde | IN | 891 | 4.0% |
| 7 | Indonésie | ID | 690 | 3.1% |
| 8 | null | null | 525 | 2.4% |
| 9 | Hong Kong | HK | 467 | 2.1% |
| 10 | Allemagne | DE | 411 | 1.9% |
| 11 | Pologne | PL | 327 | 1.5% |
| 12 | Ukraine | UA | 321 | 1.4% |
| 13 | Australie | AU | 316 | 1.4% |
| 14 | France | FR | 268 | 1.2% |
| 15 | Afrique du Sud | ZA | 266 | 1.2% |
| 16 | Turquie | TR | 261 | 1.2% |
| 17 | Pays-Bas | NL | 249 | 1.1% |
| 18 | Bangladesh | BD | 221 | 1.0% |
| 19 | Zambie | ZM | 217 | 1.0% |
| 20 | Espagne | ES | 204 | 0.9% |
| 21 | Suède | SE | 190 | 0.9% |
| 22 | Colombie | CO | 184 | 0.8% |
| 23 | Roumanie | RO | 184 | 0.8% |
| 24 | Singapour | SG | 183 | 0.8% |
| 25 | Afghanistan | AF | 171 | 0.8% |
| 26 | Ouganda | UG | 166 | 0.7% |
| 27 | Canada | CA | 154 | 0.7% |
| 28 | Iran | IR | 151 | 0.7% |
| 29 | Bulgarie | BG | 147 | 0.7% |
| 30 | Viêt Nam | VN | 138 | 0.6% |

### 5.3 Top 30 Paires Hijacker → Victime (pays)

| Rang | Pays hijackeur | ISO2-H | Pays victime | ISO2-V | Nb incidents |
|---:|---|---|---|---|---:|
| 1 | États-Unis | US | Royaume-Uni | GB | 337 |
| 2 | Hong Kong | HK | États-Unis | US | 308 |
| 3 | Royaume-Uni | GB | États-Unis | US | 258 |
| 4 | Chine | CN | États-Unis | US | 222 |
| 5 | Pays-Bas | NL | États-Unis | US | 221 |
| 6 | États-Unis | US | null | null | 170 |
| 7 | Hong Kong | HK | Chine | CN | 144 |
| 8 | États-Unis | US | Bahreïn | BH | 128 |
| 9 | États-Unis | US | Russie | RU | 118 |
| 10 | États-Unis | US | Brésil | BR | 107 |
| 11 | États-Unis | US | Indonésie | ID | 106 |
| 12 | Russie | RU | null | null | 105 |
| 13 | Inde | IN | États-Unis | US | 101 |
| 14 | Allemagne | DE | États-Unis | US | 98 |
| 15 | États-Unis | US | France | FR | 98 |
| 16 | Luxembourg | LU | Royaume-Uni | GB | 83 |
| 17 | Suède | SE | Royaume-Uni | GB | 83 |
| 18 | Corée du Sud | KR | Russie | RU | 82 |
| 19 | États-Unis | US | Allemagne | DE | 81 |
| 20 | Russie | RU | États-Unis | US | 81 |
| 21 | États-Unis | US | Turquie | TR | 81 |
| 22 | États-Unis | US | Canada | CA | 80 |
| 23 | Royaume-Uni | GB | Suède | SE | 72 |
| 24 | États-Unis | US | Hong Kong | HK | 72 |
| 25 | Indonésie | ID | États-Unis | US | 69 |
| 26 | États-Unis | US | Pays-Bas | NL | 69 |
| 27 | Lituanie | LT | États-Unis | US | 67 |
| 28 | Lituanie | LT | Afrique du Sud | ZA | 64 |
| 29 | Royaume-Uni | GB | Russie | RU | 62 |
| 30 | France | FR | États-Unis | US | 61 |

### 5.4 Top 25 Paires Hijacker → Victime (ASNs)

| Rang | ASN hijackeur | ASN victime | Nb incidents |
|---:|---:|---:|---:|
| 1 | AS6453 | AS5416 | 128 |
| 2 | AS58519 | AS134542 | 126 |
| 3 | AS134542 | AS58519 | 124 |
| 4 | AS12668 | AS2854 | 109 |
| 5 | AS199524 | AS59245 | 105 |
| 6 | AS4847 | AS4808 | 104 |
| 7 | AS138421 | AS4811 | 103 |
| 8 | AS36901 | AS29032 | 103 |
| 9 | AS23724 | AS4808 | 103 |
| 10 | AS17025 | AS10753 | 101 |
| 11 | AS140716 | AS138950 | 100 |
| 12 | AS136958 | AS58466 | 100 |
| 13 | AS1031 | AS999 | 98 |
| 14 | AS45629 | AS7693 | 98 |
| 15 | AS17621 | AS4812 | 97 |
| 16 | AS10753 | AS17025 | 97 |
| 17 | AS45629 | AS58955 | 97 |
| 18 | AS58466 | AS136958 | 95 |
| 19 | AS45102 | AS45700 | 93 |
| 20 | AS24203 | AS17885 | 93 |
| 21 | AS9802 | AS23724 | 91 |
| 22 | AS4816 | AS17622 | 91 |
| 23 | AS140570 | AS54801 | 88 |
| 24 | AS17621 | AS4811 | 88 |
| 25 | AS4811 | AS17621 | 87 |

### 5.5 Top 30 ASNs Victimes

| Rang | ASN victime | Nb occurrences |
|---:|---:|---:|
| 1 | AS174 | 698 |
| 2 | AS834 | 555 |
| 3 | AS23724 | 234 |
| 4 | AS4808 | 216 |
| 5 | AS63199 | 213 |
| 6 | AS28629 | 209 |
| 7 | AS4811 | 198 |
| 8 | AS134542 | 182 |
| 9 | AS4812 | 182 |
| 10 | AS58519 | 171 |
| 11 | AS212238 | 160 |
| 12 | AS2854 | 150 |
| 13 | AS7420 | 135 |
| 14 | AS5416 | 128 |
| 15 | AS10753 | 117 |
| 16 | AS2914 | 117 |
| 17 | AS999 | 113 |
| 18 | AS9009 | 113 |
| 19 | AS58466 | 106 |
| 20 | AS17621 | 105 |
| 21 | AS59245 | 105 |
| 22 | AS328608 | 105 |
| 23 | AS59019 | 104 |
| 24 | AS29032 | 103 |
| 25 | AS208185 | 102 |
| 26 | AS138407 | 102 |
| 27 | AS138950 | 100 |
| 28 | AS45700 | 99 |
| 29 | AS17025 | 98 |
| 30 | AS7693 | 98 |

---
## 6. Évolution Temporelle — BGP Hijacks

### 6.1 Évolution Mensuelle

| Mois | Nb events | Conf. moy. | Dur. moy. (h) | Conf≥8 | RPKI inv% | IRR inv% |
|---|---:|---:|---:|---:|---:|---:|
| 2025-12 | 2,794 | 6.06 | 16.1 | 1,168 | 56.1% | 76.5% |
| 2026-01 | 3,172 | 5.94 | 15.8 | 1,272 | 53.8% | 77.1% |
| 2026-02 | 3,093 | 5.94 | 17.2 | 1,223 | 56.2% | 75.6% |
| 2026-03 | 3,758 | 5.70 | 16.3 | 1,430 | 54.2% | 76.2% |
| 2026-04 | 3,154 | 6.07 | 16.4 | 1,316 | 55.8% | 77.4% |
| 2026-05 | 3,172 | 6.31 | 17.7 | 1,406 | 60.2% | 77.3% |
| 2026-06 | 834 | 6.31 | 12.1 | 382 | 62.5% | 73.9% |

### 6.2 Évolution Hebdomadaire (toutes semaines)

| Semaine | Nb events | Conf. moy. | Dur. méd. (h) | Dur. moy. (h) | Préf. moy. | RPKI inv% |
|---|---:|---:|---:|---:|---:|---:|
| 2025-12-01/2025-12-07 | 350 | 6.33 | 2.2 | 16.4 | 2.8 | 59.1% |
| 2025-12-08/2025-12-14 | 759 | 5.97 | 2.8 | 17.7 | 3.1 | 54.9% |
| 2025-12-15/2025-12-21 | 776 | 6.08 | 2.5 | 16.9 | 2.7 | 56.2% |
| 2025-12-22/2025-12-28 | 655 | 5.96 | 1.4 | 14.7 | 3.4 | 54.0% |
| 2025-12-29/2026-01-04 | 570 | 5.78 | 1.4 | 14.5 | 2.7 | 50.7% |
| 2026-01-05/2026-01-11 | 639 | 5.92 | 0.5 | 12.9 | 2.6 | 55.7% |
| 2026-01-12/2026-01-18 | 706 | 6.02 | 2.7 | 14.5 | 2.9 | 55.0% |
| 2026-01-19/2026-01-25 | 812 | 6.05 | 1.3 | 16.4 | 2.7 | 55.9% |
| 2026-01-26/2026-02-01 | 779 | 6.07 | 2.5 | 18.0 | 3.1 | 54.8% |
| 2026-02-02/2026-02-08 | 815 | 5.95 | 0.9 | 16.9 | 2.6 | 58.3% |
| 2026-02-09/2026-02-15 | 715 | 5.92 | 1.0 | 15.4 | 2.6 | 55.1% |
| 2026-02-16/2026-02-22 | 731 | 5.99 | 2.0 | 18.1 | 2.9 | 54.6% |
| 2026-02-23/2026-03-01 | 820 | 5.81 | 6.6 | 18.5 | 3.1 | 56.8% |
| 2026-03-02/2026-03-08 | 1,003 | 5.31 | 0.7 | 14.1 | 18.1 | 50.0% |
| 2026-03-09/2026-03-15 | 900 | 5.83 | 2.3 | 16.7 | 3.1 | 58.6% |
| 2026-03-16/2026-03-22 | 819 | 5.81 | 1.3 | 15.3 | 2.5 | 53.4% |
| 2026-03-23/2026-03-29 | 748 | 5.78 | 3.3 | 18.3 | 2.9 | 54.8% |
| 2026-03-30/2026-04-05 | 708 | 6.00 | 2.2 | 17.6 | 2.4 | 53.1% |
| 2026-04-06/2026-04-12 | 709 | 5.96 | 1.6 | 16.2 | 3.4 | 55.6% |
| 2026-04-13/2026-04-19 | 715 | 6.03 | 3.2 | 17.9 | 4.0 | 57.2% |
| 2026-04-20/2026-04-26 | 739 | 6.25 | 1.8 | 16.2 | 3.2 | 56.8% |
| 2026-04-27/2026-05-03 | 749 | 6.27 | 1.6 | 18.7 | 3.5 | 56.2% |
| 2026-05-04/2026-05-10 | 818 | 6.19 | 3.2 | 17.6 | 2.6 | 59.0% |
| 2026-05-11/2026-05-17 | 687 | 6.37 | 3.3 | 19.7 | 4.0 | 60.4% |
| 2026-05-18/2026-05-24 | 760 | 6.29 | 4.3 | 15.4 | 3.8 | 59.3% |
| 2026-05-25/2026-05-31 | 661 | 6.36 | 1.7 | 15.4 | 3.8 | 62.3% |
| 2026-06-01/2026-06-07 | 651 | 6.35 | 1.4 | 14.1 | 2.8 | 62.7% |
| 2026-06-08/2026-06-14 | 183 | 6.18 | 0.5 | 4.9 | 2.6 | 61.7% |

### 6.3 Semaines Anormales (|Z| ≥ 2,0)

| Semaine | Nb events | Z-score | Type |
|---|---:|---:|---|
| 2025-12-01/2025-12-07 | 350 | -2.36 | **CREUX** ⚠️ |
| 2026-06-08/2026-06-14 | 183 | -3.45 | **CREUX** ⚠️ |

---
## 7. BGP Leaks — Vue d'Ensemble

> **19,999 événements de fuite BGP** sur la période 2026-03-02 → 2026-06-09  
> Tous de type 1 (BGP type 1 leak : valley-free violation).

### 7.1 Statistiques Descriptives — Leaks

| Statistique | Leak count | Prefix count | Peer count | Origin count | Seg len | Durée (h) |
|---|---:|---:|---:|---:|---:|---:|
| Min | 1.0 | 1.0 | 1.0 | 1.0 | 3.00 | 0.0 |
| P25 | 12.0 | 1.0 | 3.0 | 1.0 | 3.00 | 0.4 |
| Médiane | 62.0 | 2.0 | 11.0 | 1.0 | 3.00 | 44.7 |
| Moyenne | 15947.0 | 50.5 | 27.2 | 8.9 | 3.00 | 37.6 |
| P75 | 315.0 | 4.0 | 41.0 | 2.0 | 3.00 | 68.5 |
| Max | 22897341.0 | 247324.0 | 233.0 | 16933.0 | 3.00 | 76.0 |
| Std | 437783.7 | 1798.0 | 33.1 | 138.9 | 0.00 | 29.9 |

**Leaks encore actifs (non terminés) : 582 (2.9%)**

### 7.2 Top 30 ASNs Fuiteurs (leak_asn)

| Rang | ASN fuiteur | Nb événements | % total | Leaks actifs |
|---:|---:|---:|---:|---:|
| 1 | AS199310 | 252 | 1.26% | 2 |
| 2 | AS30990 | 233 | 1.17% | 5 |
| 3 | AS268624 | 151 | 0.76% | 6 |
| 4 | AS25145 | 148 | 0.74% | 6 |
| 5 | AS7473 | 139 | 0.70% | 3 |
| 6 | AS136897 | 138 | 0.69% | 3 |
| 7 | AS4761 | 126 | 0.63% | 4 |
| 8 | AS37440 | 108 | 0.54% | 2 |
| 9 | AS4775 | 107 | 0.54% | 2 |
| 10 | AS18001 | 102 | 0.51% | 4 |
| 11 | AS9927 | 94 | 0.47% | 2 |
| 12 | AS28663 | 94 | 0.47% | 0 |
| 13 | AS205941 | 93 | 0.47% | 4 |
| 14 | AS24812 | 93 | 0.47% | 2 |
| 15 | AS37133 | 90 | 0.45% | 3 |
| 16 | AS136255 | 88 | 0.44% | 3 |
| 17 | AS51765 | 87 | 0.44% | 1 |
| 18 | AS53153 | 79 | 0.40% | 2 |
| 19 | AS214941 | 74 | 0.37% | 2 |
| 20 | AS19551 | 73 | 0.37% | 1 |
| 21 | AS206119 | 72 | 0.36% | 1 |
| 22 | AS52025 | 72 | 0.36% | 2 |
| 23 | AS61468 | 69 | 0.35% | 6 |
| 24 | AS199524 | 69 | 0.35% | 3 |
| 25 | AS20598 | 66 | 0.33% | 2 |
| 26 | AS204464 | 66 | 0.33% | 2 |
| 27 | AS51202 | 65 | 0.33% | 0 |
| 28 | AS47890 | 64 | 0.32% | 2 |
| 29 | AS45430 | 64 | 0.32% | 1 |
| 30 | AS45903 | 64 | 0.32% | 3 |

### 7.3 Top 25 ASNs Noeud de Fuite (middle de leak_seg)

| Rang | ASN middle | Nb occurrences |
|---:|---:|---:|
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
| 16 | AS136255 | 88 |
| 17 | AS51765 | 87 |
| 18 | AS53153 | 79 |
| 19 | AS214941 | 74 |
| 20 | AS19551 | 73 |
| 21 | AS206119 | 72 |
| 22 | AS52025 | 72 |
| 23 | AS199524 | 69 |
| 24 | AS61468 | 69 |
| 25 | AS204464 | 66 |

### 7.4 Top 20 ASNs Origine dans les Leaks

| Rang | ASN origine | Nb occurrences |
|---:|---:|---:|
| 1 | AS174 | 1,213 |
| 2 | AS6939 | 1,156 |
| 3 | AS9002 | 947 |
| 4 | AS3356 | 570 |
| 5 | AS3257 | 441 |
| 6 | AS58453 | 428 |
| 7 | AS9304 | 396 |
| 8 | AS7473 | 334 |
| 9 | AS52468 | 319 |
| 10 | AS37100 | 308 |
| 11 | AS6461 | 291 |
| 12 | AS1299 | 248 |
| 13 | AS4637 | 246 |
| 14 | AS6762 | 230 |
| 15 | AS6453 | 222 |
| 16 | AS20485 | 212 |
| 17 | AS37662 | 212 |
| 18 | AS9498 | 207 |
| 19 | AS2914 | 205 |
| 20 | AS22356 | 199 |

### 7.5 Top 25 Pays Impliqués dans les Leaks

| Rang | Pays | ISO2 | Nb occurrences | % |
|---:|---|---|---:|---:|
| 1 | États-Unis | US | 13,350 | 22.3% |
| 2 | Brésil | BR | 9,616 | 16.1% |
| 3 | Russie | RU | 3,597 | 6.0% |
| 4 | Indonésie | ID | 2,190 | 3.7% |
| 5 | Hong Kong | HK | 2,102 | 3.5% |
| 6 | Royaume-Uni | GB | 2,077 | 3.5% |
| 7 | Inde | IN | 1,647 | 2.8% |
| 8 | Allemagne | DE | 1,322 | 2.2% |
| 9 | Singapour | SG | 1,154 | 1.9% |
| 10 | Philippines | PH | 1,017 | 1.7% |
| 11 | Italie | IT | 999 | 1.7% |
| 12 | Turquie | TR | 946 | 1.6% |
| 13 | Colombie | CO | 893 | 1.5% |
| 14 | Suède | SE | 891 | 1.5% |
| 15 | Espagne | ES | 869 | 1.5% |
| 16 | Maurice | MU | 786 | 1.3% |
| 17 | Bulgarie | BG | 783 | 1.3% |
| 18 | Ukraine | UA | 782 | 1.3% |
| 19 | Chine | CN | 763 | 1.3% |
| 20 | France | FR | 598 | 1.0% |
| 21 | Pays-Bas | NL | 596 | 1.0% |
| 22 | Pologne | PL | 562 | 0.9% |
| 23 | Roumanie | RO | 544 | 0.9% |
| 24 | Suisse | CH | 531 | 0.9% |
| 25 | Panama | PA | 479 | 0.8% |

### 7.6 Longueur des Chemins de Fuite (leak_seg_len)

| Longueur chemin | Nb événements | % |
|---:|---:|---:|
| 3 ASNs | 19,999 | 100.0% |

---
## 8. Évolution Temporelle — BGP Leaks

### 8.1 Évolution Mensuelle

| Mois | Nb events | Durée moy. seg | Finished % |
|---|---:|---:|---:|
| 2026-03 | 5,906 | 3.00 ASNs | 100.0% |
| 2026-04 | 6,098 | 3.00 ASNs | 100.0% |
| 2026-05 | 6,232 | 3.00 ASNs | 100.0% |
| 2026-06 | 1,763 | 3.00 ASNs | 67.0% |

### 8.2 Évolution Hebdomadaire

| Semaine | Nb events | Dur. seg moy. | Leak count moy. | Préfixes moy. | Pairs moy. |
|---|---:|---:|---:|---:|---:|
| 2026-03-02/2026-03-08 | 1,323 | 3.00 | 1269.7 | 36.6 | 25.1 |
| 2026-03-09/2026-03-15 | 1,385 | 3.00 | 1491.4 | 32.3 | 26.3 |
| 2026-03-16/2026-03-22 | 1,270 | 3.00 | 1253.6 | 43.8 | 25.9 |
| 2026-03-23/2026-03-29 | 1,460 | 3.00 | 3289.6 | 208.1 | 26.4 |
| 2026-03-30/2026-04-05 | 1,364 | 3.00 | 2586.1 | 45.3 | 26.6 |
| 2026-04-06/2026-04-12 | 1,339 | 3.00 | 1704.5 | 34.5 | 28.2 |
| 2026-04-13/2026-04-19 | 1,454 | 3.00 | 2695.7 | 29.0 | 27.4 |
| 2026-04-20/2026-04-26 | 1,447 | 3.00 | 2634.3 | 50.5 | 28.2 |
| 2026-04-27/2026-05-03 | 1,476 | 3.00 | 12162.1 | 40.7 | 28.7 |
| 2026-05-04/2026-05-10 | 1,453 | 3.00 | 6005.9 | 41.6 | 27.6 |
| 2026-05-11/2026-05-17 | 1,444 | 3.00 | 5975.0 | 32.3 | 28.2 |
| 2026-05-18/2026-05-24 | 1,429 | 3.00 | 53175.6 | 41.3 | 29.0 |
| 2026-05-25/2026-05-31 | 1,392 | 3.00 | 70244.7 | 27.7 | 27.2 |
| 2026-06-01/2026-06-07 | 1,421 | 3.00 | 60327.5 | 44.0 | 28.2 |
| 2026-06-08/2026-06-14 | 342 | 3.00 | 1294.5 | 19.5 | 18.8 |

### 8.3 Semaines Anormales Leaks (|Z| ≥ 2,0)

| Semaine | Nb events | Z-score | Type |
|---|---:|---:|---|
| 2026-06-08/2026-06-14 | 342 | -3.53 | **CREUX** ⚠️ |

---
## 9. Analyse Croisée — Hijacks × Leaks (période commune mars–juin 2026)

| Indicateur | Hijacks (mars–juin) | Leaks (mars–juin) |
|---|---:|---:|
| Nb événements | 10,850 | 19,999 |
| Pays uniques impliqués | 129 | 145 |
| ASNs uniques | 1,596 | 1,848 |
| Conf./score moy. | 6.03 | — |
| Durée moy. (h) | 16.4 | 37.6 |

**ASNs présents dans hijacks ET leaks (même ASN joue les deux rôles) : 302**
Exemples : AS1251, AS2611, AS2764, AS3216, AS3255, AS3549, AS3573, AS4628, AS4761, AS4775, AS4800, AS4837, AS6205, AS6327, AS6802

---
## 10. Corrélations Intra-BGP et Patterns

### 10.1 Corrélation Confidence Score × Métriques

- **Confidence × Durée (h)** : r_Spearman = 0.0900, p = 0.0000 ✅
- **Confidence × Nb préfixes** : r_Spearman = 0.0557, p = 0.0000 ✅
- **Confidence × Nb victimes ASNs** : r_Spearman = 0.1781, p = 0.0000 ✅
- **Confidence × Nb victimes pays** : r_Spearman = 0.2121, p = 0.0000 ✅
- **Confidence × Nb pairs** : r_Spearman = 0.0236, p = 0.0009 ✅
- **Confidence × Score tags** : r_Spearman = 0.9423, p = 0.0000 ✅
- **Confidence × Nb messages** : r_Spearman = 0.0131, p = 0.0643 

### 10.2 Corrélation Durée × Préfixes

- Durée × Préfixes : r = 0.2009, p = 0.0000
- Durée × Confidence : r = 0.0900, p = 0.0000
- Préfixes × Confidence : r = 0.0557, p = 0.0000

### 10.3 Patterns Temporels (heure de début des hijacks)

| Heure UTC | Nb events | Conf. moy. |
|---:|---:|---:|
| 00:00 | 875 | 5.44 |
| 01:00 | 716 | 5.90 |
| 02:00 | 619 | 6.28 |
| 03:00 | 783 | 6.61 |
| 04:00 | 694 | 5.95 |
| 05:00 | 699 | 6.10 |
| 06:00 | 819 | 6.48 |
| 07:00 | 1,035 | 6.25 |
| 08:00 | 1,090 | 5.97 |
| 09:00 | 988 | 6.26 |
| 10:00 | 962 | 5.91 |
| 11:00 | 935 | 6.12 |
| 12:00 | 999 | 5.66 |
| 13:00 | 921 | 6.14 |
| 14:00 | 978 | 5.83 |
| 15:00 | 858 | 6.05 |
| 16:00 | 871 | 6.13 |
| 17:00 | 872 | 5.71 |
| 18:00 | 793 | 6.07 |
| 19:00 | 791 | 5.87 |
| 20:00 | 729 | 5.77 |
| 21:00 | 588 | 6.07 |
| 22:00 | 724 | 5.74 |
| 23:00 | 638 | 5.93 |

---
## 11. Findings et Implications Sécurité Routage

### 11.1 Résumé Statistique Global

| Indicateur | BGP Hijacks | BGP Leaks |
|---|---|---|
| Période couverte | Déc. 2025 – Juin 2026 | Mars 2026 – Juin 2026 |
| Nb total événements | 20,000 | 19,999 |
| Taux résolution | 99.6% résolus | 97.1% terminés |
| Durée médiane | 1.9 h | 44.7 h |
| Pays origine | 142 pays | 145 pays impliqués |
| Top pays offensif | US (4,698 events) | US (13,350 occ.) |

### 11.2 Observations Clés

1. **Concentration géographique des menaces :** US + CN + RU représentent 38.8% des hijacks. Cependant, les hijacks attribués aux USA peuvent refléter des compromissions d'ASNs hébergés aux USA plutôt que des acteurs étatiques.

2. **RPKI : déploiement insuffisant.** 56.3% des hijacks violent des ROAs RPKI — ce qui signifie que 43.7% des hijacks n'auraient PAS été détectés par RPKI seul. La couverture ROV (Route Origin Validation) reste largement incomplète sur l'internet mondial.

3. **Durées hétérogènes : de quelques secondes à 106 jours.** La médiane de 1.9h indique que la majorité des hijacks sont résolus rapidement, mais les événements extrêmes (>100h) peuvent avoir des impacts durables.

4. **Leaks BGP type 1 (valley-free) omniprésents.** Les 19,999 leaks identifiés sur 3 mois indiquent un problème structurel de politique de filtrage BGP. AS199310 (AS199310) est le fuiteur le plus actif avec 252 événements.

5. **Hijacks à large portée.** Un seul événement peut toucher jusqu'à 15,129 préfixes et 138 pays simultanément — soulignant la vulnérabilité systémique du routage BGP sans RPKI/ROV.

6. **Chevauchement hijacks/leaks : 302 ASNs actifs dans les deux.** La présence d'ASNs communs dans les hijacks ET les leaks peut indiquer soit des réseaux compromis, soit des opérateurs sans politique de sécurité BGP robuste.

7. **Vigilance sur les leaks non terminés.** 582 leaks (2.9%) restent actifs à la fin de la période — trafic potentiellement détourné en cours.

---
*Rapport généré automatiquement par `phase_G_bgp.py` le 2026-06-16 16:22:07.*  
*Sources : Cloudflare Radar API v4 — bgp_hijacks, bgp_leaks datasets.*  
*Prochaine étape : Phase H — Corrélations croisées inter-domaines.*