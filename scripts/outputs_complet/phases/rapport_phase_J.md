# Rapport Phase J — Détection d'Anomalies Consolidée
**Cloudflare Radar Dataset — Juin 2025 / Juin 2026**  
**Auteur :** Issakha Thiam  
**Généré le :** 2026-06-16 22:20:28

---
## 1. Résumé Exécutif

| Indicateur | Valeur |
|---|---|
| Séries temporelles analysées | 21 |
| Méthodes de détection | 4 (Z-score, IQR, Isolation Forest, LOF) |
| Seuil consensus | ≥ 2 méthodes sur 4 |
| Total anomalies consensus (toutes séries) | **42** |
| Série la plus anomalique | **SPOOF%** (4 anomalies) |
| Semaines avec ≥ 2 domaines anormaux | **10** |
| Pays avec profil anomalique (Isolation Forest) | **18** |

**Semaine la plus critique :** 2026-05-18 avec **6 domaines** anormaux simultanément.

---
## 2. Anomalies par Série Temporelle

> **Méthodes** : Z-score (|z|≥2.5), IQR (×2.0), Isolation Forest (5% contamination), LOF (5% contamination)  
> **Consensus** : anomalie retenue si détectée par ≥ 2 méthodes sur 4.

| Domaine | Série | N obs. | Moy. | Std | Z-anom | IQR-anom | IFo-anom | LOF-anom | Consensus |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Email | SPOOF% | 53 | 17.15 | 6.25 | 3 | 3 | 3 | 3 | **4** |
| BGP | BGP volume msgs | 53 | 11970274698.45 | 2874387120.96 | 1 | 2 | 3 | 3 | **3** |
| BGP | BGP hijacks count | 28 | 713.46 | 153.77 | 1 | 3 | 2 | 2 | **3** |
| Email | DMARC FAIL% | 53 | 5.31 | 2.09 | 1 | 1 | 3 | 3 | **3** |
| Email | SPF FAIL% | 53 | 16.27 | 2.17 | 1 | 2 | 3 | 3 | **3** |
| Email | SPAM% | 53 | 6.23 | 1.64 | 2 | 2 | 3 | 3 | **3** |
| L3 Attacks | L3 UDP% | 53 | 73.96 | 13.41 | 1 | 0 | 3 | 3 | **3** |
| BGP | BGP RPKI inv% | 28 | 56.51 | 3.14 | 0 | 0 | 2 | 2 | **2** |
| DNS | DNS qualité | 52 | 0.76 | 0.12 | 0 | 0 | 3 | 3 | **2** |
| Email | DMARC PASS% | 53 | 87.92 | 1.98 | 1 | 1 | 3 | 3 | **2** |
| Email | MALICIOUS% | 53 | 10.80 | 6.51 | 2 | 1 | 3 | 3 | **2** |
| HTTP/Protocol | IPv6% | 53 | 19.78 | 0.98 | 1 | 0 | 3 | 3 | **2** |
| HTTP/Protocol | TLS 1.3% | 53 | 66.22 | 1.30 | 0 | 0 | 3 | 3 | **2** |
| L3 Attacks | L3 haut vol.% | 53 | 29.13 | 19.78 | 1 | 1 | 3 | 3 | **2** |
| BGP | BGP conf. moy. | 28 | 6.03 | 0.23 | 1 | 1 | 2 | 2 | **1** |
| BGP | BGP leaks count | 15 | 1333.27 | 280.46 | 1 | 1 | 0 | 1 | **1** |
| Email | DKIM PASS% | 53 | 89.41 | 1.81 | 1 | 1 | 3 | 3 | **1** |
| Email | SPF PASS% | 53 | 79.00 | 2.23 | 0 | 0 | 3 | 3 | **1** |
| HTTP/Protocol | Bot rate% | 53 | 20.42 | 1.68 | 0 | 0 | 3 | 3 | **1** |
| L3 Attacks | L3 TCP% | 53 | 24.92 | 13.57 | 1 | 0 | 3 | 3 | **1** |
| L7 Attacks | L7 Internet&Télécom | 13 | 22.84 | 3.77 | 0 | 0 | 0 | 1 | **0** |

---
## 3. Détail des Anomalies Consensus par Série

### SPOOF% (4 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2025-06-23 | 9.095 | -1.29 | ⬇️ CREUX 🟡 MODÉRÉ | IFo+LOF |
| 2026-05-18 | 38.243 | +3.38 | ⬆️ PIC 🟠 FORT | Z+IQR+IFo |
| 2026-05-25 | 32.920 | +2.52 | ⬆️ PIC 🟡 MODÉRÉ | Z+IQR |
| 2026-06-01 | 35.196 | +2.89 | ⬆️ PIC 🟡 MODÉRÉ | Z+IQR+IFo |

### BGP volume msgs (3 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2026-05-18 | 18280851471.000 | +2.20 | ⬆️ PIC 🟡 MODÉRÉ | IQR+IFo+LOF |
| 2026-06-01 | 25499721429.000 | +4.71 | ⬆️ PIC 🔴 EXTRÊME | Z+IQR+IFo+LOF |
| 2026-06-08 | 6139854290.000 | -2.03 | ⬇️ CREUX 🟡 MODÉRÉ | IFo+LOF |

### BGP hijacks count (3 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2025-12-01 | 350.000 | -2.36 | ⬇️ CREUX 🟡 MODÉRÉ | IQR+LOF |
| 2026-03-02 | 1003.000 | +1.88 | ⬆️ PIC 🟡 MODÉRÉ | IQR+IFo |
| 2026-06-08 | 183.000 | -3.45 | ⬇️ CREUX 🟠 FORT | Z+IQR+IFo+LOF |

### DMARC FAIL% (3 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2025-07-28 | 9.988 | +2.24 | ⬆️ PIC 🟡 MODÉRÉ | IFo+LOF |
| 2026-02-16 | 2.868 | -1.17 | ⬇️ CREUX 🟡 MODÉRÉ | IFo+LOF |
| 2026-05-18 | 14.978 | +4.63 | ⬆️ PIC 🔴 EXTRÊME | Z+IQR+IFo+LOF |

### SPF FAIL% (3 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2025-09-15 | 21.436 | +2.38 | ⬆️ PIC 🟡 MODÉRÉ | IQR+IFo |
| 2026-03-02 | 12.953 | -1.53 | ⬇️ CREUX 🟡 MODÉRÉ | IFo+LOF |
| 2026-05-18 | 22.493 | +2.86 | ⬆️ PIC 🟡 MODÉRÉ | Z+IQR+IFo+LOF |

### SPAM% (3 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2025-07-28 | 11.274 | +3.08 | ⬆️ PIC 🟠 FORT | Z+IQR+IFo+LOF |
| 2026-05-18 | 11.700 | +3.34 | ⬆️ PIC 🟠 FORT | Z+IQR+IFo+LOF |
| 2026-06-08 | 3.408 | -1.72 | ⬇️ CREUX 🟡 MODÉRÉ | IFo+LOF |

### L3 UDP% (3 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2025-10-13 | 46.156 | -2.07 | ⬇️ CREUX 🟡 MODÉRÉ | IFo+LOF |
| 2026-03-09 | 39.167 | -2.59 | ⬇️ CREUX 🟡 MODÉRÉ | Z+IFo+LOF |
| 2026-04-06 | 98.933 | +1.86 | ⬆️ PIC 🟡 MODÉRÉ | IFo+LOF |

### BGP RPKI inv% (2 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2025-12-29 | 50.702 | -1.85 | ⬇️ CREUX 🟡 MODÉRÉ | IFo+LOF |
| 2026-03-02 | 49.950 | -2.09 | ⬇️ CREUX 🟡 MODÉRÉ | IFo+LOF |

### DNS qualité (2 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2025-06-09 | 0.582 | -1.49 | ⬇️ CREUX 🟡 MODÉRÉ | IFo+LOF |
| 2025-06-16 | 0.581 | -1.50 | ⬇️ CREUX 🟡 MODÉRÉ | IFo+LOF |

### DMARC PASS% (2 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2025-07-28 | 83.712 | -2.13 | ⬇️ CREUX 🟡 MODÉRÉ | IFo+LOF |
| 2026-05-18 | 79.225 | -4.40 | ⬇️ CREUX 🔴 EXTRÊME | Z+IQR+IFo+LOF |

### MALICIOUS% (2 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2026-05-25 | 27.878 | +2.62 | ⬆️ PIC 🟡 MODÉRÉ | Z+IFo |
| 2026-06-01 | 31.457 | +3.17 | ⬆️ PIC 🟠 FORT | Z+IQR+IFo+LOF |

### IPv6% (2 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2025-06-23 | 17.311 | -2.50 | ⬇️ CREUX 🟡 MODÉRÉ | Z+IFo |
| 2025-12-29 | 21.158 | +1.40 | ⬆️ PIC 🟡 MODÉRÉ | IFo+LOF |

### TLS 1.3% (2 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2025-12-08 | 68.770 | +1.96 | ⬆️ PIC 🟡 MODÉRÉ | IFo+LOF |
| 2025-12-15 | 68.619 | +1.85 | ⬆️ PIC 🟡 MODÉRÉ | IFo+LOF |

### L3 haut vol.% (2 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2025-11-17 | 94.998 | +3.33 | ⬆️ PIC 🟠 FORT | Z+IQR+IFo+LOF |
| 2026-06-01 | 71.014 | +2.12 | ⬆️ PIC 🟡 MODÉRÉ | IFo+LOF |

### BGP conf. moy. (1 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2026-03-02 | 5.307 | -3.10 | ⬇️ CREUX 🟠 FORT | Z+IQR+IFo+LOF |

### BGP leaks count (1 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2026-06-08 | 342.000 | -3.53 | ⬇️ CREUX 🟠 FORT | Z+IQR+LOF |

### DKIM PASS% (1 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2025-07-28 | 84.124 | -2.91 | ⬇️ CREUX 🟡 MODÉRÉ | Z+IQR+IFo+LOF |

### SPF PASS% (1 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2026-02-16 | 82.417 | +1.53 | ⬆️ PIC 🟡 MODÉRÉ | IFo+LOF |

### Bot rate% (1 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2025-11-10 | 16.727 | -2.20 | ⬇️ CREUX 🟡 MODÉRÉ | IFo+LOF |

### L3 TCP% (1 anomalies consensus)

| Date | Valeur | Z-score | Type | Méthodes |
|---|---:|---:|---|---|
| 2026-03-09 | 60.768 | +2.64 | ⬆️ PIC 🟡 MODÉRÉ | Z+IFo+LOF |

---
## 4. Coïncidences d'Anomalies Multi-Domaines

> Semaines où ≥ 2 séries de domaines DIFFÉRENTS sont simultanément anormales.
> Total : **10** semaines critiques.

| Semaine | Nb domaines | Séries anormales |
|---|---:|---|
| 2026-05-18 | **6** | BGP volume msgs · DMARC PASS% · DMARC FAIL% · SPF FAIL% · SPAM% · SPOOF%  |
| 2025-07-28 | **4** | DMARC PASS% · DMARC FAIL% · DKIM PASS% · SPAM%  |
| 2026-06-01 | **4** | BGP volume msgs · SPOOF% · MALICIOUS% · L3 haut vol.%  |
| 2026-03-02 | **4** | BGP hijacks count · BGP conf. moy. · BGP RPKI inv% · SPF FAIL%  |
| 2026-06-08 | **4** | BGP volume msgs · BGP hijacks count · BGP leaks count · SPAM%  |
| 2025-06-23 | **2** | SPOOF% · IPv6%  |
| 2026-03-09 | **2** | L3 UDP% · L3 TCP%  |
| 2026-02-16 | **2** | DMARC FAIL% · SPF PASS%  |
| 2025-12-29 | **2** | BGP RPKI inv% · IPv6%  |
| 2026-05-25 | **2** | SPOOF% · MALICIOUS%  |

### 4.1 Corrélation entre Séries Anomaliques (Jaccard)

> Jaccard(A,B) = |A∩B| / |A∪B| : proportion de semaines où A et B sont TOUTES DEUX anormales.

| Rang | Série A | Série B | Semaines communes | Jaccard |
|---:|---|---|---:|---:|
| 1 | DMARC PASS% | DMARC FAIL% | 2 | 0.667 |
| 2 | DMARC PASS% | SPAM% | 2 | 0.667 |
| 3 | BGP volume msgs | SPAM% | 2 | 0.500 |
| 4 | DMARC FAIL% | SPAM% | 2 | 0.500 |
| 5 | SPOOF% | MALICIOUS% | 2 | 0.500 |
| 6 | BGP volume msgs | SPOOF% | 2 | 0.400 |
| 7 | BGP RPKI inv% | IPv6% | 1 | 0.333 |
| 8 | MALICIOUS% | L3 haut vol.% | 1 | 0.333 |
| 9 | BGP volume msgs | DMARC PASS% | 1 | 0.250 |
| 10 | BGP volume msgs | MALICIOUS% | 1 | 0.250 |
| 11 | BGP volume msgs | L3 haut vol.% | 1 | 0.250 |
| 12 | BGP hijacks count | BGP RPKI inv% | 1 | 0.250 |
| 13 | BGP RPKI inv% | SPF FAIL% | 1 | 0.250 |
| 14 | DMARC PASS% | SPF FAIL% | 1 | 0.250 |
| 15 | BGP volume msgs | BGP hijacks count | 1 | 0.200 |
| 16 | BGP volume msgs | DMARC FAIL% | 1 | 0.200 |
| 17 | BGP volume msgs | SPF FAIL% | 1 | 0.200 |
| 18 | BGP hijacks count | SPF FAIL% | 1 | 0.200 |
| 19 | BGP hijacks count | SPAM% | 1 | 0.200 |
| 20 | DMARC PASS% | SPOOF% | 1 | 0.200 |

---
## 5. Pays à Profil Anomalique (Isolation Forest)

> Isolation Forest sur 4 features (IPv6, HTTP/3, TLS1.3, Bot%) — contamination 7%.
> 18 pays identifiés comme outliers sur 247 pays analysés.

| Rang | ISO2 | Pays | IPv6% | HTTP/3% | TLS1.3% | Bot% | IMP | Z max | Anomalie principale |
|---:|---|---|---:|---:|---:|---:|---:|---:|---|
| 1 | GI | Gibraltar | 0.2 | 2.8 | 94.1 | 90.7 | 22.4 | 4.94 | ⬆️ bot extrême (z=+4.9) |
| 2 | AQ | AQ | 42.9 | 1.4 | 95.4 | 72.6 | 38.4 | 4.38 | ⬆️ TLSv1.3 extrême (z=+4.4) |
| 3 | CX | CX | 98.1 | 0.0 | 82.0 | 63.9 | 51.8 | 4.05 | ⬆️ IPv6 extrême (z=+4.0) |
| 4 | TF | TF | 98.0 | 0.6 | 80.7 | 54.2 | 54.5 | 4.04 | ⬆️ IPv6 extrême (z=+4.0) |
| 5 | IR | Iran | 3.1 | 2.8 | 92.7 | 76.5 | 27.1 | 3.98 | ⬆️ TLSv1.3 extrême (z=+4.0) |
| 6 | TM | Turkménistan | 0.0 | 35.3 | 62.8 | 75.3 | 28.8 | 3.86 | ⬆️ bot extrême (z=+3.9) |
| 7 | UM | UM | 93.6 | 24.3 | 62.7 | 40.8 | 59.8 | 3.82 | ⬆️ IPv6 extrême (z=+3.8) |
| 8 | SG | Singapour | 6.6 | 6.9 | 78.4 | 74.0 | 26.9 | 3.77 | ⬆️ bot extrême (z=+3.8) |
| 9 | KP | Corée du Nord | 73.3 | 5.4 | 90.6 | 71.7 | 46.3 | 3.67 | ⬆️ TLSv1.3 extrême (z=+3.7) |
| 10 | IE | IE | 10.2 | 8.2 | 70.3 | 70.1 | 27.7 | 3.49 | ⬆️ bot extrême (z=+3.5) |
| 11 | GS | GS | 81.6 | 0.6 | 73.3 | 35.8 | 54.5 | 3.23 | ⬇️ HTTP/3 extrême (z=-3.2) |
| 12 | CC | CC | 78.6 | 0.9 | 87.3 | 65.6 | 47.6 | 3.20 | ⬇️ HTTP/3 extrême (z=-3.2) |
| 13 | PN | PN | 80.4 | 29.7 | 56.3 | 25.8 | 61.1 | 3.13 | ⬆️ IPv6 extrême (z=+3.1) |
| 14 | EH | EH | 69.4 | 2.5 | 69.1 | 33.7 | 51.7 | 2.99 | ⬇️ HTTP/3 extrême (z=-3.0) |
| 15 | HK | Hong Kong | 3.7 | 9.7 | 80.4 | 55.8 | 32.7 | 2.49 | ⬆️ bot extrême (z=+2.5) |
| 16 | IM | IM | 8.6 | 13.6 | 49.9 | 54.3 | 29.2 | 2.45 | ⬇️ TLSv1.3 extrême (z=-2.4) |
| 17 | IO | IO | 33.0 | 14.6 | 50.0 | 9.7 | 49.0 | 2.44 | ⬇️ TLSv1.3 extrême (z=-2.4) |
| 18 | ER | ER | 57.3 | 8.6 | 74.1 | 17.3 | 56.1 | 2.20 | ⬇️ HTTP/3 extrême (z=-2.2) |

---
## 6. Chronologie des Anomalies (Timeline)

> Toutes les anomalies consensus classées chronologiquement.

| Date | Domaine | Série | Z-score | Dir. |
|---|---|---|---:|---|
| 2025-06-09 | DNS | DNS qualité | -1.49 | ⬇️ |
| 2025-06-16 | DNS | DNS qualité | -1.50 | ⬇️ |
| 2025-06-23 | Email | SPOOF% | -1.29 | ⬇️ |
| 2025-06-23 | HTTP/Protocol | IPv6% | -2.50 | ⬇️ |
| 2025-07-28 | Email | DMARC PASS% | -2.13 | ⬇️ |
| 2025-07-28 | Email | DMARC FAIL% | +2.24 | ⬆️ |
| 2025-07-28 | Email | DKIM PASS% | -2.91 | ⬇️ |
| 2025-07-28 | Email | SPAM% | +3.08 | ⬆️ |
| 2025-09-15 | Email | SPF FAIL% | +2.38 | ⬆️ |
| 2025-10-13 | L3 Attacks | L3 UDP% | -2.07 | ⬇️ |
| 2025-11-10 | HTTP/Protocol | Bot rate% | -2.20 | ⬇️ |
| 2025-11-17 | L3 Attacks | L3 haut vol.% | +3.33 | ⬆️ |
| 2025-12-01 | BGP | BGP hijacks count | -2.36 | ⬇️ |
| 2025-12-08 | HTTP/Protocol | TLS 1.3% | +1.96 | ⬆️ |
| 2025-12-15 | HTTP/Protocol | TLS 1.3% | +1.85 | ⬆️ |
| 2025-12-29 | BGP | BGP RPKI inv% | -1.85 | ⬇️ |
| 2025-12-29 | HTTP/Protocol | IPv6% | +1.40 | ⬆️ |
| 2026-02-16 | Email | DMARC FAIL% | -1.17 | ⬇️ |
| 2026-02-16 | Email | SPF PASS% | +1.53 | ⬆️ |
| 2026-03-02 | BGP | BGP hijacks count | +1.88 | ⬆️ |
| 2026-03-02 | BGP | BGP conf. moy. | -3.10 | ⬇️ |
| 2026-03-02 | BGP | BGP RPKI inv% | -2.09 | ⬇️ |
| 2026-03-02 | Email | SPF FAIL% | -1.53 | ⬇️ |
| 2026-03-09 | L3 Attacks | L3 UDP% | -2.59 | ⬇️ |
| 2026-03-09 | L3 Attacks | L3 TCP% | +2.64 | ⬆️ |
| 2026-04-06 | L3 Attacks | L3 UDP% | +1.86 | ⬆️ |
| 2026-05-18 | BGP | BGP volume msgs | +2.20 | ⬆️ |
| 2026-05-18 | Email | DMARC PASS% | -4.40 | ⬇️ |
| 2026-05-18 | Email | DMARC FAIL% | +4.63 | ⬆️ |
| 2026-05-18 | Email | SPF FAIL% | +2.86 | ⬆️ |
| 2026-05-18 | Email | SPAM% | +3.34 | ⬆️ |
| 2026-05-18 | Email | SPOOF% | +3.38 | ⬆️ |
| 2026-05-25 | Email | SPOOF% | +2.52 | ⬆️ |
| 2026-05-25 | Email | MALICIOUS% | +2.62 | ⬆️ |
| 2026-06-01 | BGP | BGP volume msgs | +4.71 | ⬆️ |
| 2026-06-01 | Email | SPOOF% | +2.89 | ⬆️ |
| 2026-06-01 | Email | MALICIOUS% | +3.17 | ⬆️ |
| 2026-06-01 | L3 Attacks | L3 haut vol.% | +2.12 | ⬆️ |
| 2026-06-08 | BGP | BGP volume msgs | -2.03 | ⬇️ |
| 2026-06-08 | BGP | BGP hijacks count | -3.45 | ⬇️ |
| 2026-06-08 | BGP | BGP leaks count | -3.53 | ⬇️ |
| 2026-06-08 | Email | SPAM% | -1.72 | ⬇️ |

---
## 7. Findings et Implications

### 7.1 Anomalies Temporelles les Plus Critiques

**10 semaines** présentent des anomalies simultanées sur ≥ 2 domaines. Les plus critiques :

- **2026-05-18** : 6 domaines anormaux (BGP volume msgs, DMARC PASS%, DMARC FAIL%, SPF FAIL%...)
- **2025-07-28** : 4 domaines anormaux (DMARC PASS%, DMARC FAIL%, DKIM PASS%, SPAM%...)
- **2026-06-01** : 4 domaines anormaux (BGP volume msgs, SPOOF%, MALICIOUS%, L3 haut vol.%...)
- **2026-03-02** : 4 domaines anormaux (BGP hijacks count, BGP conf. moy., BGP RPKI inv%, SPF FAIL%...)
- **2026-06-08** : 4 domaines anormaux (BGP volume msgs, BGP hijacks count, BGP leaks count, SPAM%...)

### 7.2 Séries à Surveillance Prioritaire

1. **SPOOF%** : 4 anomalies consensus sur la période
2. **BGP volume msgs** : 3 anomalies consensus sur la période
3. **BGP hijacks count** : 3 anomalies consensus sur la période
4. **DMARC FAIL%** : 3 anomalies consensus sur la période
5. **SPF FAIL%** : 3 anomalies consensus sur la période

### 7.3 Pays à Profil Extrême

18 pays sur 247 ont un profil protocolaire statistiquement anormal.
Le pays le plus extrême : **GI** (Z max = 4.94)

### 7.4 Implications pour la Surveillance

1. **Méthode consensus** : La combinaison Z-score + IQR + Isolation Forest + LOF réduit les faux positifs et identifie les anomalies robustes.

2. **Anomalies simultanées** : Les semaines avec anomalies multi-domaines sont des signaux d'alerte systémiques — elles indiquent une dégradation coordonnée de la sécurité internet.

3. **Pays extrêmes** : Les outliers pays ne sont pas nécessairement des menaces — certains (ex. Gibraltar) ont des profils extrêmes dus à leur structure économique (finance offshore, CDN).

4. **Utilité opérationnelle** : Ce catalogue d'anomalies peut alimenter un tableau de bord de surveillance en temps réel — chaque indicateur peut déclencher une alerte dès qu'il passe au-dessus du seuil Z=2.5.

---
*Rapport généré automatiquement par `phase_J_anomalies.py` le 2026-06-16 22:20:28.*  
*Sources : Cloudflare Radar API v4 — 25 datasets nettoyés.*  
*Prochaine étape : Phase K — Analyse de graphe réseau (ASN network).*