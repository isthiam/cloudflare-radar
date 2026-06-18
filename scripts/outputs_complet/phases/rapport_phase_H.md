# Rapport Phase H — Corrélations Inter-Domaines
**Cloudflare Radar Dataset — Juin 2025 / Juin 2026**  
**Auteur :** Issakha Thiam  
**Généré le :** 2026-06-16 16:57:47

---
## 1. Résumé Exécutif

Cette phase analyse les **corrélations temporelles entre 8 domaines** de sécurité Internet :

| Domaine | Variables clé | Période |
|---|---|---|
| **BGP Hijacks** | 4 variables | Déc 2025 – Juin 2026 |
| **BGP Leaks** | 2 variables | Mar 2026 – Juin 2026 |
| **BGP Volume** | 1 variables | Juin 2025 – Juin 2026 |
| **DNS Quality** | 1 variables | Juin 2025 – Juin 2026 |
| **Email Security** | 9 variables | Juin 2025 – Juin 2026 |
| **HTTP/Protocol** | 6 variables | Juin 2025 – Juin 2026 |
| **L3 Attacks** | 3 variables | Juin 2025 – Juin 2026 |
| **L7 Attacks** | 6 variables | Mar 2026 – Juin 2026 |
| **IVC** | 5 variables | Juin 2025 – Juin 2026 |

**Matrice de corrélation :** 29 variables × 29 variables
**Paires inter-domaines significatives (p<0.05) :** 40
**Causalités Granger significatives :** 4/10

---
## 2. Tendances Temporelles par Domaine

> Résumé Mann-Kendall τ pour chaque variable clé.

### 2.1 BGP Hijacks

| Variable | N semaines | τ Mann-Kendall | p-value | Tendance |
|---|---:|---:|---:|---|
| BGP hij. count | 28 | -0.0132 | 0.9213  | stable (n.s.) |
| BGP hij. conf. | 28 | 0.2751 | 0.0411 ✅ | ↑ hausse modérée (τ=0.28) |
| BGP RPKI inv% | 28 | 0.3862 | 0.0035 ✅ | ↑ hausse forte (τ=0.39) |
| BGP sévérité | 28 | 0.1481 | 0.2800  | stable (n.s.) |

### 2.2 BGP Leaks

| Variable | N semaines | τ Mann-Kendall | p-value | Tendance |
|---|---:|---:|---:|---|
| BGP leaks count | 15 | 0.0095 | 1.0000  | stable (n.s.) |
| bgp_leaks_countries | 0 | N/A | N/A  | stable (n.s.) |

### 2.3 BGP Volume

| Variable | N semaines | τ Mann-Kendall | p-value | Tendance |
|---|---:|---:|---:|---|
| BGP volume msgs | 53 | 0.3237 | 0.0006 ✅ | ↑ hausse forte (τ=0.32) |

### 2.4 DNS Quality

| Variable | N semaines | τ Mann-Kendall | p-value | Tendance |
|---|---:|---:|---:|---|
| DNS qualité | 52 | 0.8477 | 0.0000 ✅ | ↑ hausse forte (τ=0.85) |

### 2.5 Email Security

| Variable | N semaines | τ Mann-Kendall | p-value | Tendance |
|---|---:|---:|---:|---|
| DMARC PASS% | 53 | 0.0769 | 0.4162  | stable (n.s.) |
| DMARC FAIL% | 53 | -0.0247 | 0.7942  | stable (n.s.) |
| DKIM PASS% | 53 | 0.2525 | 0.0076 ✅ | ↑ hausse modérée (τ=0.25) |
| SPF PASS% | 53 | 0.3701 | 0.0001 ✅ | ↑ hausse forte (τ=0.37) |
| SPF FAIL% | 53 | -0.4238 | 0.0000 ✅ | ↓ baisse forte (τ=-0.42) |
| SPAM% | 53 | -0.4383 | 0.0000 ✅ | ↓ baisse forte (τ=-0.44) |
| SPOOF% | 53 | 0.6328 | 0.0000 ✅ | ↑ hausse forte (τ=0.63) |
| MALICIOUS% | 53 | 0.7271 | 0.0000 ✅ | ↑ hausse forte (τ=0.73) |
| ISE (email sec.) | 53 | -0.2235 | 0.0181 ✅ | ↓ baisse modérée (τ=-0.22) |

### 2.6 HTTP/Protocol

| Variable | N semaines | τ Mann-Kendall | p-value | Tendance |
|---|---:|---:|---:|---|
| IPv6% | 53 | 0.5385 | 0.0000 ✅ | ↑ hausse forte (τ=0.54) |
| HTTP/3% | 53 | 0.3425 | 0.0003 ✅ | ↑ hausse forte (τ=0.34) |
| TLS 1.3% | 53 | 0.0450 | 0.6344  | stable (n.s.) |
| Bot rate% | 53 | 0.2583 | 0.0063 ✅ | ↑ hausse modérée (τ=0.26) |
| mobile | 0 | N/A | N/A  | stable (n.s.) |
| IMP (protocol) | 53 | 0.3106 | 0.0010 ✅ | ↑ hausse forte (τ=0.31) |

### 2.7 L3 Attacks

| Variable | N semaines | τ Mann-Kendall | p-value | Tendance |
|---|---:|---:|---:|---|
| L3 UDP% | 53 | 0.2293 | 0.0154 ✅ | ↑ hausse modérée (τ=0.23) |
| L3 TCP% | 53 | -0.2061 | 0.0294 ✅ | ↓ baisse modérée (τ=-0.21) |
| L3 haut vol.% | 53 | 0.3033 | 0.0013 ✅ | ↑ hausse forte (τ=0.30) |

### 2.8 L7 Attacks

| Variable | N semaines | τ Mann-Kendall | p-value | Tendance |
|---|---:|---:|---:|---|
| L7 Internet&Télécom | 13 | 0.5897 | 0.0043 ✅ | ↑ hausse forte (τ=0.59) |
| L7 Informatique | 13 | -0.2308 | 0.3062  | stable (n.s.) |
| l7_finance | 0 | N/A | N/A  | stable (n.s.) |
| l7_gambling | 0 | N/A | N/A  | stable (n.s.) |
| L7 GET% | 13 | -0.3846 | 0.0763  | stable (n.s.) |
| L7 POST% | 13 | 0.4359 | 0.0422 ✅ | ↑ hausse forte (τ=0.44) |

### 2.9 IVC

| Variable | N semaines | τ Mann-Kendall | p-value | Tendance |
|---|---:|---:|---:|---|
| IVC (vulnérabilité) | 13 | 0.6154 | 0.0027 ✅ | ↑ hausse forte (τ=0.62) |
| bgp_risk | 0 | N/A | N/A  | stable (n.s.) |
| email_threat | 0 | N/A | N/A  | stable (n.s.) |
| proto_weakness | 0 | N/A | N/A  | stable (n.s.) |
| net_attack | 0 | N/A | N/A  | stable (n.s.) |

---
## 3. Matrice de Corrélation Spearman Inter-Domaines

> ✅ p < 0.05 | ⚠️ p < 0.10 | r > 0 = corrélation positive | r < 0 = inverse
> Seules les corrélations inter-domaines sont incluses ici.

### 3.1 Top 40 Corrélations Inter-Domaines (|r| décroissant)

| Rang | Variable 1 | Domaine 1 | Variable 2 | Domaine 2 | r Spearman | p-value | Sig. |
|---:|---|---|---|---|---:|---:|---|
| 1 | SPOOF% | Email Security | IVC (vulnérabilité) | IVC | 0.8516 ↑↑ | 0.0002 | ✅ |
| 2 | L3 haut vol.% | L3 Attacks | IVC (vulnérabilité) | IVC | 0.8407 ↑↑ | 0.0003 | ✅ |
| 3 | MALICIOUS% | Email Security | IVC (vulnérabilité) | IVC | 0.8352 ↑↑ | 0.0004 | ✅ |
| 4 | DNS qualité | DNS Quality | MALICIOUS% | Email Security | 0.8224 ↑↑ | 0.0000 | ✅ |
| 5 | BGP hij. conf. | BGP Hijacks | IVC (vulnérabilité) | IVC | 0.8132 ↑↑ | 0.0007 | ✅ |
| 6 | ISE (email sec.) | Email Security | L7 POST% | L7 Attacks | -0.7912 ↑↓ | 0.0013 | ✅ |
| 7 | ISE (email sec.) | Email Security | L7 GET% | L7 Attacks | 0.7857 ↑↑ | 0.0015 | ✅ |
| 8 | DMARC PASS% | Email Security | L7 GET% | L7 Attacks | 0.7802 ↑↑ | 0.0017 | ✅ |
| 9 | TLS 1.3% | HTTP/Protocol | L7 POST% | L7 Attacks | 0.7692 ↑↑ | 0.0021 | ✅ |
| 10 | DMARC PASS% | Email Security | L7 POST% | L7 Attacks | -0.7637 ↑↓ | 0.0024 | ✅ |
| 11 | DNS qualité | DNS Quality | SPOOF% | Email Security | 0.7382 ↑↑ | 0.0000 | ✅ |
| 12 | BGP RPKI inv% | BGP Hijacks | L7 Internet&Télécom | L7 Attacks | 0.7363 ↑↑ | 0.0041 | ✅ |
| 13 | MALICIOUS% | Email Security | L7 POST% | L7 Attacks | 0.7253 ↑↑ | 0.0050 | ✅ |
| 14 | DMARC FAIL% | Email Security | L7 Informatique | L7 Attacks | 0.7198 ↑↑ | 0.0055 | ✅ |
| 15 | SPOOF% | Email Security | L7 POST% | L7 Attacks | 0.7088 ↑↑ | 0.0067 | ✅ |
| 16 | ISE (email sec.) | Email Security | IVC (vulnérabilité) | IVC | -0.7088 ↑↓ | 0.0067 | ✅ |
| 17 | DNS qualité | DNS Quality | IPv6% | HTTP/Protocol | 0.7083 ↑↑ | 0.0000 | ✅ |
| 18 | MALICIOUS% | Email Security | L7 GET% | L7 Attacks | -0.6923 ↑↓ | 0.0087 | ✅ |
| 19 | SPOOF% | Email Security | L7 GET% | L7 Attacks | -0.6868 ↑↓ | 0.0095 | ✅ |
| 20 | TLS 1.3% | HTTP/Protocol | L7 GET% | L7 Attacks | -0.6868 ↑↓ | 0.0095 | ✅ |
| 21 | DNS qualité | DNS Quality | IVC (vulnérabilité) | IVC | 0.6783 ↑↑ | 0.0153 | ✅ |
| 22 | IPv6% | HTTP/Protocol | IVC (vulnérabilité) | IVC | -0.6758 ↑↓ | 0.0112 | ✅ |
| 23 | BGP hij. conf. | BGP Hijacks | L7 POST% | L7 Attacks | 0.6758 ↑↑ | 0.0112 | ✅ |
| 24 | BGP volume msgs | BGP Volume | IVC (vulnérabilité) | IVC | 0.6648 ↑↑ | 0.0132 | ✅ |
| 25 | MALICIOUS% | Email Security | IPv6% | HTTP/Protocol | 0.6641 ↑↑ | 0.0000 | ✅ |
| 26 | BGP sévérité | BGP Hijacks | BGP leaks count | BGP Leaks | 0.6607 ↑↑ | 0.0073 | ✅ |
| 27 | SPF PASS% | Email Security | HTTP/3% | HTTP/Protocol | 0.6593 ↑↑ | 0.0000 | ✅ |
| 28 | L3 haut vol.% | L3 Attacks | BGP leaks count | BGP Leaks | 0.6500 ↑↑ | 0.0087 | ✅ |
| 29 | BGP hij. count | BGP Hijacks | L7 Internet&Télécom | L7 Attacks | -0.6484 ↑↓ | 0.0165 | ✅ |
| 30 | HTTP/3% | HTTP/Protocol | L7 Informatique | L7 Attacks | 0.6429 ↑↑ | 0.0178 | ✅ |
| 31 | HTTP/3% | HTTP/Protocol | BGP leaks count | BGP Leaks | 0.6214 ↑↑ | 0.0134 | ✅ |
| 32 | HTTP/3% | HTTP/Protocol | IVC (vulnérabilité) | IVC | 0.6209 ↑↑ | 0.0235 | ✅ |
| 33 | BGP RPKI inv% | BGP Hijacks | IVC (vulnérabilité) | IVC | 0.6209 ↑↑ | 0.0235 | ✅ |
| 34 | BGP RPKI inv% | BGP Hijacks | L7 POST% | L7 Attacks | 0.6154 ↑↑ | 0.0252 | ✅ |
| 35 | SPOOF% | Email Security | IPv6% | HTTP/Protocol | 0.6118 ↑↑ | 0.0000 | ✅ |
| 36 | BGP hij. conf. | BGP Hijacks | L7 GET% | L7 Attacks | -0.6099 ↑↓ | 0.0269 | ✅ |
| 37 | Bot rate% | HTTP/Protocol | L7 Informatique | L7 Attacks | -0.6044 ↑↓ | 0.0287 | ✅ |
| 38 | DNS qualité | DNS Quality | SPF FAIL% | Email Security | -0.6031 ↑↓ | 0.0000 | ✅ |
| 39 | IMP (protocol) | HTTP/Protocol | L7 POST% | L7 Attacks | 0.5934 ↑↑ | 0.0325 | ✅ |
| 40 | BGP hij. count | BGP Hijacks | L7 Informatique | L7 Attacks | 0.5879 ↑↑ | 0.0346 | ✅ |

### 3.2 Top Corrélations Intra-Domaine Clés

| Rang | Variable 1 | Variable 2 | Domaine | r Spearman | p-value |
|---:|---|---|---|---:|---:|
| 1 | L7 GET% | L7 POST% | L7 Attacks | -0.9890 | 0.0000 |
| 2 | L3 UDP% | L3 TCP% | L3 Attacks | -0.9579 | 0.0000 |
| 3 | SPOOF% | MALICIOUS% | Email Security | 0.9205 | 0.0000 |
| 4 | DMARC PASS% | DKIM PASS% | Email Security | 0.8302 | 0.0000 |
| 5 | SPF PASS% | SPF FAIL% | Email Security | -0.7875 | 0.0000 |
| 6 | DKIM PASS% | SPF PASS% | Email Security | 0.7375 | 0.0000 |
| 7 | DMARC PASS% | ISE (email sec.) | Email Security | 0.7288 | 0.0000 |
| 8 | BGP hij. conf. | BGP RPKI inv% | BGP Hijacks | 0.7132 | 0.0000 |
| 9 | SPF PASS% | SPAM% | Email Security | -0.7028 | 0.0000 |
| 10 | TLS 1.3% | Bot rate% | HTTP/Protocol | -0.6726 | 0.0000 |
| 11 | DKIM PASS% | SPAM% | Email Security | -0.6525 | 0.0000 |
| 12 | DMARC PASS% | SPF PASS% | Email Security | 0.6428 | 0.0000 |
| 13 | SPF FAIL% | MALICIOUS% | Email Security | -0.6410 | 0.0000 |
| 14 | SPOOF% | ISE (email sec.) | Email Security | -0.6408 | 0.0000 |
| 15 | DKIM PASS% | ISE (email sec.) | Email Security | 0.6103 | 0.0000 |
| 16 | L7 Internet&Télécom | L7 POST% | L7 Attacks | 0.5989 | 0.0306 |
| 17 | L7 Internet&Télécom | L7 GET% | L7 Attacks | -0.5989 | 0.0306 |
| 18 | TLS 1.3% | IMP (protocol) | HTTP/Protocol | 0.5952 | 0.0000 |
| 19 | HTTP/3% | Bot rate% | HTTP/Protocol | 0.5841 | 0.0000 |
| 20 | DMARC PASS% | SPAM% | Email Security | -0.5733 | 0.0000 |
| 21 | DKIM PASS% | SPF FAIL% | Email Security | -0.5604 | 0.0000 |
| 22 | DMARC FAIL% | SPF FAIL% | Email Security | 0.5561 | 0.0000 |
| 23 | IPv6% | IMP (protocol) | HTTP/Protocol | 0.5416 | 0.0000 |
| 24 | SPF FAIL% | SPAM% | Email Security | 0.5403 | 0.0000 |
| 25 | SPF FAIL% | SPOOF% | Email Security | -0.5052 | 0.0001 |

---
## 4. Analyse CCF — Structure de Lag Inter-Domaines

> CCF(lag) : corrélation croisée à décalage t. Lag positif = v1 précède v2.

### BGP hijacks → MALICIOUS emails

| Lag (semaines) | CCF | Interprétation |
|---:|---:|---|
| 0 | -0.1096 | faible |
| 1 | -0.4939 | modéré négatif à lag 1w |
| 2 | -0.4269 | modéré négatif à lag 2w |
| 3 | -0.3801 | modéré négatif à lag 3w |
| 4 | -0.3100 | modéré négatif à lag 4w |
| 5 | -0.3380 | modéré négatif à lag 5w |

> **Pic CCF :** lag=1 semaines, r=-0.4939

### BGP hijacks → SPOOF emails

| Lag (semaines) | CCF | Interprétation |
|---:|---:|---|
| 0 | -0.0810 | faible |
| 1 | -0.4911 | modéré négatif à lag 1w |
| 2 | -0.4430 | modéré négatif à lag 2w |
| 3 | -0.5059 | fort négatif à lag 3w |
| 4 | -0.2698 | modéré négatif à lag 4w |
| 5 | -0.2686 | modéré négatif à lag 5w |

> **Pic CCF :** lag=3 semaines, r=-0.5059

### BGP hijacks → DNS qualité

| Lag (semaines) | CCF | Interprétation |
|---:|---:|---|
| 0 | 0.1175 | faible |
| 1 | -0.0112 | faible |
| 2 | -0.0028 | faible |
| 3 | 0.0124 | faible |
| 4 | -0.1259 | faible |
| 5 | -0.2637 | modéré négatif à lag 5w |

> **Pic CCF :** lag=5 semaines, r=-0.2637

### BGP hijacks → L3 UDP

| Lag (semaines) | CCF | Interprétation |
|---:|---:|---|
| 0 | -0.1380 | faible |
| 1 | -0.1676 | faible |
| 2 | -0.1236 | faible |
| 3 | -0.1857 | faible |
| 4 | -0.3344 | modéré négatif à lag 4w |
| 5 | -0.3136 | modéré négatif à lag 5w |

> **Pic CCF :** lag=4 semaines, r=-0.3344

### SPOOF → MALICIOUS (cross-validation)

| Lag (semaines) | CCF | Interprétation |
|---:|---:|---|
| 0 | 0.9679 | fort positif à lag 0w |
| 1 | 0.8284 | fort positif à lag 1w |
| 2 | 0.7118 | fort positif à lag 2w |
| 3 | 0.6171 | fort positif à lag 3w |
| 4 | 0.5177 | fort positif à lag 4w |
| 5 | 0.4675 | modéré positif à lag 5w |

> **Pic CCF :** lag=0 semaines, r=0.9679

### DNS qualité → Sécurité email

| Lag (semaines) | CCF | Interprétation |
|---:|---:|---|
| 0 | -0.2950 | modéré négatif à lag 0w |
| 1 | -0.2385 | faible |
| 2 | -0.1659 | faible |
| 3 | -0.0415 | faible |
| 4 | 0.0113 | faible |
| 5 | 0.0135 | faible |

> **Pic CCF :** lag=0 semaines, r=-0.2950

### L3 haut vol. → BGP hijacks

| Lag (semaines) | CCF | Interprétation |
|---:|---:|---|
| 0 | 0.0567 | faible |
| 1 | -0.0940 | faible |
| 2 | 0.1677 | faible |
| 3 | -0.0125 | faible |
| 4 | 0.0155 | faible |
| 5 | 0.0208 | faible |

> **Pic CCF :** lag=2 semaines, r=0.1677

### L3 UDP → BGP hijacks

| Lag (semaines) | CCF | Interprétation |
|---:|---:|---|
| 0 | -0.1380 | faible |
| 1 | -0.1865 | faible |
| 2 | -0.0242 | faible |
| 3 | 0.2438 | faible |
| 4 | 0.2141 | faible |
| 5 | 0.3103 | modéré positif à lag 5w |

> **Pic CCF :** lag=5 semaines, r=0.3103

### IVC → Sévérité BGP

*Données insuffisantes pour le calcul CCF.*

---
## 5. Causalité de Granger Inter-Domaines

> H0 : la cause n'améliore pas la prédiction de l'effet. p < 0.05 → rejeter H0 → causalité Granger.
> maxlag = 4 semaines. Test F (SSR).

| Relation causale | p_min (4 lags) | Résultat |
|---|---:|---|
| BGP hijacks → MALICIOUS | 0.0042 | ✅ SIGNIFICATIF |
| BGP hijacks → SPOOF | 0.0053 | ✅ SIGNIFICATIF |
| RPKI violations → DNS qualité | 0.0096 | ✅ SIGNIFICATIF |
| SPOOF → MALICIOUS | 0.0029 | ✅ SIGNIFICATIF |
| DNS qualité → SPOOF | 0.1659 | — non significatif |
| L3 volume → BGP hijacks | 0.3038 | — non significatif |
| MALICIOUS → L3 UDP | 0.3244 | — non significatif |
| BGP hijacks → L3 UDP | 0.4020 | — non significatif |
| L3 vol → SPOOF | 0.1286 | — non significatif |
| ISE → DNS qualité | 0.0910 | ⚠️ MARGINAL |

---
## 6. Coïncidences d'Anomalies Multi-Domaines

> Seuil |Z| ≥ 2.5. Variables surveillées : BGP hij. count, DNS qualité, SPOOF%, MALICIOUS%, ISE (email sec.), L3 UDP%, L3 haut vol.%, IVC (vulnérabilité), BGP sévérité

### 6.1 Semaines avec ≥ 2 Anomalies Simultanées

| Semaine | Nb domaines | Variables anormales |
|---|---:|---|
| 2026-05-18 | **2** | SPOOF%, ISE (email sec.) |
| 2026-05-25 | **2** | SPOOF%, MALICIOUS% |
| 2026-06-01 | **2** | SPOOF%, MALICIOUS% |

**Total : 3 semaine(s) avec anomalies simultanées sur ≥ 2 domaines.**

## 7. Index de Vulnérabilité Composite (IVC)

> **IVC** = 0.30×BGP_risk + 0.30×Email_threat + 0.20×Proto_weakness + 0.20×Net_attack  
> Chaque composante normalisée [0,1] → IVC ∈ [0,100].  
> Valeur haute = vulnérabilité Internet globale élevée.

### 7.1 Statistiques IVC

| Indicateur | Valeur |
|---|---:|
| Moyenne | 55.7 / 100 |
| Écart-type | 12.3 |
| Minimum | 37.1 (semaine la plus calme) |
| Maximum | 77.6 (semaine la plus critique) |
| Tendance Mann-Kendall τ | 0.6154 (p=0.0027) |
| Interprétation | ↑ hausse forte (τ=0.62) |

### 7.2 Top 15 Semaines Critiques (IVC le plus élevé)

| Rang | Semaine | IVC | BGP_risk | Email_threat | Proto_weakness | Net_attack |
|---:|---|---:|---:|---:|---:|---:|
| 1 | 2026-06-01 | **77.6** | 0.72 | 0.86 | 0.52 | 1.00 |
| 2 | 2026-05-18 | **75.3** | 0.87 | 1.00 | 0.23 | 0.73 |
| 3 | 2026-05-25 | **67.3** | 0.73 | 0.82 | 0.23 | 0.81 |
| 4 | 2026-05-04 | **59.0** | 0.94 | 0.50 | 0.29 | 0.51 |
| 5 | 2026-05-11 | **58.7** | 0.77 | 0.63 | 0.25 | 0.58 |
| 6 | 2026-04-27 | **56.2** | 0.85 | 0.57 | 0.35 | 0.33 |
| 7 | 2026-04-20 | **55.9** | 0.83 | 0.44 | 0.55 | 0.34 |
| 8 | 2026-04-13 | **54.7** | 0.76 | 0.33 | 0.67 | 0.44 |
| 9 | 2026-04-06 | **51.5** | 0.74 | 0.57 | 0.61 | 0.00 |
| 10 | 2026-03-30 | **44.4** | 0.74 | 0.24 | 0.43 | 0.31 |
| 11 | 2026-03-16 | **43.6** | 0.86 | 0.15 | 0.42 | 0.24 |
| 12 | 2026-03-23 | **43.0** | 0.76 | 0.22 | 0.46 | 0.21 |
| 13 | 2026-06-08 | **37.1** | 0.00 | 0.39 | 0.65 | 0.63 |

### 7.3 Évolution Hebdomadaire de l'IVC

| Semaine | IVC | Niveau |
|---|---:|---|
| 2026-03-16 | 43.6 | 🟡 MODÉRÉ |
| 2026-03-23 | 43.0 | 🟡 MODÉRÉ |
| 2026-03-30 | 44.4 | 🟡 MODÉRÉ |
| 2026-04-06 | 51.5 | 🟠 ÉLEVÉ |
| 2026-04-13 | 54.7 | 🟠 ÉLEVÉ |
| 2026-04-20 | 55.9 | 🟠 ÉLEVÉ |
| 2026-04-27 | 56.2 | 🟠 ÉLEVÉ |
| 2026-05-04 | 59.0 | 🟠 ÉLEVÉ |
| 2026-05-11 | 58.7 | 🟠 ÉLEVÉ |
| 2026-05-18 | 75.3 | 🔴 CRITIQUE |
| 2026-05-25 | 67.3 | 🟠 ÉLEVÉ |
| 2026-06-01 | 77.6 | 🔴 CRITIQUE |
| 2026-06-08 | 37.1 | 🟡 MODÉRÉ |

---
## 8. Interactions Clés Inter-Domaines

### 8.1 BGP ↔ Email

| Paire | r Spearman | p-value | Interprétation |
|---|---:|---:|---|
| BGP hijacks count → SPOOF | -0.3230 | 0.0937 | Non significatif |
| BGP hijacks count → MALICIOUS | -0.2732 | 0.1596 | Non significatif |
| RPKI violations → ISE | -0.2392 | 0.2203 | Non significatif |

### 8.2 BGP ↔ DNS

| Paire | r Spearman | p-value | Interprétation |
|---|---:|---:|---|
| BGP hijacks count → DNS qualité | 0.0827 | 0.6816 | Non significatif |
| BGP volume msgs → DNS qualité | 0.5179 | 0.0001 | Lien détecté ✅ |

### 8.3 Attaques L3/L7 ↔ BGP

| Paire | r Spearman | p-value | Interprétation |
|---|---:|---:|---|
| L3 haut volume → BGP hijacks | -0.0569 | 0.7735 | Non significatif |
| L3 UDP% → BGP hijacks | -0.1415 | 0.4726 | Non significatif |

### 8.4 Email ↔ DNS

| Paire | r Spearman | p-value | Interprétation |
|---|---:|---:|---|
| DNS qualité → ISE (email sec.) | -0.2076 | 0.1397 | Non significatif |
| DNS qualité → SPOOF | 0.7382 | 0.0000 | Lien détecté ✅ |

### 8.5 Protocole (IMP) ↔ Menaces

| Paire | r Spearman | p-value | Interprétation |
|---|---:|---:|---|
| IMP → BGP hijacks | 0.2201 | 0.2605 | Non significatif |
| IMP → SPOOF | 0.3400 | 0.0127 | Lien détecté ✅ |
| IPv6% → BGP hijacks | -0.0879 | 0.6566 | Non significatif |

---
## 9. Matrice Complète de Corrélation Spearman

> Cellules : r (✅ p<0.05, ⚠️ p<0.10, blanc=n.s.)

| Var | BGP_vol | DNS_q | DMARC+ | DMARC- | DKIM+ | SPF+ | SPF- | SPAM | SPOOF | MALIC | ISE | IPv6 | HTTP3 | TLS13 | BOT | IMP | L3UDP | L3TCP | L3HV | HIJ_n | HIJ_c | RPKI% | HIJ_sv | LK_n | L7IT | L7CE | L7GET | L7PST | IVC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| BGP_vol |  1.00  | +0.52✅ | -0.07 | -0.03 | +0.22 | +0.31✅ | -0.31✅ | -0.20 | +0.37✅ | +0.44✅ | -0.15 | +0.21 | +0.16 | +0.25⚠️ | -0.06 | +0.32✅ | +0.11 | -0.08 | +0.43✅ | +0.05 | +0.26 | +0.43✅ | +0.49✅ | +0.12 | +0.25 | -0.10 | -0.58✅ | +0.53⚠️ | +0.66✅ |
| DNS_q | +0.52✅ |  1.00  | +0.23⚠️ | -0.02 | +0.52✅ | +0.58✅ | -0.60✅ | -0.58✅ | +0.74✅ | +0.82✅ | -0.21 | +0.71✅ | +0.59✅ | +0.05 | +0.26⚠️ | +0.50✅ | +0.31✅ | -0.25⚠️ | +0.48✅ | +0.08 | +0.39✅ | +0.42✅ | +0.30 | +0.47⚠️ | +0.27 | -0.42 | -0.17 | +0.28 | +0.68✅ |
| DMARC+ | -0.07 | +0.23⚠️ |  1.00  | -0.45✅ | +0.83✅ | +0.64✅ | -0.44✅ | -0.57✅ | -0.14 | +0.04 | +0.73✅ | +0.10 | +0.33✅ | -0.39✅ | +0.25⚠️ | -0.14 | +0.05 | -0.02 | +0.03 | +0.26 | -0.08 | -0.04 | +0.02 | +0.20 | -0.51⚠️ | -0.27 | +0.78✅ | -0.76✅ | -0.25 |
| DMARC- | -0.03 | -0.02 | -0.45✅ |  1.00  | -0.33✅ | -0.26⚠️ | +0.56✅ | +0.15 | +0.01 | -0.13 | -0.43✅ | -0.19 | +0.22 | -0.28✅ | +0.41✅ | -0.30✅ | +0.26⚠️ | -0.26⚠️ | +0.14 | +0.03 | +0.29 | +0.31 | +0.37✅ | +0.25 | -0.14 | +0.72✅ | -0.27 | +0.26 | +0.24 |
| DKIM+ | +0.22 | +0.52✅ | +0.83✅ | -0.33✅ |  1.00  | +0.74✅ | -0.56✅ | -0.65✅ | +0.08 | +0.28✅ | +0.61✅ | +0.27⚠️ | +0.51✅ | -0.28✅ | +0.24⚠️ | +0.10 | +0.07 | -0.06 | +0.23⚠️ | +0.42✅ | -0.10 | +0.04 | +0.13 | +0.20 | -0.35 | +0.02 | +0.49⚠️ | -0.49⚠️ | -0.19 |
| SPF+ | +0.31✅ | +0.58✅ | +0.64✅ | -0.26⚠️ | +0.74✅ |  1.00  | -0.79✅ | -0.70✅ | +0.30✅ | +0.46✅ | +0.37✅ | +0.36✅ | +0.66✅ | -0.31✅ | +0.39✅ | +0.14 | +0.26⚠️ | -0.26⚠️ | +0.14 | +0.26 | +0.08 | +0.25 | +0.07 | +0.32 | -0.09 | -0.30 | +0.13 | -0.07 | +0.33 |
| SPF- | -0.31✅ | -0.60✅ | -0.44✅ | +0.56✅ | -0.56✅ | -0.79✅ |  1.00  | +0.54✅ | -0.51✅ | -0.64✅ | -0.16 | -0.57✅ | -0.41✅ | +0.02 | -0.05 | -0.44✅ | -0.11 | +0.10 | -0.10 | -0.38✅ | +0.24 | +0.04 | +0.22 | -0.15 | +0.13 | +0.21 | -0.17 | +0.14 | -0.32 |
| SPAM | -0.20 | -0.58✅ | -0.57✅ | +0.15 | -0.65✅ | -0.70✅ | +0.54✅ |  1.00  | -0.23⚠️ | -0.47✅ | -0.23⚠️ | -0.37✅ | -0.47✅ | +0.26⚠️ | -0.32✅ | -0.03 | -0.29✅ | +0.27✅ | -0.25⚠️ | -0.10 | -0.17 | -0.37⚠️ | +0.02 | +0.07 | -0.12 | +0.42 | -0.16 | +0.10 | -0.07 |
| SPOOF | +0.37✅ | +0.74✅ | -0.14 | +0.01 | +0.08 | +0.30✅ | -0.51✅ | -0.23⚠️ |  1.00  | +0.92✅ | -0.64✅ | +0.61✅ | +0.39✅ | +0.08 | +0.34✅ | +0.34✅ | +0.30✅ | -0.26⚠️ | +0.26⚠️ | -0.32⚠️ | +0.51✅ | +0.44✅ | +0.31 | +0.20 | +0.38 | -0.14 | -0.69✅ | +0.71✅ | +0.85✅ |
| MALIC | +0.44✅ | +0.82✅ | +0.04 | -0.13 | +0.28✅ | +0.46✅ | -0.64✅ | -0.47✅ | +0.92✅ |  1.00  | -0.45✅ | +0.66✅ | +0.43✅ | +0.09 | +0.27✅ | +0.38✅ | +0.28✅ | -0.25⚠️ | +0.32✅ | -0.27 | +0.50✅ | +0.47✅ | +0.29 | +0.16 | +0.43 | -0.19 | -0.69✅ | +0.73✅ | +0.84✅ |
| ISE | -0.15 | -0.21 | +0.73✅ | -0.43✅ | +0.61✅ | +0.37✅ | -0.16 | -0.23⚠️ | -0.64✅ | -0.45✅ |  1.00  | -0.18 | +0.07 | -0.24⚠️ | -0.14 | -0.10 | -0.25⚠️ | +0.23⚠️ | -0.17 | +0.43✅ | -0.40✅ | -0.24 | -0.19 | -0.06 | -0.43 | +0.06 | +0.79✅ | -0.79✅ | -0.71✅ |
| IPv6 | +0.21 | +0.71✅ | +0.10 | -0.19 | +0.27⚠️ | +0.36✅ | -0.57✅ | -0.37✅ | +0.61✅ | +0.66✅ | -0.18 |  1.00  | +0.29✅ | +0.03 | +0.11 | +0.54✅ | +0.10 | -0.04 | +0.24⚠️ | -0.09 | -0.55✅ | -0.25 | -0.41✅ | -0.35 | -0.10 | -0.04 | +0.49⚠️ | -0.57✅ | -0.68✅ |
| HTTP3 | +0.16 | +0.59✅ | +0.33✅ | +0.22 | +0.51✅ | +0.66✅ | -0.41✅ | -0.47✅ | +0.39✅ | +0.43✅ | +0.07 | +0.29✅ |  1.00  | -0.50✅ | +0.58✅ | +0.18 | +0.35✅ | -0.34✅ | +0.18 | +0.37⚠️ | +0.19 | +0.26 | +0.17 | +0.62✅ | -0.25 | +0.64✅ | -0.19 | +0.25 | +0.62✅ |
| TLS13 | +0.25⚠️ | +0.05 | -0.39✅ | -0.28✅ | -0.28✅ | -0.31✅ | +0.02 | +0.26⚠️ | +0.08 | +0.09 | -0.24⚠️ | +0.03 | -0.50✅ |  1.00  | -0.67✅ | +0.60✅ | -0.27⚠️ | +0.29✅ | +0.17 | -0.24 | +0.12 | -0.04 | +0.06 | -0.06 | +0.46 | -0.12 | -0.69✅ | +0.77✅ | +0.58✅ |
| BOT | -0.06 | +0.26⚠️ | +0.25⚠️ | +0.41✅ | +0.24⚠️ | +0.39✅ | -0.05 | -0.32✅ | +0.34✅ | +0.27✅ | -0.14 | +0.11 | +0.58✅ | -0.67✅ |  1.00  | -0.47✅ | +0.46✅ | -0.46✅ | +0.00 | -0.11 | +0.31 | +0.34⚠️ | +0.26 | +0.21 | -0.03 | -0.60✅ | +0.36 | -0.37 | -0.19 |
| IMP | +0.32✅ | +0.50✅ | -0.14 | -0.30✅ | +0.10 | +0.14 | -0.44✅ | -0.03 | +0.34✅ | +0.38✅ | -0.10 | +0.54✅ | +0.18 | +0.60✅ | -0.47✅ |  1.00  | -0.16 | +0.21 | +0.29✅ | +0.22 | -0.31 | -0.29 | -0.27 | -0.02 | +0.03 | +0.45 | -0.54⚠️ | +0.59✅ | +0.56✅ |
| L3UDP | +0.11 | +0.31✅ | +0.05 | +0.26⚠️ | +0.07 | +0.26⚠️ | -0.11 | -0.29✅ | +0.30✅ | +0.28✅ | -0.25⚠️ | +0.10 | +0.35✅ | -0.27⚠️ | +0.46✅ | -0.16 |  1.00  | -0.96✅ | +0.21 | -0.14 | +0.50✅ | +0.35⚠️ | +0.34⚠️ | +0.20 | +0.13 | -0.46 | -0.25 | +0.25 | +0.31 |
| L3TCP | -0.08 | -0.25⚠️ | -0.02 | -0.26⚠️ | -0.06 | -0.26⚠️ | +0.10 | +0.27✅ | -0.26⚠️ | -0.25⚠️ | +0.23⚠️ | -0.04 | -0.34✅ | +0.29✅ | -0.46✅ | +0.21 | -0.96✅ |  1.00  | -0.13 | +0.16 | -0.50✅ | -0.34⚠️ | -0.32⚠️ | -0.17 | -0.11 | +0.45 | +0.20 | -0.20 | -0.26 |
| L3HV | +0.43✅ | +0.48✅ | +0.03 | +0.14 | +0.23⚠️ | +0.14 | -0.10 | -0.25⚠️ | +0.26⚠️ | +0.32✅ | -0.17 | +0.24⚠️ | +0.18 | +0.17 | +0.00 | +0.29✅ | +0.21 | -0.13 |  1.00  | -0.06 | +0.59✅ | +0.42✅ | +0.52✅ | +0.65✅ | +0.02 | -0.03 | -0.05 | +0.15 | +0.84✅ |
| HIJ_n | +0.05 | +0.08 | +0.26 | +0.03 | +0.42✅ | +0.26 | -0.38✅ | -0.10 | -0.32⚠️ | -0.27 | +0.43✅ | -0.09 | +0.37⚠️ | -0.24 | -0.11 | +0.22 | -0.14 | +0.16 | -0.06 |  1.00  | -0.33⚠️ | -0.17 | -0.08 | +0.07 | -0.65✅ | +0.59✅ | +0.49⚠️ | -0.46 | -0.02 |
| HIJ_c | +0.26 | +0.39✅ | -0.08 | +0.29 | -0.10 | +0.08 | +0.24 | -0.17 | +0.51✅ | +0.50✅ | -0.40✅ | -0.55✅ | +0.19 | +0.12 | +0.31 | -0.31 | +0.50✅ | -0.50✅ | +0.59✅ | -0.33⚠️ |  1.00  | +0.71✅ | +0.47✅ | +0.33 | +0.49⚠️ | -0.09 | -0.61✅ | +0.68✅ | +0.81✅ |
| RPKI% | +0.43✅ | +0.42✅ | -0.04 | +0.31 | +0.04 | +0.25 | +0.04 | -0.37⚠️ | +0.44✅ | +0.47✅ | -0.24 | -0.25 | +0.26 | -0.04 | +0.34⚠️ | -0.29 | +0.35⚠️ | -0.34⚠️ | +0.42✅ | -0.17 | +0.71✅ |  1.00  | +0.33⚠️ | +0.11 | +0.74✅ | -0.35 | -0.58✅ | +0.62✅ | +0.62✅ |
| HIJ_sv | +0.49✅ | +0.30 | +0.02 | +0.37✅ | +0.13 | +0.07 | +0.22 | +0.02 | +0.31 | +0.29 | -0.19 | -0.41✅ | +0.17 | +0.06 | +0.26 | -0.27 | +0.34⚠️ | -0.32⚠️ | +0.52✅ | -0.08 | +0.47✅ | +0.33⚠️ |  1.00  | +0.66✅ | -0.15 | +0.18 | -0.18 | +0.18 | +0.46 |
| LK_n | +0.12 | +0.47⚠️ | +0.20 | +0.25 | +0.20 | +0.32 | -0.15 | +0.07 | +0.20 | +0.16 | -0.06 | -0.35 | +0.62✅ | -0.06 | +0.21 | -0.02 | +0.20 | -0.17 | +0.65✅ | +0.07 | +0.33 | +0.11 | +0.66✅ |  1.00  | -0.53⚠️ | +0.35 | +0.36 | -0.31 | +0.26 |
| L7IT | +0.25 | +0.27 | -0.51⚠️ | -0.14 | -0.35 | -0.09 | +0.13 | -0.12 | +0.38 | +0.43 | -0.43 | -0.10 | -0.25 | +0.46 | -0.03 | +0.03 | +0.13 | -0.11 | +0.02 | -0.65✅ | +0.49⚠️ | +0.74✅ | -0.15 | -0.53⚠️ |  1.00  | -0.55⚠️ | -0.60✅ | +0.60✅ | +0.27 |
| L7CE | -0.10 | -0.42 | -0.27 | +0.72✅ | +0.02 | -0.30 | +0.21 | +0.42 | -0.14 | -0.19 | +0.06 | -0.04 | +0.64✅ | -0.12 | -0.60✅ | +0.45 | -0.46 | +0.45 | -0.03 | +0.59✅ | -0.09 | -0.35 | +0.18 | +0.35 | -0.55⚠️ |  1.00  | +0.16 | -0.16 | -0.12 |
| L7GET | -0.58✅ | -0.17 | +0.78✅ | -0.27 | +0.49⚠️ | +0.13 | -0.17 | -0.16 | -0.69✅ | -0.69✅ | +0.79✅ | +0.49⚠️ | -0.19 | -0.69✅ | +0.36 | -0.54⚠️ | -0.25 | +0.20 | -0.05 | +0.49⚠️ | -0.61✅ | -0.58✅ | -0.18 | +0.36 | -0.60✅ | +0.16 |  1.00  | -0.99✅ | -0.45 |
| L7PST | +0.53⚠️ | +0.28 | -0.76✅ | +0.26 | -0.49⚠️ | -0.07 | +0.14 | +0.10 | +0.71✅ | +0.73✅ | -0.79✅ | -0.57✅ | +0.25 | +0.77✅ | -0.37 | +0.59✅ | +0.25 | -0.20 | +0.15 | -0.46 | +0.68✅ | +0.62✅ | +0.18 | -0.31 | +0.60✅ | -0.16 | -0.99✅ |  1.00  | +0.51⚠️ |
| IVC | +0.66✅ | +0.68✅ | -0.25 | +0.24 | -0.19 | +0.33 | -0.32 | -0.07 | +0.85✅ | +0.84✅ | -0.71✅ | -0.68✅ | +0.62✅ | +0.58✅ | -0.19 | +0.56✅ | +0.31 | -0.26 | +0.84✅ | -0.02 | +0.81✅ | +0.62✅ | +0.46 | +0.26 | +0.27 | -0.12 | -0.45 | +0.51⚠️ |  1.00  |

---
## 10. Findings et Implications

### 10.1 Résumé des Corrélations Inter-Domaines Clés

Sur les **345 paires inter-domaines** analysées, **40** sont statistiquement significatives (p < 0.05).

**Top 5 corrélations inter-domaines (|r| décroissant) :**

1. **SPOOF%** (Email Security) et **IVC (vulnérabilité)** (IVC) sont corrélées positivement (r=0.852, p=0.0002)
2. **L3 haut vol.%** (L3 Attacks) et **IVC (vulnérabilité)** (IVC) sont corrélées positivement (r=0.841, p=0.0003)
3. **MALICIOUS%** (Email Security) et **IVC (vulnérabilité)** (IVC) sont corrélées positivement (r=0.835, p=0.0004)
4. **DNS qualité** (DNS Quality) et **MALICIOUS%** (Email Security) sont corrélées positivement (r=0.822, p=0.0000)
5. **BGP hij. conf.** (BGP Hijacks) et **IVC (vulnérabilité)** (IVC) sont corrélées positivement (r=0.813, p=0.0007)

### 10.2 Causalités Confirmées

- **BGP hijacks → MALICIOUS** : p_min=0.0042 → causalité Granger confirmée
- **BGP hijacks → SPOOF** : p_min=0.0053 → causalité Granger confirmée
- **RPKI violations → DNS qualité** : p_min=0.0096 → causalité Granger confirmée
- **SPOOF → MALICIOUS** : p_min=0.0029 → causalité Granger confirmée

### 10.3 Analyse des Anomalies Multi-Domaines

**3 semaine(s)** présentent des anomalies simultanées sur ≥ 2 domaines.

La semaine **2026-05-18** est la plus critique avec **2 domaines** anormaux simultanément.

### 10.4 Index de Vulnérabilité Composite (IVC) — Synthèse

- IVC moyen sur la période : **55.7/100**
- IVC max : **77.6/100** — vulnérabilité maximale observée
- Tendance IVC : **↑ hausse forte (τ=0.62)**

### 10.5 Implications pour la Sécurité Internet

1. **Découplage BGP-Email :** L'absence (ou la faiblesse) de corrélation entre les hijacks BGP et les indicateurs email suggère que ces menaces opèrent sur des cycles indépendants — ou que le délai de propagation dépasse 4 semaines (limite Granger testée ici).

2. **DNS comme hub central :** La DNS qualité est corrélée avec plusieurs domaines, ce qui en fait un indicateur avancé potentiel de la santé globale de l'écosystème internet.

3. **Synergies email/réseau :** Les hausses de SPOOF et MALICIOUS se produisent dans des contextes de faiblesse protocolaire (IMP bas, TLS 1.3 insuffisant), suggérant que le renforcement de la chaîne protocolaire réduit la surface d'attaque email.

4. **BGP : menace autonome.** Les hijacks BGP ne suivent pas les cycles d'autres menaces — ils constituent un vecteur d'attaque structurellement séparé, qui nécessite des mesures dédiées (RPKI/ROV, MANRS).

5. **IVC : outil de pilotage.** L'Index de Vulnérabilité Composite permet d'identifier les semaines à risque agrégé élevé et de prioriser les actions de remédiation.

---
*Rapport généré automatiquement par `phase_H_correlations.py` le 2026-06-16 16:57:47.*  
*Sources : Cloudflare Radar API v4 — 25 datasets nettoyés.*  
*Prochaine étape : Phase I — Clustering et segmentation géographique.*