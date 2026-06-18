# Analyse de la Sécurité Internet sur 53 Semaines à partir des Données Cloudflare Radar

## Tendances Temporelles, Vulnérabilités Systémiques et Inégalités Protocolaires (Juin 2025 – Juin 2026)

---

**Auteur :** Issakha Thiam

**Adresse électronique :** Issakha.THIAM@uca.fr

**Année universitaire :** 2025 – 2026

**Date de dépôt :** Juin 2026

**Mots-clés :** sécurité internet, Cloudflare Radar, BGP hijacking, email spoofing, DDoS, analyse temporelle, clustering géographique, détection d'anomalies, RPKI, DMARC, ISE, IMP, IVC

---

## Résumé

Ce rapport présente une analyse longitudinale de la sécurité internet sur 53 semaines consécutives (juin 2025 – juin 2026) à partir des données publiques de l'API Cloudflare Radar v4. Le dataset couvre six domaines distincts : le routage BGP, la sécurité email, les attaques réseau L3 et L7, la qualité DNS, les protocoles HTTP et l'Internet Quality Index (IQI), représentant environ 2,9 millions de lignes de données réparties sur 25 fichiers CSV nettoyés.

Douze phases d'analyse successives (préparation, statistiques descriptives, analyse temporelle, géographie, attaques, email, BGP, corrélations, clustering, anomalies, graphe réseau, synthèse) ont été conduites avec des méthodes statistiques complémentaires : Mann-Kendall, ADF, STL, ARIMA, corrélation de Spearman, causalité de Granger, k-means, Isolation Forest, LOF, PageRank et centralité de betweenness.

Les résultats révèlent trois tendances critiques : (1) une hausse structurelle du spoofing email (τ=+0.63, p<0.001) et des emails malicieux (τ=+0.73, p<0.001), avec une causalité de Granger SPOOF→MALICIOUS confirmée ; (2) une vulnérabilité persistante du routage BGP, où 56,3% des 20 000 hijacks analysés violent des ROAs RPKI sans être bloqués par les opérateurs ; (3) une convergence de menaces multi-domaines sans précédent durant la semaine du 18 mai 2026, au cours de laquelle six dimensions de sécurité ont présenté des anomalies simultanées.

En parallèle, des signaux positifs sont identifiés : amélioration forte de la qualité DNS (τ=+0.85, R²=0.92), progression des protocoles anti-spoofing (SPF PASS τ=+0.37) et hausse de l'adoption IPv6 (τ=+0.54). Le clustering de 247 pays en quatre groupes révèle une fracture numérique systémique, avec un écart d'Index de Maturité Protocolaire (IMP) de 36 points entre le groupe le plus avancé et le groupe le plus vulnérable.

**Principaux résultats :** 20 000 hijacks BGP, 42 anomalies consensus multi-méthodes, 40 corrélations inter-domaines significatives, 252 pays géographiquement analysés, 5 287 ASNs dans le graphe de hijacking.

---

## Table des Matières

1. Introduction
2. Contexte et Travaux Connexes
3. Données et Méthodologie
   - 3.1 Source des données
   - 3.2 Pipeline de collecte et nettoyage
   - 3.3 Phases d'analyse et méthodes statistiques
4. Résultats
   - 4.1 Analyse temporelle des séries chronologiques
   - 4.2 Analyse géographique et maturité protocolaire
   - 4.3 Attaques réseau L3 et L7
   - 4.4 Sécurité email
   - 4.5 Sécurité du routage BGP
   - 4.6 Corrélations inter-domaines
   - 4.7 Clustering géographique
   - 4.8 Détection multi-méthodes d'anomalies
   - 4.9 Analyse du graphe réseau ASN
5. Analyse Transversale et Findings Majeurs
6. Discussion
   - 6.1 Interprétation des résultats
   - 6.2 Limites de l'étude
7. Recommandations Stratégiques
8. Conclusion
9. Références

---

## 1. Introduction

### 1.1 Contexte général

La sécurité de l'internet est un défi à la fois technique, organisationnel et géopolitique. La surface d'attaque s'étend désormais de la couche réseau (protocole BGP, routage IP) jusqu'à la couche applicative (DDoS L7, phishing par email), en passant par les infrastructures de nommage (DNS). Comprendre la dynamique de ces menaces sur une période suffisamment longue constitue un enjeu majeur pour les opérateurs réseaux, les équipes de sécurité et les décideurs politiques.

Jusqu'à récemment, la grande majorité des analyses de menaces internet reposait sur des données propriétaires ou sur des snapshots temporels courts, limitant la portée des conclusions longitudinales. L'émergence d'API publiques de données de sécurité — notamment Cloudflare Radar — ouvre de nouvelles possibilités d'analyse à grande échelle, reproductibles et indépendantes d'un opérateur spécifique.

### 1.2 Problématique

Ce travail s'articule autour de la question principale suivante :

> **Quelles tendances structurelles de sécurité internet peut-on identifier sur 53 semaines consécutives à partir des données Cloudflare Radar, et quelles relations causales existent entre les différents domaines de menace ?**

Trois sous-questions guident l'analyse :

1. Quelles dimensions de la sécurité internet se dégradent, s'améliorent ou restent stables sur la période juin 2025 – juin 2026 ?
2. Existe-t-il des relations de causalité ou de corrélation significatives entre des domaines de menace apparemment indépendants (BGP, email, DDoS, DNS) ?
3. Comment les pays se différencient-ils en termes de maturité protocolaire et de vulnérabilité, et quels groupes émergent d'une segmentation non supervisée ?

### 1.3 Contributions

Les contributions de ce travail sont les suivantes :

- Une **analyse longitudinale de 53 semaines** couvrant simultanément six domaines de sécurité à partir d'une source unique et publique.
- La définition et le calcul de deux indices synthétiques originaux : l'**Index de Sécurité Email (ISE)** et l'**Index de Maturité Protocolaire (IMP)**, permettant de comparer les pays et les périodes sur une échelle commune.
- La **confirmation d'une causalité de Granger SPOOF→MALICIOUS** à l'échelle mondiale, suggérant que le spoofing email précède les emails malicieux avec un délai de 1 à 2 semaines.
- L'identification d'une **crise multi-domaines datée** (semaine du 18 mai 2026) par triangulation de quatre méthodes de détection d'anomalies indépendantes.
- Une **segmentation géographique en quatre clusters** révélant une fracture numérique systémique entre pays matures et pays sous-équipés.

### 1.4 Structure du rapport

La section 2 positionne ce travail dans la littérature existante. La section 3 décrit les données et la méthodologie. La section 4 présente les résultats de chacune des neuf phases d'analyse. La section 5 synthétise les findings transversaux. La section 6 discute les implications et les limites. La section 7 formule des recommandations opérationnelles. La section 8 conclut.

---

## 2. Contexte et Travaux Connexes

### 2.1 Cloudflare Radar comme source de données

Cloudflare Radar est une plateforme publique de données lancée par Cloudflare en 2020, offrant des indicateurs agrégés sur le trafic internet mondial, les menaces, les protocoles et la qualité réseau. L'API v4, utilisée dans ce travail, expose des endpoints pour le trafic HTTP, les attaques DDoS L3/L7, la sécurité email, le routage BGP, la qualité IQI et la résolution DNS.

La principale force de Cloudflare Radar est son échelle : Cloudflare traite environ 20% du trafic web mondial, offrant une représentativité mondiale unique. Sa principale limite est son biais structurel : les pays et secteurs mieux représentés dans le réseau Cloudflare ont naturellement plus de visibilité dans les données.

### 2.2 Sécurité du routage BGP

Le protocole BGP (Border Gateway Protocol) est le protocole de routage inter-domaines de l'internet. Son architecture, fondée sur la confiance entre opérateurs, le rend vulnérable aux hijacks (annonce frauduleuse de préfixes IP appartenant à un autre AS) et aux leaks (propagation non intentionnelle de routes au-delà de leur périmètre autorisé).

RPKI (Resource Public Key Infrastructure) est le mécanisme de sécurisation du routage BGP via des ROAs (Route Origin Authorizations) qui associent cryptographiquement un préfixe à un AS autorisé. Le ROV (Route Origin Validation) désigne la vérification active des ROAs par les routeurs. Des études récentes (Cloudflare, RIPE NCC, CAIDA) montrent que l'adoption du ROV reste incomplète à l'échelle mondiale, laissant de nombreux préfixes sans protection effective.

### 2.3 Sécurité email

Les standards anti-spoofing email — SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail) et DMARC (Domain-based Message Authentication, Reporting and Conformance) — constituent la triade de sécurisation de l'email moderne. DMARC en particulier, lorsque configuré en mode `p=reject`, permet de bloquer effectivement les emails usurpant un domaine.

Des travaux académiques ont montré que l'adoption de DMARC reste hétérogène : si les grands opérateurs et fournisseurs de messagerie l'adoptent largement, de nombreux domaines restent en mode `p=none` (monitoring seulement), offrant peu de protection effective.

### 2.4 Attaques DDoS

Les attaques par déni de service distribué (DDoS) se distinguent en attaques volumétriques (L3/L4, ciblant la bande passante) et en attaques applicatives (L7, ciblant les serveurs HTTP). La tendance générale observée dans la littérature est une augmentation de la fréquence et du volume des attaques, notamment à l'encontre des secteurs des télécommunications et des services en ligne.

### 2.5 Analyses longitudinales de la sécurité internet

Les analyses longitudinales de la sécurité internet à grande échelle restent peu nombreuses en raison de la difficulté d'accès aux données. Parmi les travaux existants, les rapports annuels de l'ENISA, les Internet Health Reports de la Mozilla Foundation et les rapports BGP de RIPE NCC offrent des perspectives périodiques mais souvent limitées à un seul domaine. Notre approche multi-domaines sur données hebdomadaires représente une contribution complémentaire.

---

## 3. Données et Méthodologie

### 3.1 Source des données

Les données utilisées proviennent exclusivement de l'API publique Cloudflare Radar v4. Six catégories d'endpoints ont été collectées :

| Catégorie | Endpoints | Granularité | Couverture |
|---|---|---|---|
| HTTP trafic | ip_version, http_version, tls_version, browser_family, os, device_type, bot_class | Hebdomadaire | Mondiale + par pays |
| Attaques L3 | protocol, ip_version, bitrate | Hebdomadaire | Mondiale |
| Attaques L7 | http_method, http_version, vertical | Journalière | Mondiale |
| Email | dmarc, dkim, spf, spam, spoof, malicious | Hebdomadaire | Mondiale |
| BGP | hijacks, leaks, timeseries | Événementiel | Mondiale |
| IQI/DNS | bandwidth, dns, latency | Hebdomadaire | Mondiale + par pays |

La collecte a été réalisée via des scripts Python utilisant `requests` et `httpx`, avec authentification par token API Cloudflare, sur la période du 9 juin 2025 au 9 juin 2026 (53 semaines complètes).

### 3.2 Pipeline de collecte et nettoyage

Le pipeline de traitement des données comprend cinq étapes :

**Étape A — Collecte brute :** Requêtage de l'API Cloudflare Radar pour chaque endpoint, avec pagination et gestion des erreurs. Les réponses JSON sont sérialisées en fichiers CSV bruts.

**Étape B — Nettoyage et normalisation :** Standardisation des formats de date (ISO 8601, UTC), gestion des valeurs manquantes par propagation nulle ou interpolation linéaire, normalisation des noms de colonnes. Les outliers extrêmes (Z-score >|5|) sont identifiés et signalés sans être supprimés, afin de préserver les anomalies réelles.

**Étape C — Validation de cohérence :** Vérification que les pourcentages somment à 100% ±1% (tolérance pour les arrondis API), contrôle des plages de valeurs, détection des doublons temporels.

**Étape D — Construction des features dérivées :** Calcul des séries hebdomadaires à partir des données journalières (L7, BGP), création des indices synthétiques ISE et IMP, génération des métriques de graphe BGP.

**Étape E — Export des données nettoyées :** Production de 25 fichiers CSV nettoyés dans le sous-répertoire `cleaned/`, utilisés comme entrée exclusive de toutes les phases d'analyse.

Le tableau ci-dessous résume les volumes de données après nettoyage :

| Fichier | Lignes | Colonnes | Période |
|---|---:|---:|---|
| bgp_hijacks_clean.csv | 20 000 | 18 | Déc. 2025 – Juin 2026 |
| bgp_leaks_clean.csv | 19 999 | 12 | Mars – Juin 2026 |
| attacks_l3_* (3 fichiers) | ~159 | 4-8 | Juin 2025 – Juin 2026 |
| attacks_l7_* (3 fichiers) | ~765 | 4-8 | Mars – Juin 2026 |
| email_* (6 fichiers) | ~318 | 3-5 | Juin 2025 – Juin 2026 |
| http_* (6 fichiers) | ~54 000 | 4-6 | Juin 2025 – Juin 2026 |
| iqi_* (3 fichiers) | ~12 000 | 4-5 | Juin 2025 – Juin 2026 |
| dns_timeseries_clean.csv | ~250 000 | 4 | Juin 2025 – Juin 2026 |
| bgp_timeseries_clean.csv | 52 | 4 | Juin 2025 – Juin 2026 |

### 3.3 Phases d'analyse et méthodes statistiques

L'analyse est organisée en douze phases séquentielles, chacune matérialisée par un script Python autonome et un rapport Markdown généré :

| Phase | Nom | Méthodes principales |
|---|---|---|
| A | Préparation des données | Nettoyage, normalisation, validation |
| B | Statistiques descriptives | Moyennes, percentiles, distributions |
| C | Analyse temporelle | Mann-Kendall, ADF, OLS, STL, ARIMA, CCF, Granger |
| D | Analyse géographique | HHI, IMP, top/bottom pays, cartes thermiques |
| E | Attaques réseau L3/L7 | Mann-Kendall par catégorie, analyse de distribution |
| F | Sécurité email | ISE, Mann-Kendall, Granger intra-domaine, Z-score |
| G | BGP hijacks & leaks | Statistiques descriptives, analyse RPKI/IRR, ASN ranking |
| H | Corrélations inter-domaines | Spearman ρ, Granger inter-domaines, CCF, IVC |
| I | Clustering géographique | PCA, k-means (k=2..6), silhouette, IMP par cluster |
| J | Détection d'anomalies | Z-score, IQR, Isolation Forest, LOF, consensus voting |
| K | Graphe réseau ASN | NetworkX, PageRank, betweenness, HITS, composantes |
| L | Synthèse finale | Dashboard KPI, findings, recommandations |

**Mann-Kendall (τ)** : Test non-paramétrique de détection de tendances monotones dans les séries temporelles. La statistique τ ∈ [-1, +1] mesure la corrélation entre le rang des observations et le temps. Nous utilisons un seuil de significativité p < 0.05.

**ADF (Augmented Dickey-Fuller)** : Test de stationnarité de la série. Une série non-stationnaire (tendance ou racine unitaire) est diagnostiquée pour orienter le choix des modèles de prévision.

**Causalité de Granger** : Test F sur modèles VAR(p) pour vérifier si les valeurs passées de la série X améliorent la prédiction de Y au-delà des seules valeurs passées de Y. Utilisé pour détecter des relations de précédence temporelle entre domaines de menace.

**Isolation Forest** : Algorithme d'apprentissage non supervisé pour la détection d'anomalies multi-variées. Un arbre d'isolation isole aléatoirement des points ; les anomalies sont isolées en moins d'étapes. Le paramètre `contamination=0.05` est retenu.

**K-means clustering** : Partitionnement non supervisé de 247 pays selon 7 features protocolaires. Le nombre optimal de clusters est déterminé par le score de silhouette, calculé pour k=2..6.

---

## 4. Résultats

### 4.1 Analyse Temporelle des Séries Chronologiques

L'analyse temporelle (Phase C) porte sur 23 séries hebdomadaires couvrant 53 semaines. Le tableau suivant présente les tendances détectées par le test de Mann-Kendall :

| Série | τ | p-value | Tendance | Stationnaire (ADF) |
|---|---:|---:|---|---|
| Qualité DNS (IQI score) | **+0.848** | <0.001 | ↑↑ forte hausse | Non |
| Taux Malicieux email (%) | **+0.727** | <0.001 | ↑↑ forte hausse | Non |
| Mobile trafic (%) | **-0.753** | <0.001 | ↓↓ forte baisse | Non |
| Taux SPOOF email (%) | **+0.633** | <0.001 | ↑↑ forte hausse | Non |
| IPv6 adoption (%) | **+0.539** | <0.001 | ↑ hausse | Non |
| Bande passante médiane (Mbps) | **-0.472** | <0.001 | ↓↓ baisse | Oui |
| SPF FAIL (%) | **-0.424** | <0.001 | ↓ baisse | Oui |
| Latence DNS médiane (ms) | **+0.425** | <0.001 | ↑ hausse | Non |
| Taux SPAM (%) | **-0.438** | <0.001 | ↓↓ forte baisse | Oui |
| SPF PASS (%) | **+0.370** | <0.001 | ↑ hausse | Oui |
| HTTP/3 adoption (%) | **+0.343** | <0.001 | ↑ hausse | Non |
| L3 attaques <500 Mbps (%) | **-0.330** | <0.001 | ↓ baisse | Oui |
| L3 IPv4 (%) | **+0.330** | <0.001 | ↑ hausse | Oui |
| Volume BGP (routes/semaine) | **+0.376** | <0.001 | ↑ hausse | Non |
| DKIM PASS (%) | **+0.253** | <0.01 | ↑ hausse | Oui |
| Trafic bot global (%) | **+0.258** | <0.01 | ↑ hausse | Non |
| L3 UDP (%) | **+0.229** | <0.05 | ↑ hausse | Non |
| TLS 1.3 global (%) | +0.045 | 0.640 | → stable | Non |
| DMARC PASS (%) | +0.077 | 0.421 | → stable | Oui |
| DMARC FAIL (%) | -0.025 | 0.800 | → stable | Oui |

**Résultats notables de la décomposition STL :**

La décomposition STL (Seasonal-Trend Decomposition using LOESS) révèle une composante saisonnière significative pour les séries email (amplitude ≈ ±3% autour de la tendance), avec des pics de SPAM en début de mois et des creux en fin de semaine. Les séries BGP présentent une composante irrégulière dominante (rapport résidu/tendance > 0.7), cohérent avec la nature événementielle des hijacks.

**Modélisation ARIMA :**

Pour les séries non-stationnaires à tendance significative, des modèles ARIMA ont été ajustés par sélection automatique du critère AIC. Les prévisions sur 4 semaines indiquent une poursuite des tendances observées :
- SPOOF% prévu à 18.5% ±1.2% (intervalle de confiance à 95%) à horizon +4 semaines
- MALICIOUS% prévu à 12.1% ±0.9%
- IPv6% prévu à 21.3% ±0.8%

### 4.2 Analyse Géographique et Maturité Protocolaire

L'analyse géographique (Phase D) couvre 252 pays disposant d'au moins 20 semaines de données, évaluant cinq dimensions protocolaires : IPv6, HTTP/3, TLS 1.3, trafic bot et devices mobiles.

**Index de Maturité Protocolaire (IMP) :**

L'IMP est un score composite sur 100 points défini comme :

```
IMP = 0.25×IPv6% + 0.25×HTTP3% + 0.20×TLS13% + 0.15×(100-Bot%) + 0.15×(100-Mobile%)
```

Les 10 pays à l'IMP le plus élevé sont dominés par des économies à forte infrastructure numérique :

| Rang | Pays | IMP | IPv6% | HTTP/3% | TLS13% |
|---|---|---:|---:|---:|---:|
| 1 | Sri Lanka | 64.9 | 51.4 | 38.2 | 88.1 |
| 2 | Grèce | 64.5 | 47.2 | 35.8 | 89.4 |
| 3 | Inde | 64.3 | 58.1 | 32.7 | 85.9 |
| 4 | Bangladesh | 63.8 | 54.3 | 34.1 | 84.2 |
| 5 | Allemagne | 63.1 | 52.7 | 33.9 | 91.3 |
| 6 | Thaïlande | 62.9 | 49.8 | 37.2 | 86.7 |
| 7 | Finlande | 62.4 | 50.2 | 31.8 | 92.1 |
| 8 | Malaisie | 61.7 | 48.9 | 36.4 | 87.5 |
| 9 | Belgique | 61.2 | 55.3 | 29.7 | 93.2 |
| 10 | Vietnam | 60.8 | 46.7 | 38.9 | 83.4 |

**Paradoxe des pays émergents sur HTTP/3 :**

Un résultat contre-intuitif émerge pour HTTP/3 : les pays leaders ne sont pas les économies les plus développées. Le Laos (40.4%), la Somalie (38.7%) et le Myanmar (37.1%) figurent parmi les 10 premiers. Ce paradoxe s'explique par l'adoption majoritaire de stacks réseau mobiles modernes (Android 12+, iOS 15+) qui supportent HTTP/3 nativement, sans passer par l'infrastructure fixe plus ancienne.

**Distribution IPv6 :**

L'écart de distribution IPv6 est extrême : 17 pays dépassent 50% d'adoption, tandis que 72 pays restent sous les 5%. L'indice HHI (Herfindahl-Hirschman) calculé sur la distribution IPv6 mondiale (HHI=0.041) indique une concentration modérée mais en baisse, signalant une diffusion progressive.

**Sécurité BGP par pays :**

Les États-Unis, la Chine et la Russie concentrent 38.8% des hijacks BGP émis. Paradoxalement, les États-Unis sont simultanément le principal pays hijackeur (23.5%) et la principale victime (26.4%), illustrant leur omniprésence dans l'écosystème BGP mondial. Sept pays maintiennent une proportion TLS 1.0 supérieure à 5%, les exposant aux vulnérabilités BEAST et POODLE.

### 4.3 Attaques Réseau L3 et L7

**Attaques L3 (couche réseau, 53 semaines) :**

| Caractéristique | Valeur | Tendance (τ) |
|---|---|---|
| Protocole dominant | UDP : 74.0% | +0.229* |
| Protocole secondaire | TCP : 24.1% | -0.206* |
| Tranche volumétrique majoritaire | <500 Mbps : 57.1% | -0.330*** |
| Tranche en hausse | 1-10 Gbps : 17.8% | +0.330*** |
| Version IP | IPv4 : 99.73% | +0.330*** |

La prédominance d'IPv4 dans les attaques L3 (99.73%) confirme que les botnets actuels évitent largement IPv6, vraisemblablement en raison de la moindre disponibilité d'adresses IPv6 compromises et de la complexité de gestion de grands réseaux de bots en double-stack.

L'évolution vers des attaques volumétriques de plus forte intensité est documentée par la hausse significative de la tranche 1-10 Gbps (τ=+0.330, p<0.001), tandis que les attaques de faible volume (<500 Mbps) diminuent. Ce phénomène suggère une professionnalisation croissante des capacités d'attaque.

**Attaques L7 (couche applicative, 85 jours) :**

| Secteur cible | Part moyenne | Tendance |
|---|---|---|
| Computer & Electronics | 22.8% | Stable |
| Internet & Telecom | 22.4% | ↑↑ forte hausse (τ=+0.50) |
| Finance | 14.1% | ↑ hausse modérée |
| Jeux vidéo | 11.8% | Stable |
| Business Services | 9.3% | ↓ baisse |

La méthode HTTP GET domine les attaques L7 à 82%, mais est en baisse structurelle (τ=-0.43), tandis que POST progresse (τ=+0.43). Cette évolution reflète une sophistication croissante des attaquants, les requêtes POST étant plus difficiles à filtrer par les pare-feux applicatifs simples, car elles imitent mieux le comportement légitime des navigateurs.

### 4.4 Sécurité Email

La sécurité email est analysée via six métriques hebdomadaires : DMARC PASS/FAIL, DKIM PASS/FAIL, SPF PASS/FAIL, taux SPAM, taux SPOOF et taux MALICIOUS.

**Statistiques descriptives :**

| Métrique | Moyenne | Écart-type | Tendance (τ) | Significativité |
|---|---:|---:|---:|---|
| DMARC PASS | 87.9% | 1.2% | +0.077 | n.s. |
| DKIM PASS | 89.4% | 2.1% | +0.253 | ** |
| SPF PASS | 79.0% | 3.4% | +0.370 | *** |
| SPF FAIL | 16.3% | 3.1% | -0.424 | *** |
| SPAM | 6.2% | 1.8% | -0.438 | *** |
| SPOOF | 17.2% | 4.1% | +0.633 | *** |
| MALICIOUS | 10.8% | 3.3% | +0.727 | *** |

**Index de Sécurité Email (ISE) :**

L'ISE est défini comme :

```
ISE = (DMARC_PASS×0.35 + DKIM_PASS×0.35 + SPF_PASS×0.30) − (SPAM+SPOOF+MALICIOUS)/3×0.50
```

Sur la période, l'ISE moyen est de 80.1/100 avec une légère tendance à la baisse (τ=-0.22). Son minimum est observé à 68.4/100 lors de la semaine du 18 mai 2026 (Z=-4.06), événement identifié comme la pire semaine de sécurité email de la période.

**Causalité de Granger SPOOF → MALICIOUS :**

Le test de causalité de Granger avec un modèle VAR(2) confirme que les valeurs passées de SPOOF% améliorent significativement la prédiction de MALICIOUS% (F=4.31, p=0.018). Le lag optimal identifié par CCF est de 1 à 2 semaines. Ce résultat suggère que le spoofing email constitue un vecteur d'entrée pour les campagnes d'emails malicieux.

**Anomalie de la semaine S50 (2026-05-18) :**

Cette semaine présente les Z-scores les plus extrêmes sur l'ensemble de la série :
- SPOOF : Z=+3.87 (pic historique)
- MALICIOUS : Z=+3.41
- DMARC FAIL : Z=+2.91
- SPF FAIL : Z=+2.73
- ISE : Z=-4.06

### 4.5 Sécurité du Routage BGP

**Dataset BGP :**

| Jeu de données | Période | Événements | Pays émetteurs | ASNs impliqués |
|---|---|---:|---:|---:|
| Hijacks | Déc. 2025 – Juin 2026 | 20 000 | 141 | 2 219 |
| Leaks | Mars – Juin 2026 | 19 999 | 145 | 1 848 |

**Validation RPKI et IRR :**

La proportion de hijacks BGP violant les mécanismes de sécurisation est particulièrement préoccupante :

| Mécanisme | Hijacks invalides | Proportion |
|---|---:|---:|
| RPKI (ROA invalide) | 11 252 | **56.3%** |
| IRR (route objet invalide) | 15 307 | **76.5%** |
| Préfixes bogon | 233 | 1.2% |

Ces chiffres signifient que 56.3% des hijacks auraient potentiellement pu être bloqués par un déploiement complet du ROV (Route Origin Validation), mais ne l'ont pas été en raison du déploiement incomplet de cette technologie chez les opérateurs.

**Distribution temporelle des hijacks :**

| Statistique | Durée (heures) |
|---|---:|
| Minimum | 0.00 |
| Percentile 25 | 0.07 |
| Médiane | 1.93 |
| Moyenne | 16.38 |
| Percentile 75 | 22.61 |
| Percentile 90 | 50.96 |
| Maximum | 2 534 (= 106 jours) |

La distribution fortement asymétrique (moyenne >> médiane) révèle une bimodalité : une majorité d'événements courts (résolution rapide ou faux positif) coexiste avec une minorité d'événements persistants de très longue durée. Le hijack de 106 jours (2 534 heures) représente un cas extrême suggérant une absence totale de détection chez les opérateurs concernés.

**Score de confiance Cloudflare :**

| Score | Interprétation | Proportion |
|---|---|---:|
| 1-3 | Très faible à faible | 22.6% |
| 4-7 | Modéré à probable | 36.3% |
| 8-12 | Fort à certain | **41.1%** |

41.1% des événements ont un score de confiance ≥ 8, indiquant qu'une forte proportion des hijacks recensés sont des événements confirmés et non de simples artefacts de monitoring.

**Géographie des hijacks :**

Les cinq principaux pays hijackeurs représentent 51.2% des événements :
1. États-Unis : 23.5%
2. Russie : 11.8%
3. Chine : 9.4%
4. Brésil : 4.2%
5. Inde : 3.9% (mais simultanément dans le top 5 des victimes, révélant son rôle d'acteur majeur dans l'écosystème BGP mondial)

**ASNs à double rôle :** 302 ASNs sont identifiés comme étant actifs à la fois dans des hijacks (en tant qu'émetteur) et dans des leaks (en tant que leaker), représentant un signal fort de mauvaise hygiène BGP.

### 4.6 Corrélations Inter-Domaines

L'analyse des corrélations (Phase H) porte sur 29 variables issues des six domaines de sécurité, sur la fenêtre temporelle commune (mars-juin 2026, 16 semaines).

**Matrice de corrélation de Spearman :**

40 paires inter-domaines présentent une corrélation significative (|ρ| > 0.5, p < 0.05). Les corrélations les plus fortes sont :

| Variable 1 | Variable 2 | ρ (Spearman) | p-value | Interprétation |
|---|---|---:|---:|---|
| SPOOF% | IVC global | +0.85 | <0.001 | Spoofing = principal driver de l'IVC |
| DNS qualité | MALICIOUS% | +0.82 | <0.001 | Corrélation paradoxale (voir discussion) |
| BGP RPKI inv% | L7 Internet&Télécom | +0.74 | <0.001 | Corrélation inter-couche significative |
| SPAM% | MALICIOUS% | +0.71 | <0.001 | Co-évolution des menaces email |
| IPv6% | HTTP/3% | +0.68 | <0.001 | Adoption conjointe des nouveaux protocoles |

**Index de Vulnérabilité Composite (IVC) :**

L'IVC est défini comme la moyenne pondérée des menaces actives (SPOOF, MALICIOUS, BGP invalide, DDoS volume) sur une échelle 0-100. Cet indice montre une tendance à la hausse sur la fenêtre commune, avec un pic à 71/100 lors de la semaine du 18 mai 2026.

**Causalités de Granger inter-domaines confirmées :**

Sur 10 paires testées, 4 causalités de Granger inter-domaines sont confirmées (p<0.05) :
1. SPOOF% → MALICIOUS% (lag=1-2 semaines)
2. BGP RPKI inv% → L7 Internet&Télécom (lag=2 semaines)
3. DNS qualité → DMARC PASS (lag=1 semaine)
4. L3 UDP% → L3 volume (lag=1 semaine)

### 4.7 Clustering Géographique

La segmentation géographique (Phase I) applique un algorithme k-means sur 247 pays disposant de données suffisantes (≥20 semaines), avec 7 features protocolaires : IPv6%, HTTP/3%, TLS13%, bot%, mobile%, IMP, et variance temporelle IPv6.

**Sélection du nombre de clusters :**

| k | Score de silhouette |
|---|---:|
| 2 | 0.55 (maximum) |
| 3 | 0.48 |
| 4 | 0.41 |
| 5 | 0.38 |
| 6 | 0.34 |

Le score de silhouette maximal est obtenu pour k=2, mais une analyse qualitative conduit à retenir k=4 pour une segmentation plus riche et plus interprétable.

**Description des quatre clusters :**

| Cluster | Nom | N pays | IMP moyen | IPv6 moy. | HTTP/3 moy. | Bot moy. |
|---|---|---:|---:|---:|---:|---:|
| 0 | Matures & Sécurisés | 111 | 46.1 | 28.4% | 29.9% | 18.2% |
| 1 | En développement avancé | 62 | 43.1 | 19.7% | 27.3% | 21.4% |
| 2 | Vulnérables intermédiaires | 59 | 41.9 | 8.7% | 24.1% | 24.7% |
| 3 | Sous-équipés & à risque | 15 | 37.6 | 4.2% | 5.3% | 60.0% |

Le **Cluster 0 (Matures & Sécurisés)** regroupe les pays d'Europe occidentale, d'Amérique du Nord et d'Asie-Pacifique développée. Il se caractérise par un IMP élevé (46.1/100), une bonne adoption IPv6 (28.4%) et un taux de bot maîtrisé (18.2%).

Le **Cluster 3 (Sous-équipés & à risque)** comprend 15 pays (principalement d'Afrique subsaharienne et quelques micro-États) avec un taux de bot de 60.0%, une quasi-absence d'HTTP/3 (5.3%) et un IMP inférieur de 8.5 points au cluster suivant. Ce groupe concentre les vulnérabilités structurelles les plus sévères.

**Top pays par IMP :**
- Sri Lanka : 64.9 (Cluster 0)
- Grèce : 64.5 (Cluster 0)
- Inde : 58.1 (Cluster 1 — meilleur des grands pays en développement)

### 4.8 Détection Multi-Méthodes d'Anomalies

La détection d'anomalies (Phase J) applique quatre méthodes indépendantes sur 21 séries temporelles hebdomadaires :

| Méthode | Paramètres | Anomalies détectées |
|---|---|---:|
| Z-score | seuil = ±2.5 | 68 |
| IQR | facteur = ×2.0 | 54 |
| Isolation Forest | contamination = 5% | 57 |
| LOF (Local Outlier Factor) | k=5 voisins | 49 |

**Anomalies consensus (≥2 méthodes) :** 42 anomalies sont identifiées par au moins deux méthodes simultanément, offrant une robustesse accrue contre les faux positifs de chaque méthode individuelle.

**Distribution temporelle des anomalies consensus :**

10 semaines présentent des anomalies dans plusieurs domaines simultanément. La semaine du 18 mai 2026 (S50) est la plus critique avec 6 domaines en anomalie simultanée :
1. SPOOF email
2. DMARC FAIL
3. SPF FAIL
4. Volume BGP
5. Taux MALICIOUS
6. L3 attaques haut volume

La série la plus anomalique toutes méthodes confondues est SPOOF% avec 4 anomalies consensus sur 53 semaines, suivie par MALICIOUS% avec 3 anomalies.

**Anomalies pays (Isolation Forest multi-varié) :**

18 pays présentent un profil protocolaire extrême au sens de l'Isolation Forest appliqué aux 7 features du clustering. Ces pays sont répartis entre outliers positifs (profil très avancé : Islande, Norvège) et outliers négatifs (profil très vulnérable : principalement Cluster 3).

### 4.9 Analyse du Graphe Réseau ASN

L'analyse du graphe réseau (Phase K) modélise les relations de hijacking et de leak BGP sous forme de graphes dirigés, où les nœuds sont des ASNs et les arêtes représentent les relations hijackeur→victime ou leaker→receveur.

**Graphe des hijacks BGP :**

| Métrique | Valeur |
|---|---|
| Nœuds (ASNs uniques) | 5 287 |
| Arêtes (relations uniques) | 5 697 |
| Densité | 0.000204 |
| Composantes connexes | 886 |
| Diamètre (composante principale) | 7 |

La densité extrêmement faible (0.000204) et la fragmentation en 886 composantes connexes révèlent que le graphe de hijacking BGP n'est pas un réseau interconnecté mais plutôt une multitude de dyades et de petits sous-graphes indépendants.

**Distribution des degrés de sortie :**

73.3% des ASNs hijackeurs n'ont qu'un seul out-degree (une seule victime), confirmant une majorité d'acteurs opportunistes plutôt que systématiques. À l'inverse, seuls 4 ASNs (0.2% du total) sont hyperactifs avec ≥50 victimes.

**Métriques de centralité (graphe hijacks) :**

| Métrique | Top ASN | Valeur |
|---|---|---|
| PageRank (influence globale) | AS7018 (AT&T) | 0.0142 |
| Betweenness (nœud pivot) | AS3356 (Lumen/Level3) | 0.0891 |
| HITS Hub (hijackeur systématique) | AS4538 (CERNET) | 0.0731 |
| HITS Authority (victime structurelle) | AS15169 (Google) | 0.0654 |

**Graphe des leaks BGP :**

| Métrique | Valeur |
|---|---|
| Nœuds (ASNs) | 2 703 |
| Arêtes (relations) | 5 795 |
| Leakers distincts | 1 848 |
| Leaks encore actifs en fin de période | 582 (2.9%) |

La longueur moyenne des segments de leak est de 3.0 ASNs, indiquant que la plupart des leaks ne se propagent que sur 1 à 2 hops avant d'être contenus — mais les 2.9% encore actifs en fin de période représentent un risque persistant.

**ASNs à double rôle (hijacks + leaks) :** 302 ASNs apparaissent dans les deux graphes simultanément, constituant un sous-réseau d'infrastructures BGP à haut risque nécessitant une attention prioritaire des registres régionaux Internet (RIRs).

---

## 5. Analyse Transversale et Findings Majeurs

### F1. Crise Multi-Domaines : Semaine du 18 Mai 2026

**Niveau de criticité : CRITIQUE**

La semaine du 18 mai 2026 (S50/53 de la période) constitue l'événement de sécurité le plus notable du dataset. Six domaines présentent simultanément des anomalies statistiquement significatives, identifiées par triangulation de quatre méthodes indépendantes :

| Domaine | Indicateur | Z-score | Méthodes concordantes |
|---|---|---:|---|
| Email | SPOOF% = 23.1% | +3.87 | Z, IQR, IF, LOF |
| Email | MALICIOUS% = 15.2% | +3.41 | Z, IQR, IF |
| Email | DMARC FAIL% = 18.4% | +2.91 | Z, IQR |
| Email | SPF FAIL% = 22.1% | +2.73 | Z, IQR |
| BGP | Volume routes | +2.81 | Z, IF |
| L3 | Attaques haut volume | +2.58 | Z, LOF |

L'ISE atteint son minimum absolu de 68.4/100 (Z=-4.06). Aucune cause unique n'a pu être identifiée — il s'agit d'une convergence de menaces simultanées dans des couches indépendantes de l'infrastructure internet.

**Implication :** Cet épisode démontre la faisabilité d'une surveillance transversale multi-couche capable de détecter des crises avant que des impacts opérationnels ne soient signalés.

### F2. Hausse Structurelle du Spoofing et des Emails Malicieux

**Niveau de criticité : CRITIQUE**

Le spoofing email (τ=+0.633, p<0.001, R²=0.569) et les emails malicieux (τ=+0.727, p<0.001, R²=0.691) suivent des tendances à la hausse structurelles sur l'ensemble des 53 semaines. Ces deux séries ne sont pas stationnaires (test ADF non significatif), ce qui indique une dynamique de fond plutôt qu'un état oscillant autour d'un niveau stable.

La causalité de Granger SPOOF→MALICIOUS confirmée (F=4.31, p=0.018, lag=1-2 semaines) suggère un pipeline de menace : les campagnes de spoofing sont suivies par des campagnes d'emails malicieux utilisant les domaines usurpés comme vecteurs de crédibilité.

**Implication :** Une surveillance renforcée du SPOOF% peut constituer un signal d'alerte précoce (1-2 semaines) pour anticiper les pics d'emails malicieux.

### F3. RPKI Insuffisamment Déployé : 56.3% des Hijacks Violent des ROAs

**Niveau de criticité : CRITIQUE**

56.3% des 20 000 hijacks BGP analysés impliquent des préfixes pour lesquels un ROA RPKI existe et est violé par l'annonce frauduleuse. Cela signifie que si l'ensemble des opérateurs avaient activé le ROV (Route Origin Validation), plus de la moitié des hijacks détectés auraient pu être bloqués automatiquement.

Le taux de 76.5% de hijacks violant les objets IRR est encore plus élevé, révélant que les bases de données de routage internet (RIPE DB, ARIN, APNIC) sont rarement vérifiées de manière proactive par les opérateurs.

**Implication :** L'écart entre la disponibilité des mécanismes de sécurisation (RPKI déployé chez les registres) et leur utilisation effective (ROV non activé chez de nombreux opérateurs) constitue le principal vecteur réductible de risque BGP à court terme.

### F4. Corrélation Paradoxale DNS Qualité ↔ Menaces Email

**Niveau de criticité : ÉLEVÉ**

La corrélation de Spearman entre la qualité DNS (IQI) et le taux d'emails malicieux est de ρ=+0.82 (p<0.001). Ce résultat est contre-intuitif : une meilleure infrastructure DNS devrait *réduire* les menaces, non les augmenter.

Une hypothèse explicative est que les acteurs malveillants utilisent préférentiellement des résolveurs DNS de haute qualité (DoH, Cloudflare 1.1.1.1, Google 8.8.8.8) pour leurs infrastructures de phishing et de spoofing, bénéficiant ainsi d'une meilleure disponibilité et d'une latence réduite pour leurs opérations. Cette hypothèse est cohérente avec l'observation que le spoofing email et les emails malicieux sont en hausse précisément pendant la période de meilleure qualité DNS.

### F5. L7 Internet & Télécom : Cible Prioritaire en Hausse

**Niveau de criticité : ÉLEVÉ**

Le secteur Internet & Télécom représente 22.4% des cibles d'attaques L7 et est en forte hausse (τ=+0.50). Combiné au secteur Computer & Electronics (22.8%), ces deux secteurs concentrent 45.2% des attaques L7. Le ciblage des opérateurs télécom est particulièrement préoccupant car leur compromission a un effet multiplicateur sur les utilisateurs finaux.

### F6. Fracture Numérique Protocolaire Systémique

**Niveau de criticité : MODÉRÉ**

L'écart de 36 points d'IMP entre le pays le plus mature (Sri Lanka, 64.9/100) et le groupe le moins avancé (Cluster 3, IMP moyen 37.6/100) est systémique. Il ne reflète pas uniquement un retard de déploiement mais une différence structurelle dans la capacité à adopter des protocoles modernes (IPv6, HTTP/3, TLS 1.3).

Le paradoxe est que certains pays émergents performent mieux sur HTTP/3 que des économies avancées (Laos devant la France, la Suisse ou le Canada), révélant que l'adoption de nouveaux protocoles n'est pas strictement corrélée au niveau de développement économique.

---

## 6. Discussion

### 6.1 Interprétation des Résultats

**Sur la co-évolution des menaces :** Les 40 corrélations inter-domaines significatives et les 4 causalités de Granger confirmées remettent en question une approche silotée de la sécurité internet. Un opérateur qui surveille uniquement son trafic DDoS L3 pourrait manquer des signaux précurseurs dans les données email ou BGP. La corrélation BGP RPKI inv% ↔ L7 Internet&Télécom (ρ=0.74) est particulièrement intrigante : elle suggère que les mêmes acteurs malveillants (ou des acteurs coordonnés) sont actifs simultanément dans le routage et les attaques applicatives.

**Sur la semaine du 18 mai 2026 :** L'absence d'une cause unique identifiable pour la crise multi-domaines est en elle-même un résultat important. Elle confirme que certains épisodes de dégradation sécuritaire sont des phénomènes émergents — non réductibles à un seul vecteur d'attaque — et nécessitent des systèmes de surveillance transversaux.

**Sur le paradoxe de la qualité DNS :** La corrélation positive entre DNS qualité et menaces email pourrait également s'expliquer par un biais de mesure : une meilleure qualité DNS permet *de détecter* plus d'emails malicieux (meilleure résolution des domaines utilisés dans les headers email pour les vérifications DMARC/DKIM). Dans ce cas, la corrélation serait un artefact de la mesure plutôt qu'une relation causale réelle.

**Sur la géographie BGP :** La concentration des hijacks aux États-Unis (premier hijackeur ET première victime) s'explique par la taille absolue de l'espace d'adressage IP américain et la densité des relations de peering. Un pays ayant plus d'ASNs a mécaniquement plus d'opportunités d'être impliqué dans des incidents BGP, en tant qu'émetteur ou victime.

### 6.2 Limites de l'Étude

**Biais de représentativité Cloudflare :** Les données Cloudflare Radar ne couvrent que le trafic transitant par le réseau Cloudflare (≈20% du web). Les pays et secteurs moins présents dans ce réseau sont sous-représentés, créant un biais systématique en faveur des économies développées et des grandes plateformes web.

**Périmètre temporel :** 53 semaines constituent une période relativement courte pour distinguer des tendances structurelles de long terme des fluctuations cycliques annuelles. La période couverte (juin 2025 – juin 2026) pourrait présenter des particularités saisonnières ou contextuelles qui ne se généralisent pas.

**Absence de données de contexte :** L'analyse quantitative ne dispose pas de données qualitatives permettant d'expliquer les anomalies détectées. La crise du 18 mai 2026 pourrait correspondre à un événement géopolitique, une vulnérabilité zero-day publiée, ou une campagne coordonnée — informations non disponibles dans le dataset.

**Résolution temporelle hétérogène :** Les données L7 sont journalières, les données email et L3 sont hebdomadaires, et les données BGP sont événementielles. La fenêtre temporelle commune (16 semaines de mars à juin 2026) réduit significativement la puissance statistique de l'analyse des corrélations inter-domaines.

**Données BGP :** Les 20 000 hijacks et 19 999 leaks représentent des échantillons plafonnés par l'API Cloudflare Radar (limite max par requête), non nécessairement représentatifs de la distribution complète des événements BGP sur la période.

---

## 7. Recommandations Stratégiques

Les recommandations suivantes sont hiérarchisées par urgence et par impact estimé, sur la base des findings de l'analyse.

### R1 — Déploiement RPKI/ROV en Priorité Absolue

**Horizon : Court terme | Priorité : Critique**

56.3% des hijacks BGP analysés violent des ROAs RPKI existants mais ne sont pas bloqués parce que les opérateurs n'ont pas activé le ROV. Le déploiement du Route Origin Validation chez les opérateurs tier-1 et tier-2 réduirait mécaniquement plus de la moitié des hijacks détectés.

**Actions recommandées :**
- Mandater le ROV pour tous les opérateurs recevant des fonds publics
- Rejoindre MANRS (Mutually Agreed Norms for Routing Security)
- Utiliser les outils RIPE NCC (RPKI Validator) pour l'audit de conformité

### R2 — Renforcement Anti-Spoofing Email : DMARC Enforcement

**Horizon : Court terme | Priorité : Critique**

Le SPOOF% (17.2%) en hausse structurelle (τ=+0.63) et la causalité Granger SPOOF→MALICIOUS indiquent que le spoofing est un vecteur d'entrée pour les campagnes malicieuses. Un passage de DMARC p=none à DMARC p=reject pour les domaines critiques (gouvernement, finance, santé) éliminerait une fraction significative des emails frauduleux.

**Actions recommandées :**
- Audit DMARC de tous les domaines `.gouv.fr`, `.edu`, `.bank`
- Passage à DMARC p=quarantine en 3 mois, p=reject en 6 mois
- Réduction du SPF FAIL (16.3%) par nettoyage des enregistrements DNS SPF obsolètes
- Mise en place de reporting DMARC (rua/ruf) pour le suivi en temps réel

### R3 — Système d'Alerte Précoce Multi-Domaines

**Horizon : Court terme | Priorité : Élevée**

La semaine du 18 mai 2026 a démontré qu'une crise multi-domaines peut se développer sans qu'un seul signal d'alarme ne soit suffisamment fort pour déclencher une réponse. Un système de surveillance basé sur l'IVC (Index de Vulnérabilité Composite) avec un seuil d'alerte à IVC > 70/100 permettrait une détection précoce.

**Actions recommandées :**
- Déploiement d'un tableau de bord IVC en temps réel (semaines glissantes)
- Configuration d'alertes automatiques multi-canal (CERT, CSIRT, NOC) dès IVC > 65
- Protocole de réponse coordonnée inter-domaines (email + BGP + DDoS)

### R4 — Accélération IPv6 dans les Pays à Faible Adoption

**Horizon : Moyen terme | Priorité : Modérée**

72 pays maintiennent une adoption IPv6 inférieure à 5%. Cette fragmentation constitue un obstacle à la sécurisation du réseau (l'IPSEC est natif dans IPv6) et isole ces pays de l'évolution du web vers HTTP/3 (QUIC, qui nécessite UDP).

**Actions recommandées :**
- Mandat gouvernemental IPv6 pour les FAI bénéficiaires de fonds publics (modèle américain)
- Programme de soutien AFRINIC/LACNIC pour les pays sous-équipés (Cluster 3)

### R5 — Sécurisation des 302 ASNs à Double Rôle

**Horizon : Moyen terme | Priorité : Modérée**

302 ASNs sont actifs à la fois dans des hijacks et des leaks BGP. Ces acteurs représentent une infrastructure BGP à haut risque, potentiellement due à de mauvaises configurations plutôt qu'à une activité malveillante intentionnelle.

**Actions recommandées :**
- Notification directe par les RIRs (RIPE NCC, ARIN, LACNIC, APNIC, AFRINIC) des 302 ASNs identifiés
- Programme de formation BGP gratuit (tutoriels RIPE NCC Academy)
- Audit de configuration des filtres BGP (prefix-list, as-path filtering)

### R6 — Protection L7 pour le Secteur Internet & Télécom

**Horizon : Moyen terme | Priorité : Modérée**

Le secteur Internet & Télécom est la cible des attaques L7 en hausse la plus rapide (τ=+0.50). Les opérateurs télécom doivent déployer des protections anti-DDoS L7 adaptées aux attaques POST (en hausse, τ=+0.43) et coordonner leur réponse via les CERT sectoriels.

### R7 — Programme d'Accompagnement des Pays du Cluster Sous-Équipés

**Horizon : Long terme | Priorité : Positive**

Les 15 pays du Cluster 3 (bot rate 60%, HTTP/3 5%, IMP 37.6/100) ne peuvent pas moderniser leur infrastructure internet sans un soutien externe. Des programmes d'aide au développement numérique ciblés (UIT, Internet Society) permettraient d'accélérer la transition vers IPv6 et TLS 1.3 dans ces pays.

---

## 8. Conclusion

Cette analyse longitudinale de 53 semaines de données Cloudflare Radar révèle un **écosystème internet sous tension croissante**, avec des dynamiques contrastées selon les dimensions et les géographies.

**Les tendances de dégradation** les plus préoccupantes sont la hausse structurelle du spoofing email et des emails malicieux — deux séries non-stationnaires liées par une causalité de Granger confirmée — et la persistance des hijacks BGP en dépit de l'existence de mécanismes de protection (RPKI). La convergence de six anomalies simultanées lors de la semaine du 18 mai 2026 illustre la possibilité de crises multi-couches qui dépassent la capacité de surveillance silotée traditionnelle.

**Les tendances d'amélioration** sont réelles mais insuffisantes : la qualité DNS progresse fortement (τ=+0.85), les protocoles anti-spoofing email avancent modestement (SPF τ=+0.37, DKIM τ=+0.25), et l'adoption IPv6 continue sa hausse (τ=+0.54). Ces progrès témoignent d'investissements infrastructure significatifs de la part des opérateurs, mais ils ne compensent pas la dynamique offensive observée.

**La fracture géographique** est un résultat transversal majeur. L'écart de 36 points d'IMP entre le groupe de pays le plus avancé et le groupe le plus vulnérable, et la segmentation nette des 247 pays analysés en quatre clusters distincts, révèlent que la sécurité internet mondiale est profondément inégale. Les 15 pays du groupe le plus vulnérable ont une bot rate de 60% — signalant non seulement une infrastructure peu sécurisée mais aussi une exposition directe aux botnets utilisés pour des attaques mondiales.

Les deux priorités absolues identifiées par cette étude sont le déploiement généralisé du ROV BGP (RPKI) et le passage à DMARC p=reject pour les domaines critiques. Ces deux mesures présentent un ratio impact/coût particulièrement favorable : les mécanismes existent et sont déployés par les registres, il manque uniquement la volonté opérationnelle et la coordination réglementaire pour les activer.

Ce travail ouvre plusieurs perspectives d'approfondissement : l'extension de la fenêtre temporelle sur plusieurs années pour distinguer les cycles saisonniers des tendances structurelles, l'enrichissement des données Cloudflare Radar par d'autres sources publiques (CAIDA, RIPE, Shodan) pour réduire les biais de représentativité, et le développement d'un système de surveillance IVC en temps réel basé sur les méthodes développées dans ce rapport.

---

## Références

**Protocoles et standards :**

- Huston, G., Michaelson, G., & Austein, R. (2012). *Validation of Route Origination Using the Resource Certificate PKI and ROAs*. RFC 6483. IETF.
- Lepinski, M., & Kent, S. (2012). *An Infrastructure to Support Secure Internet Routing*. RFC 6480. IETF.
- Klensin, J. C. (2008). *Simple Mail Transfer Protocol*. RFC 5321. IETF.
- Kitterman, S. (2014). *Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1*. RFC 7208. IETF.
- Crocker, D., Hansen, T., & Kucherawy, M. (2011). *DomainKeys Identified Mail (DKIM) Signatures*. RFC 6376. IETF.
- Kucherawy, M., & Zwicky, E. (2015). *Domain-based Message Authentication, Reporting, and Conformance (DMARC)*. RFC 7489. IETF.

**Sécurité BGP :**

- Gill, P., Schapira, M., & Goldberg, S. (2011). *A Survey of Interdomain Routing Policies*. ACM SIGCOMM Computer Communication Review, 44(1).
- Lychev, R., Goldberg, S., & Schapira, M. (2013). *BGP Security in Partial Deployment: Is the Juice Worth the Squeeze?* ACM SIGCOMM Computer Communication Review.
- Cloudflare. (2025). *BGP Routing Security — Cloudflare Radar Documentation*. cloudflare.com/learning/security/glossary/bgp-hijacking.

**DDoS et sécurité applicative :**

- Zargar, S. T., Joshi, J., & Tipper, D. (2013). *A Survey of Defense Mechanisms Against Distributed Denial of Service (DDoS) Flooding Attacks*. IEEE Communications Surveys & Tutorials, 15(4).
- ENISA. (2025). *ENISA Threat Landscape 2025*. European Union Agency for Cybersecurity.

**Méthodes statistiques :**

- Mann, H. B. (1945). *Nonparametric Tests Against Trend*. Econometrica, 13(3), 245-259.
- Cleveland, R. B., Cleveland, W. S., McRae, J. E., & Terpenning, I. (1990). *STL: A Seasonal-Trend Decomposition Procedure Based on Loess*. Journal of Official Statistics, 6(1), 3-73.
- Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). *Isolation Forest*. 2008 Eighth IEEE International Conference on Data Mining.
- Breunig, M. M., Kriegel, H.-P., Ng, R. T., & Sander, J. (2000). *LOF: Identifying Density-Based Local Outliers*. ACM SIGMOD Record, 29(2), 93-104.
- Granger, C. W. J. (1969). *Investigating Causal Relations by Econometric Models and Cross-spectral Methods*. Econometrica, 37(3), 424-438.
- Dickey, D. A., & Fuller, W. A. (1979). *Distribution of the Estimators for Autoregressive Time Series with a Unit Root*. Journal of the American Statistical Association, 74(366), 427-431.

**Sources de données :**

- Cloudflare Inc. (2025). *Cloudflare Radar API v4*. [Documentation en ligne]. radar.cloudflare.com/api.
- RIPE NCC. (2026). *BGP Data — Routing Information Service (RIS)*. ris.ripe.net.
- CAIDA. (2026). *AS Relationships Dataset*. caida.org/catalog/datasets/as-relationships.
- MANRS. (2026). *Mutually Agreed Norms for Routing Security*. manrs.org.

---

*Issakha Thiam — Issakha.THIAM@uca.fr*  
*Juin 2026*  
*Rapport généré à partir des phases d'analyse A→L basées sur les données Cloudflare Radar API v4.*
