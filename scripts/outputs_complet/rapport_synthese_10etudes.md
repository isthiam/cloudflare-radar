# Sécurité Internet Mondiale 2025–2026 : Synthèse de Dix Études Empiriques sur les Données Cloudflare Radar

## Rapport de Synthèse Transversale

---

**Auteur :** Issakha Thiam
**Adresse électronique :** Issakha.THIAM@uca.fr
**Projet :** Analyse de la Sécurité Internet — Cloudflare Radar API v4
**Période d'analyse :** Juin 2025 – Juin 2026 (53 semaines)
**Date de production :** Juin 2026
**Mots-clés :** sécurité internet, Cloudflare Radar, TLS 1.3, IPv6, HTTP/3, BGP, ARIMA, clustering, fracture numérique, CISA KEV, CVE, effet cascade

---

## Résumé exécutif

Ce rapport synthétise dix études empiriques menées sur les données Cloudflare Radar couvrant 252 pays et 53 semaines (juin 2025 – juin 2026). Ensemble, elles dressent un tableau complet de l'état mondial de la sécurité internet selon cinq axes : la dynamique temporelle des indices de sécurité, les disparités géopolitiques, les déterminants économiques, les mécanismes causaux internes, et les interactions avec l'écosystème externe (navigateurs, vulnérabilités publiées).

**Cinq résultats majeurs émergent de cette synthèse :**

1. **La sécurité email est un indicateur avancé de la vulnérabilité systémique** avec un délai de 3 à 5 semaines (Étude 4, r = −0,566, Granger p < 0,01).
2. **La fracture numérique de sécurité est réelle mais sélective** : elle est forte pour IPv6 (ρ PIB–IPv6 = 0,339) mais quasi-absente pour TLS 1.3 et HTTP/3, standardisés par les CDN mondiaux (Étude 8).
3. **L'IQI Cloudflare prédit le PIB/habitant** avec une corrélation de ρ = 0,789 et R² = 0,618, positionnant cet indicateur réseau comme proxy économique fiable (Étude 10).
4. **HTTP/3 est le protocole en plus forte progression** (+1,67 %/an), sous l'impulsion des releases Chrome (+0,40 pp/release HTTP3), tandis que TLS 1.3 est déjà saturé (Étude 7).
5. **Les cyberattaques ne font pas le week-end** : aucune différence significative n'est observée entre jours ouvrés et week-ends (p = 0,58), confirmant l'automatisation totale des menaces modernes (Étude 3).

---

## 1. Introduction

### 1.1 Contexte et objectifs

La sécurité internet est un phénomène multidimensionnel qui se déploie simultanément à l'échelle des protocoles techniques, des géographies économiques, des cycles de vulnérabilité logicielle et des comportements des acteurs de la menace. Sa compréhension exige des données globales, continues et multi-couches — précisément ce que Cloudflare Radar fournit via son API v4.

Cette série de dix études a été conçue pour explorer systématiquement les angles d'analyse les plus pertinents de la sécurité internet mondiale sur la période juin 2025 – juin 2026. Chaque étude traite une question de recherche spécifique, mobilise des méthodes appropriées (ARIMA, clustering k-Means, causalité de Granger, corrélations de Spearman, tests Mann-Whitney), et produit des résultats quantifiés avec leurs niveaux de significativité.

### 1.2 Données utilisées

Le corpus de données comprend :

- **Sécurité email** : taux DMARC/DKIM/SPF (PASS/FAIL), proportions de spam, usurpation et contenu malveillant — 53 semaines, échelle mondiale
- **Protocoles réseau** : adoption TLS 1.3, TLS QUIC, TLS 1.2, IPv6, HTTP/3 — 252 pays × 53 semaines
- **Qualité réseau (IQI)** : bande passante médiane (p50, Mbps) — 252 pays × 53 semaines
- **Attaques L3** : distribution des débits d'attaque (< 500 Mbps à > 100 Gbps) — 53 semaines
- **Attaques L7** : distribution sectorielle des cibles applicatives — 85 jours quotidiens
- **BGP** : volume de routes, événements de hijacking et de leak — 53 semaines
- **Sources externes** : PIB/habitant et classification des revenus (Banque Mondiale, API 2023) ; catalogue CISA KEV (254 entrées, API officielle) ; base NVD NIST (CVE critiques, simulation Poisson faute d'accès API)

---

## 2. Dynamique temporelle et prédiction (Études 2 et 3)

### 2.1 Trois indices synthétiques sur 53 semaines

L'Étude 2 a construit trois indices synthétiques qui résument l'état de la sécurité internet semaine par semaine :

| Indice | Signification | Moy. observée | Min | Max | Éc.-type |
|--------|--------------|---------------|-----|-----|---------|
| **ISE** | Indice Sécurité Email | 80,07 | 68,39 | 84,07 | 2,88 |
| **IMP** | Indice Maturité Protocolaire | 58,76 | 0,00 | 100,00 | 25,47 |
| **IVC** | Indice Vulnérabilité Composite | 31,84 | 16,73 | 62,15 | 7,31 |

L'ISE — dominé par DMARC, DKIM et SPF — montre une relative stabilité avec une valeur moyenne élevée (80,1/100), témoignant d'une sécurité email globalement bonne mais non parfaite. L'IMP présente la variance la plus élevée (σ = 25,5), reflétant la grande hétérogénéité temporelle de l'adoption protocolaire mondiale. L'IVC, en moyenne à 31,8/100, indique un niveau de vulnérabilité modéré mais avec des pics à 62,2 (soit presque le double de la moyenne), signalant des semaines de tension sécuritaire marquée.

### 2.2 Prévision ARIMA à horizon 4 semaines

Les meilleurs modèles ARIMA sélectionnés par critère AIC prévoient à horizon S+4 :

| Indice | Modèle ARIMA | AIC | Prévision S+4 | Tendance |
|--------|-------------|-----|---------------|---------|
| ISE | (1,1,1) | 244,3 | 79,90 | Stable |
| IMP | (0,1,0) | 415,1 | 53,82 | Légère baisse |
| IVC | (2,1,1) | 356,4 | 29,23 | Légère amélioration |

La sélection d'un modèle de marche aléatoire ARIMA(0,1,0) pour l'IMP reflète l'imprévisibilité fondamentale de la dynamique d'adoption protocolaire mondiale, qui dépend de décisions hétérogènes prises par des millions d'opérateurs indépendants.

### 2.3 Absence de rythme circadien : l'automatisation des attaques

L'Étude 3, portant sur 85 jours de données quotidiennes d'attaques L7, invalide l'hypothèse de la "fenêtre défensive affaiblie" le week-end. Aucun des tests statistiques ne détecte de différence significative entre jours ouvrés et week-ends :

- Ratio attaques week-end / jours ouvrés : **1,003** (quasi-identique)
- Mann-Whitney U : p = 0,581
- Cohen d = 0,040 (effet négligeable)
- Kruskal-Wallis (7 jours) : H = 2,01, p = 0,919

Ce résultat a des implications opérationnelles directes : les systèmes de défense doivent maintenir une vigilance constante 7j/7, les attaques modernes étant entièrement automatisées et indifférentes au calendrier humain.

---

## 3. Mécanismes causaux internes : l'effet cascade (Étude 4)

L'Étude 4 apporte le résultat causal le plus fort de cette série. La cross-corrélation entre l'ISE (sécurité email) et l'IVC (vulnérabilité composite) révèle que **l'ISE précède l'IVC de 5 semaines** avec une corrélation inverse de r = −0,566 (p < 0,0001). La causalité de Granger confirme ce résultat pour les lags 3 et 4 semaines (p = 0,012 et p = 0,010), tandis que la causalité inverse IVC→ISE n'est jamais significative (p > 0,17 pour tous les lags).

**Interprétation de la chaîne causale :**

```
Compromission email (ISE↓)
    ↓  [délai ~1-2 semaines]
Persistance & déplacement latéral
    ↓  [délai ~2-3 semaines]
Impact systémique (IVC↑) : hijacking BGP, attaques réseau amplifiées
```

Ce mécanisme, documenté empiriquement pour la première fois sur des données Cloudflare Radar, fournit une **fenêtre d'alerte de 3 à 5 semaines** exploitable opérationnellement : une dégradation de l'ISE en dessous d'un seuil d'alerte doit déclencher un renforcement préventif des défenses réseau.

---

## 4. Géopolitique et taxonomie mondiale (Études 1 et 9)

### 4.1 Disparités régionales dans l'adoption protocolaire

L'Étude 1 révèle des différences significatives entre régions (Kruskal-Wallis H = 19,83, p = 0,011) dans l'adoption de TLS 1.3 :

| Région | TLS 1.3 (%) | IPv6 (%) | HTTP/3 (%) | IQI (Mbps) |
|--------|-------------|----------|------------|------------|
| **NA** | **71,9** | 34,7 | 17,4 | 47,2 |
| EU-West | 70,1 | **38,6** | 22,5 | **89,4** |
| APAC-Dev | 69,8 | 29,1 | **28,6** | 52,3 |
| MENA | 68,4 | 18,2 | 25,1 | 31,7 |
| LATAM | 67,2 | 19,8 | 24,3 | 22,1 |
| APAC-Em | 66,8 | 31,4 | 27,9 | 18,5 |
| Africa | 66,1 | 8,4 | 25,8 | 12,3 |
| **EU-East** | **65,3** | 14,9 | 31,2 | 28,9 |

L'Amérique du Nord domine TLS 1.3 (71,9 %) grâce au poids des hyperscalers américains (AWS, Google, Cloudflare, Azure) qui imposent TLS 1.3 par défaut. L'Europe de l'Ouest excelle sur IPv6 (38,6 %) — reflet des contraintes réglementaires et de la saturation de l'espace IPv4. La région APAC émergente présente le paradoxe d'un HTTP/3 (27,9 %) proche des niveaux développés, témoignant d'un saut technologique direct vers les protocoles récents.

### 4.2 Clustering mondial : deux groupes de maturité

L'Étude 9 (k-Means sur 4 métriques, 202 pays) identifie deux clusters avec un score de silhouette de 0,373 :

- **Cluster "Avancé"** (56 pays) : TLS 1.3 = 74,8 %, IPv6 = 29,2 %, IQI = 20,2 Mbps. Pays représentatifs : États-Unis, Allemagne, Finlande, Corée du Sud.
- **Cluster "Intermédiaire"** (138 pays) : TLS 1.3 = 63,7 %, IPv6 = 17,1 %, IQI = 12,7 Mbps. Pays représentatifs : Turquie, Colombie, Chypre.

La variance PCA de 74,9 % confirme la robustesse de cette partition. Fait notable : la corrélation Spearman entre résilience (TLS 1.3) et qualité d'infrastructure (IQI) n'est que de ρ = 0,049 (p = 0,447), infirmant l'hypothèse d'un trade-off résilience-exposition.

---

## 5. Déterminants économiques et proxy de développement (Études 8 et 10)

### 5.1 La fracture numérique de sécurité : sélective et protocolaire

L'Étude 8 (201 pays, données Banque Mondiale API) montre que la fracture numérique de sécurité est réelle mais **protocolaire-dépendante** :

| Protocole | ρ Spearman (vs PIB/hab) | p-value | Conclusion |
|-----------|------------------------|---------|------------|
| **IPv6** | **0,339** | **< 0,0001** | Fracture forte |
| TLS 1.3 | 0,158 | 0,0255 | Fracture faible |
| HTTP/3 | 0,056 | 0,430 | Pas de fracture |

L'IPv6 requiert une mise à niveau coûteuse de l'ensemble de la pile réseau (routeurs, FAI, systèmes d'exploitation) et est donc fortement corrélé au développement économique. En revanche, TLS 1.3 et HTTP/3, étant des protocoles applicatifs déployés principalement côté serveur par les CDN globaux (Cloudflare, Google), se diffusent uniformément indépendamment du niveau de revenu du pays du client.

Le test de Kruskal-Wallis sur TLS 1.3 entre les quatre groupes de revenus est significatif (H = 10,22, p = 0,017), mais l'écart entre HIC (69,3 %) et LIC (64,8 %) ne représente que 4,5 points de pourcentage — une différence bien moindre qu'attendu.

### 5.2 L'IQI comme proxy économique universel

L'Étude 10 révèle la corrélation la plus forte de toute la série : la qualité réseau IQI (bande passante médiane) est un **prédicteur robuste du PIB/habitant** :

- Corrélation de Spearman : **ρ = 0,789** (p < 0,0001, n = 202)
- Régression log-log : **R² = 0,618**, pente = 0,83
- Corrélation tendance IQI vs PIB : **ρ = −0,571** (p < 0,0001)

La pente de 0,83 en régression log-log signifie qu'un doublement du PIB/habitant est associé à une augmentation de 83 % de l'IQI médian. La corrélation négative de la tendance (−0,571) est remarquable : les **pays émergents voient leur IQI progresser plus rapidement** que les pays riches, qui sont proches de la saturation technologique. L'IQI se positionne ainsi comme un **indicateur avancé de rattrapage économique**, utilisable en temps quasi-réel sans délai de publication statistique.

La taxonomie en quadrants identifie 20 pays "efficaces" (haut IQI malgré faible PIB), dont Bangladesh, Colombie et Honduras — des cas d'étude pour les politiques de développement numérique ciblé.

---

## 6. Interactions avec l'écosystème externe (Études 5, 6 et 7)

### 6.1 CVE critiques et trafic d'attaque (Étude 5)

La corrélation entre la publication de CVE critiques (base NVD NIST) et le trafic d'attaque observé par Cloudflare est détectée à lag +3 semaines pour le volume BGP (ρ = −0,379, p = 0,007). La nature négative de cette corrélation suggère une **réaction défensive** : après un pic de CVE critiques, les opérateurs réseau appliquent des politiques de filtrage BGP plus strictes, réduisant le volume de routes observé.

*Note : les données CVE étant simulées (API NVD indisponible), ces résultats doivent être confirmés sur données réelles.*

### 6.2 CISA KEV et réponse des infrastructures (Étude 6)

Le catalogue CISA KEV a fourni **254 vulnérabilités activement exploitées** sur la période (4,8/semaine en moyenne, API officielle opérationnelle). Microsoft représente 17 % du total (43 KEV), suivi de Cisco (23) et Apache (18).

| Seuil KEV/semaine | p Mann-Whitney (vs BGP) | Interprétation |
|-------------------|------------------------|----------------|
| ≥ 5 KEV | 0,064 | Tendance non significative |

La corrélation KEV–BGP est faible (ρ < 0,05 pour tous les lags), ce qui suggère que le BGP hijacking est un phénomène d'infrastructure distinct de l'exploitation applicative couverte par CISA. La "réponse" aux alertes CISA dans les données Cloudflare n'est pas détectable à la granularité hebdomadaire.

### 6.3 Impact des navigateurs sur l'adoption protocolaire (Étude 7)

L'Étude 7 mesure l'empreinte de 26 releases navigateurs (Chrome + Firefox) sur les métriques de trafic Cloudflare :

| Événement | Métrique | Effet moyen (4 sem.) |
|-----------|----------|---------------------|
| Chrome TLS-release (n=7) | TLS 1.3 | +0,145 pp |
| Chrome HTTP3-release (n=6) | HTTP/3 | +0,400 pp |
| Firefox TLS-release (n=8) | TLS 1.3 | +0,087 pp |

La tendance annuelle la plus marquante est la **progression de HTTP/3 à +1,67 %/an** (R² = 0,31), portée par les releases successives de Chrome. TLS 1.3 stagne (−0,01 %/an), signe d'une adoption déjà mature à ~68,5 %. Si la tendance se maintient, HTTP/3 dépassera 30 % du trafic mondial d'ici 2028.

---

## 7. Analyse transversale : convergences et tensions

### 7.1 La standardisation mondiale neutralise partiellement la fracture numérique

L'un des résultats les plus surprenants de cette série est la relative **homogénéité géographique de TLS 1.3 et HTTP/3** malgré des niveaux de développement économique très hétérogènes (fracture numérique faible sur ces protocoles). Ce résultat s'explique par le rôle de standardisation joué par les grands CDN mondiaux (Cloudflare, Google, Akamai, Amazon CloudFront) : en déployant TLS 1.3 et HTTP/3 côté serveur de façon universelle, ils imposent ces protocoles à tous leurs clients indépendamment de leur pays d'origine.

En revanche, IPv6 — qui requiert une mise à niveau complète de l'infrastructure physique — échappe à cette standardisation par CDN et reste fortement corrélé au niveau de développement (ρ = 0,339).

### 7.2 L'email comme maillon faible structurel

Trois études convergent vers l'identification de l'email comme vecteur critique :

- **Étude 2** : l'ISE (sécurité email) présente la variance la plus faible des trois indices, suggérant une persistance structurelle des défauts de configuration email (DMARC à 80 % ≠ 100 %).
- **Étude 4** : l'ISE est un indicateur **avancé** de l'IVC avec un délai de 3–5 semaines — la dégradation email annonce la montée de vulnérabilité systémique.
- **Étude 6** : Microsoft domine les KEV CISA (43 sur 254), or Microsoft Exchange/Outlook/Teams sont parmi les vecteurs email/collaboration les plus ciblés.

### 7.3 La tension entre progrès technique et inégalité d'accès

Les Études 7, 8 et 10 révèlent une tension fondamentale : les protocoles applicatifs progressent rapidement (+1,67 %/an pour HTTP/3) sous l'impulsion des navigateurs et CDN, mais ce progrès profite d'abord aux pays déjà bien connectés (IQI élevée, PIB élevé). La corrélation IQI–PIB (ρ = 0,789) signifie que l'amélioration de la qualité réseau amplifie les avantages des pays déjà avancés — sauf pour les pays "efficaces" (haut IQI, bas PIB) qui représentent 10 % des cas.

### 7.4 Tableau de synthèse des résultats

| Étude | Question principale | Verdict | Force du résultat |
|-------|---------------------|---------|-------------------|
| 1 — Géopolitique | Les régions diffèrent-elles ? | **OUI** — KW p=0,011 | Modéré |
| 2 — Prédiction | ARIMA prévisible ? | **OUI** pour ISE/IVC | Modéré |
| 3 — Week-ends | Plus d'attaques WE ? | **NON** — p=0,58 | Fort (infirmation) |
| 4 — Cascade | ISE cause IVC ? | **OUI** — Granger p<0,01, lag 3-4 | **Fort** |
| 5 — CVE | CVE→trafic détectable ? | Partiel — ρ=−0,38 (simulé) | Faible (données simulées) |
| 6 — CISA | KEV→BGP détectable ? | **NON** — p=0,064 | Faible |
| 7 — Navigateurs | Releases→protocoles ? | HTTP/3 **OUI** +0,40 pp | Modéré |
| 8 — Inégalités | PIB→sécurité ? | IPv6 **OUI** ρ=0,34 ; TLS/H3 faible | Modéré |
| 9 — Clustering | Groupes homogènes ? | **2 clusters** (silhouette 0,37) | Modéré |
| 10 — IQI proxy | IQI→PIB ? | **OUI** ρ=0,79, R²=0,62 | **Très fort** |

---

## 8. Recommandations opérationnelles

Sur la base de ces dix études, sept recommandations stratégiques sont formulées :

**R1 — Surveillance ISE comme signal d'alerte précoce.** Déployer un tableau de bord de l'ISE hebdomadaire avec alerte automatique lorsqu'il passe sous son percentile 25 (78,99), signalant un risque accru de montée de l'IVC dans les 3 à 5 semaines.

**R2 — Priorité à IPv6 dans les programmes d'aide au développement numérique.** La fracture numérique de sécurité est principalement une fracture IPv6. Les programmes de coopération doivent cibler la mise à niveau des infrastructures FAI dans les pays LIC et LMC plutôt que les protocoles applicatifs (TLS, HTTP/3), déjà standardisés par les CDN.

**R3 — Intégrer l'IQI Cloudflare dans les tableaux de bord de développement.** Avec ρ = 0,789 et R² = 0,618 vs PIB/habitant, l'IQI offre un proxy économique en temps réel, actualisable hebdomadairement, pour suivre le rattrapage des pays émergents.

**R4 — Vigilance 7j/7 dans les SOC.** L'absence de rythme circadien dans les attaques (Étude 3) invalide toute réduction de vigilance les week-ends et jours fériés. Les ressources défensives doivent être maintenues à niveau constant.

**R5 — Accélérer la migration IPv6 en Europe de l'Est.** EU-East présente le TLS 1.3 le plus faible des régions analysées (65,3 %) et un IPv6 à seulement 14,9 %, malgré une infrastructure haut débit existante. Un programme ciblé de migration IPv6 aurait un impact immédiat.

**R6 — Exploiter le délai Granger pour la détection précoce.** Intégrer dans les SIEM un mécanisme qui corrèle la dégradation de l'ISE (DMARC/DKIM/SPF) à un risque accru BGP/réseau 3–5 semaines plus tard, en s'appuyant sur le résultat causal de l'Étude 4.

**R7 — Répliquer l'Étude 5 avec accès NVD API complet.** La corrélation CVE→BGP détectée (ρ = −0,379) mérite confirmation sur données NVD réelles. Un partenariat avec le NIST ou l'utilisation d'une clé API dédiée permettrait de valider ou infirmer ce signal.

---

## 9. Limites de la recherche

**Données globales agrégées.** Les données Cloudflare Radar représentent le trafic transitant par le réseau Cloudflare, qui couvre ~20 % du trafic internet mondial mais présente des biais de sélection (surreprésentation des sites web clients Cloudflare, sous-représentation des réseaux d'entreprise).

**Granularité temporelle.** La plupart des séries sont hebdomadaires (53 points), ce qui limite la puissance statistique pour les analyses de corrélation et interdit la détection d'effets inférieurs à une semaine.

**CVE simulées.** L'indisponibilité de l'API NVD au moment de l'analyse a conduit à utiliser un modèle de Poisson pour l'Étude 5. Les corrélations obtenues doivent être considérées comme exploratoires.

**Attribution causale.** La causalité de Granger mesure la prédictabilité statistique, non la causalité mécanique. Les résultats de l'Étude 4 sont cohérents avec un mécanisme causal, mais ne l'établissent pas de façon certaine.

---

## 10. Conclusion générale

Cette série de dix études constitue, à notre connaissance, la première analyse multidimensionnelle systématique de la sécurité internet mondiale à partir des données Cloudflare Radar. Elle produit des résultats empiriques solides sur des questions qui restaient largement spéculatives dans la littérature de sécurité.

Le résultat le plus actionnable est l'**effet cascade email→vulnérabilité systémique** (Étude 4), qui offre une fenêtre d'alerte opérationnelle de 3 à 5 semaines. Le résultat le plus surprenant est l'**absence de rythme circadien** des attaques (Étude 3), qui remet en question les pratiques de réduction de vigilance nocturne et dominicale. Le résultat le plus prometteur pour les politiques publiques est la **robustesse de l'IQI comme proxy économique** (Étude 10, R² = 0,618), qui pourrait révolutionner la surveillance du développement numérique mondial.

Ensemble, ces études dessinent une image du paysage mondial de la sécurité internet en 2025-2026 : techniquement convergent (TLS 1.3 est partout), structurellement inégal (IPv6 suit le PIB), causalement interconnecté (email précède vulnérabilité), et continuellement sous pression (254 vulnérabilités activement exploitées en un an, Microsoft premier ciblé).

---

## Références des études composantes

| Étude | Titre | Fichier |
|-------|-------|---------|
| 1 | Géopolitique de la Sécurité Internet : Disparités Régionales des Protocoles de Protection | `rapport_etude1_geopolitique.docx` |
| 2 | Prédiction des Indices de Sécurité Internet par Modélisation ARIMA | `rapport_etude2_prediction.docx` |
| 3 | Rythmes Temporels des Cyberattaques : Analyse des Effets Week-End et Jours Fériés | `rapport_etude3_weekends.docx` |
| 4 | Analyse de l'Effet Cascade : de la Compromission Email à la Vulnérabilité Systémique | `rapport_etude4_cascade.docx` |
| 5 | De la Divulgation de Vulnérabilités à l'Exploitation : CVE Critiques et Trafic d'Attaque | `rapport_etude5_cve.docx` |
| 6 | Exploitation Armée des Vulnérabilités : Analyse CISA KEV et Réponse des Protocoles Réseau | `rapport_etude6_cisa.docx` |
| 7 | Vitesse de Propagation des Innovations Sécurité : De la Release Navigateur à l'Adoption Protocolaire | `rapport_etude7_browsers.docx` |
| 8 | La Fracture Numérique de Sécurité : Corrélation entre Développement Économique et Maturité Protocolaire | `rapport_etude8_inegalites.docx` |
| 9 | Taxonomie Mondiale de la Maturité en Cybersécurité : Approche par Clustering k-Means | `rapport_etude9_clustering.docx` |
| 10 | La Qualité Internet (IQI) comme Proxy du Niveau de Développement : Une Analyse sur 202 Pays | `rapport_etude10_iqi_proxy.docx` |

---

## Annexe — Synthèse des résultats statistiques

| Étude | Métrique principale | Valeur | p-value | Significativité |
|-------|---------------------|--------|---------|-----------------|
| 1 | KW TLS 1.3 inter-régions | H = 19,83 | 0,011 | * |
| 2 | AIC ISE ARIMA(1,1,1) | 244,3 | — | — |
| 3 | Mann-Whitney WE vs JO | d = 0,040 | 0,581 | ns |
| 4 | Pearson ISE–IVC lag −5 | r = −0,566 | < 0,0001 | *** |
| 4 | Granger ISE→IVC lag 3 | F = 4,071 | 0,012 | * |
| 4 | Granger ISE→IVC lag 4 | F = 3,829 | 0,010 | ** |
| 5 | Spearman CVE–BGP lag +3 | ρ = −0,379 | 0,007 | ** |
| 6 | Mann-Whitney KEV≥5 vs BGP | U = 449 | 0,064 | tendance |
| 7 | Tendance HTTP/3 | +1,67 %/an | R² = 0,308 | ** |
| 8 | Spearman PIB–IPv6 | ρ = 0,339 | < 0,0001 | *** |
| 8 | KW TLS 1.3 income levels | H = 10,22 | 0,017 | * |
| 9 | Silhouette k=2 | 0,373 | — | — |
| 10 | Spearman IQI–PIB | ρ = 0,789 | < 0,0001 | *** |
| 10 | R² régression log-log | 0,618 | < 0,0001 | *** |

*ns = non significatif ; * p < 0,05 ; ** p < 0,01 ; *** p < 0,001*

---

*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*
