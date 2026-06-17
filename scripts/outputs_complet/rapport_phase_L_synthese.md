# Rapport Phase L — Synthèse Finale
## Analyse Complète de la Sécurité Internet (Cloudflare Radar)

**Cloudflare Radar Dataset — Juin 2025 / Juin 2026**  
**Chercheur :** Issakha Thiam — Université Clermont Auvergne  
**Généré le :** 2026-06-17 10:06:46

---
## 0. Vue d'Ensemble du Projet

| Aspect | Valeur |
|---|---|
| Dataset source | Cloudflare Radar API v4 |
| Période couverte | Juin 2025 – Juin 2026 (53 semaines) |
| Fichiers analysés | 25 CSV nettoyés |
| Lignes de données | ~2.9M |
| Pays couverts | 252 (HTTP/IQI) · 174 victimes BGP · 247 (clustering) |
| Phases d'analyse | A → L (12 phases) |
| Scripts Python | 9 scripts de ~300-400 lignes chacun |
| Rapports générés | 9 rapports Markdown (phases C → K) |

---
## 1. Dashboard — Indicateurs Clés de Performance (KPIs)

### 1.1 Sécurité du Routage BGP

| KPI | Valeur | Tendance | Risque |
|---|---|---|---|
| Hijacks BGP analysés | 19,977 | — | ⚠️ |
| Leaks BGP analysés | 19,999 | — | ⚠️ |
| Confiance moy. hijacks | 6.0/12 | — | 🟡 |
| Hijacks avec RPKI invalide | 56.3% | — | 🔴 Critique |
| Durée médiane hijack | 0.0 h | — | 🟡 |
| Durée max hijack | 2534 h = 106 jours | — | 🔴 |
| Pays hijackeurs | 141 | — | 🟡 |
| ASNs à double rôle (hij+leak) | 302 | — | ⚠️ |

### 1.2 Qualité DNS

| KPI | Valeur | Tendance | Risque |
|---|---|---|---|
| DNS qualité (IQI p50 moyen) | 0.7587 | ↑↑ forte hausse (τ=0.85) | 🟢 En amélioration |

### 1.3 Sécurité Email

| KPI | Valeur | Tendance | Risque |
|---|---|---|---|
| DMARC PASS% | 87.9% | → stable | 🟢 |
| DKIM PASS% | 89.4% | ↑ hausse modérée | 🟢 |
| SPF PASS% | 79.0% | ↑ hausse forte | 🟢 |
| SPF FAIL% | 16.3% | ↓ baisse | 🟡 |
| SPAM% | 6.2% | ↓↓ forte baisse (τ=-0.44) | 🟡 |
| SPOOF% | 17.2% | ↑↑ forte hausse (τ=0.63) | 🔴 CRITIQUE |
| MALICIOUS% | 10.8% | ↑↑ forte hausse (τ=0.73) | 🔴 CRITIQUE |
| ISE (index global) | 80.1/100 | ↓ légère dégradation | 🟡 |
| ISE minimum observé | 68.4/100 (semaine 2026-05-18) | — | 🔴 |

### 1.4 Maturité Protocolaire (HTTP)

| KPI | Valeur | Tendance | Risque |
|---|---|---|---|
| IPv6 adoption globale | 19.8% | ↑↑ forte hausse (τ=0.54) | 🟡 |
| HTTP/3 adoption | 25.4% | ↑↑ forte hausse (τ=0.34) | 🟡 |
| TLS 1.3 adoption | 66.2% | → stable | 🟢 |
| Bot rate globale | 20.4% | ↑ hausse modérée | 🟡 |
| IMP pays moyen | 43.8/100 | — | 🟡 |
| IMP pays max/min | 58.1 / 21.8 | — | — |

### 1.5 Attaques L3/L7

| KPI | Valeur | Tendance | Risque |
|---|---|---|---|
| L3 UDP% moyen | 74.0% | ↑ hausse modérée (τ=0.23) | 🟡 |
| L3 attaques haut volume (>1 Gbps)% | 29.1% | ↑ hausse | 🟠 |
| L7 Internet&Télécom% | 22.4% | ↑ hausse forte | 🔴 |

### 1.6 Anomalies & Graphe Réseau

| KPI | Valeur |
|---|---|
| Séries analysées (Phase J) | 21 |
| Anomalies consensus (≥2 méthodes) | **42** |
| Semaines multi-domaines anormales | **10** |
| Semaine la plus critique | **2026-05-18** (6 domaines anormaux) |
| Nœuds graphe BGP (ASNs) | 5,287 |
| Arêtes graphe BGP | 5,697 |
| Pays analysés (clustering) | 247 |
| Clusters géographiques | 4 |

---
## 2. Synthèse des Résultats par Phase

### Phase C — Analyse Temporelle

- 53 semaines (juin 2025 – juin 2026), 23 séries analysées
- DNS qualité : forte hausse τ=+0.85 (R²=0.92) — tendance structurelle
- SPOOF : forte hausse τ=+0.63 · MALICIOUS : τ=+0.73 — dégradation email
- Anomalie S50 (2026-05-18) : pics simultanés DMARC FAIL + SPF FAIL + SPOOF + MALICIOUS
- Mobile : τ=-0.75 (baisse) · IPv6 : τ=+0.54 (hausse)

### Phase D — Analyse Géographique

- 252 pays analysés, filtre MIN_WEEKS=20
- IPv6 : moy. 19.9% (σ=19.3%), 17 pays >50%, 72 pays <5%
- HTTP/3 : Laos leader (40.4%) — paradoxe pays émergents
- Bot max : Gibraltar (90.7%) — infrastructure financière offshore
- IMP #1 : Sri Lanka (64.9), Grèce (64.5), Inde (64.3)
- BGP : US+CN+RU = 38.8% hijacks ; US = top hijackeur ET victime
- 7 pays avec TLS 1.0 ≥ 5% (vulnérabilités BEAST/POODLE)

### Phase E — Attaques L3/L7

- L3 (53 semaines) : UDP 74% moy., hausse τ=+0.23
- 57.1% attaques <500 Mbps ; attaques 1-10 Gbps en hausse τ=+0.33
- L3 IPv4 : 99.73% (botnets évitent IPv6)
- L7 (85 jours) : Computer & Electronics (22.8%) + Internet & Telecom (22.4%) = 45% cibles
- Internet & Telecom en hausse forte τ=+0.50
- GET flood 82% mais en baisse ; POST en hausse τ=+0.43

### Phase F — Sécurité Email

- DMARC PASS 87.9% stable · DKIM PASS 89.4% hausse τ=+0.25
- SPF PASS 79.0% hausse τ=+0.37 · SPF FAIL 16.3% (le plus élevé)
- SPAM 6.2% baisse τ=-0.44 · SPOOF 17.2% hausse τ=+0.63 · MALICIOUS 10.8% hausse τ=+0.73
- ISE : 80.1/100 moy., légère baisse τ=-0.22
- Anomalie S50 (2026-05-18) : ISE=68.4 (Z=-4.06) — pire semaine
- Causalité Granger SPOOF→MALICIOUS confirmée (p<0.05)

### Phase G — BGP Hijacks & Leaks

- 20,000 hijacks (déc.2025–juin 2026) · 19,999 leaks (mars–juin 2026)
- RPKI invalide : 56.3% des hijacks, IRR invalide : 76.5%
- Durée médiane hijack : 1.9h · max : 2533h = 106 jours
- Top pays hijackeur : US (23.5%) · Top victime : US (26.4%)
- Sévérité critique : 18.7% des events (conf≥9, préf. moy. 11.5, durée 47h)
- 302 ASNs jouant les deux rôles (hijackeur + leaker)
- 582 leaks encore actifs (2.9%) à la fin de la période

### Phase H — Corrélations Inter-Domaines

- 29 variables × 29 : 40 paires inter-domaines significatives (p<0.05)
- 4 causalités Granger inter-domaines confirmées sur 10 testées
- Corrélation #1 : SPOOF% ↔ IVC (r=0.85)
- BGP RPKI inv% ↔ L7 Internet&Télécom (r=0.74)
- DNS qualité ↔ MALICIOUS% (r=0.82) — découverte majeure
- IVC global moy. : vulnérabilité composite en hausse sur période commune

### Phase I — Clustering Géographique

- 247 pays, 7 features protocolaires, k=4 clusters (silhouette=0.55 pour k=2)
- Cluster Matures & Sécurisés : 111 pays, IMP 46.1/100, HTTP/3 29.9%
- Cluster En développement avancé : 62 pays, IMP 43.1/100
- Cluster Vulnérables intermédiaires : 59 pays, IMP 41.9%, IPv6 8.7%
- Cluster Sous-équipés & à risque : 15 pays, IMP 37.6%, bot 60.0%
- Inde #1 IMP parmi les grands pays (58.1/100)

### Phase J — Détection d'Anomalies

- 21 séries, 4 méthodes (Z-score, IQR, Isolation Forest, LOF)
- 42 anomalies consensus total · 10 semaines multi-domaines
- Semaine 2026-05-18 : 6 domaines anormaux simultanément (pic historique)
- Série la plus anomalique : SPOOF% (4 anomalies)
- 18 pays à profil protocolaire extrême (Isolation Forest)

### Phase K — Graphe Réseau ASN

- Graphe hijacks : 5,287 nœuds, 5,697 arêtes, densité 0.000204
- 886 composantes connexes — structure très fragmentée
- 1,014 ASNs jouant les deux rôles (hijackeur + victime)
- 73.3% des hijackeurs : out-degree = 1 (attaque ponctuelle)
- Graphe leaks : 2,703 nœuds, 5,795 arêtes, 1,848 leakers distincts
- 302 ASNs actifs à la fois dans hijacks ET leaks (infrastructure à risque)

---
## 3. Findings Transversaux Majeurs

### F1. 🔴 CRITIQUE — Semaine 2026-05-18 : Crise Multi-Domaines

La semaine du 18 mai 2026 est la plus critique de la période : 6 domaines anormaux simultanément (SPOOF, DMARC FAIL, SPF FAIL, SPAM, BGP volume, L3 haut vol.). L'ISE atteint son minimum (68.4/100, Z=-4.06). Aucune causalité unique n'a été identifiée — il s'agit d'une convergence de menaces.

### F2. 🔴 CRITIQUE — SPOOF% et MALICIOUS% en hausse structurelle

Le spoofing email (τ=+0.63) et les emails malicieux (τ=+0.73) suivent des tendances à la hausse statistiquement significatives sur 53 semaines. La causalité Granger SPOOF→MALICIOUS est confirmée. Le spoofing email est précurseur des emails malicieux avec un délai de 1-2 semaines.

### F3. 🔴 CRITIQUE — RPKI insuffisamment déployé : 56.3% des hijacks violent des ROAs

56.3% des 20,000 hijacks BGP violent des ROAs RPKI — signifiant que 43.7% des hijacks AURAIENT ECHAPPÉ à une détection RPKI seule. L'adoption du ROV (Route Origin Validation) reste incomplète et urgente.

### F4. 🟠 ÉLEVÉ — DNS qualité en forte hausse mais corrélée aux menaces email

La DNS qualité (IQI) montre une forte hausse (τ=+0.85, R²=0.92) — signe d'une meilleure résolution DNS mondiale. Paradoxalement, elle est fortement corrélée à SPOOF% (r=0.74) et MALICIOUS% (r=0.82), suggérant que les acteurs malveillants utilisent de meilleures infrastructures DNS pour leurs opérations.

### F5. 🟠 ÉLEVÉ — L7 Internet & Télécom : cible prioritaire en hausse

Le secteur Internet & Télécom représente 22.4% des cibles L7 et est en forte hausse (τ=+0.50). Combiné avec le secteur Informatique (22.8%), ces deux secteurs concentrent 45% des attaques L7.

### F6. 🟡 MODÉRÉ — BGP : Réseau très fragmenté, acteurs concentrés

Le graphe BGP est extrêmement creux (densité 0.0002) avec 886 composantes connexes. Cependant, 73.3% des hijackeurs n'attaquent qu'une seule cible (out-degree=1) — majorité d'opportunistes, non de campagnes systématiques. Seuls 4 ASNs (0.2%) sont hyperactifs (≥50 victimes).

### F7. 🟡 MODÉRÉ — Fracture numérique protocolaire : IMP 21.8 → 58.1/100

L'écart d'IMP entre le pays le plus mature (Sri Lanka 58.1) et le moins avancé (21.8) révèle une fracture numérique systémique. 15 pays forment un cluster 'sous-équipé' (bot rate 60%, HTTP/3 5%) qui nécessite un accompagnement infrastructurel urgent.

### F8. 🟡 MODÉRÉ — IPv6 en hausse mais inégale : 17 pays >50%, 72 pays <5%

IPv6 progresse globalement (τ=+0.54) mais avec une variance extrême. Le paradoxe HTTP/3 des pays émergents (Laos 40.4%, Somalie 38.7%) révèle l'adoption de stacks réseau mobiles modernes sans infrastructure IPv6 mature.

### F9. 🟢 POSITIF — Amélioration globale de la DNS qualité

La DNS qualité suit une tendance à la hausse forte (τ=+0.85) sur toute la période — le meilleur signal positif du dataset. Cela indique un investissement continu des opérateurs dans la qualité de résolution DNS mondiale.

### F10. 🟢 POSITIF — SPF et DKIM en amélioration

SPF PASS% (τ=+0.37) et DKIM PASS% (τ=+0.25) progressent — signe que les opérateurs email adoptent progressivement les standards anti-spoofing. Néanmoins, le SPF FAIL reste à 16.3% (trop élevé) et le SPOOF% augmente malgré ces progrès.

---
## 4. Recommandations Stratégiques

| Rec. | Titre | Horizon | Priorité |
|---|---|---|---|
| R1 | Déploiement RPKI/ROV en priorité absolue | Court terme | 🔴 |
| R2 | Renforcement anti-spoofing email : DMARC enforcement | Court terme | 🔴 |
| R3 | Surveillance renforcée post-2026-05-18 | Court terme | 🟠 |
| R4 | Accélération IPv6 dans les pays à faible adoption | Moyen terme | 🟡 |
| R5 | Sécurisation des ASNs à double rôle (hijackeurs + leakers) | Moyen terme | 🟡 |
| R6 | Monitoring L7 Internet & Télécom | Moyen terme | 🟡 |
| R7 | Programme d'accompagnement des pays en cluster 'Sous-équipés' | Long terme | 🟢 |

### R1 — Déploiement RPKI/ROV en priorité absolue
> Horizon : Court terme | Priorité : 🔴

56.3% des hijacks BGP violent des ROAs RPKI mais ne sont pas bloqués par les ISPs. La mise en place du Route Origin Validation (ROV) chez les opérateurs tier-1 et tier-2 réduirait mécaniquement plus de la moitié des hijacks détectés. Rejoindre MANRS (Mutually Agreed Norms for Routing Security) devrait être une priorité gouvernementale.

### R2 — Renforcement anti-spoofing email : DMARC enforcement
> Horizon : Court terme | Priorité : 🔴

Le SPOOF% (17.2%) en hausse structurelle (τ=+0.63) et la causalité Granger SPOOF→MALICIOUS indiquent que le spoofing est un vecteur d'entrée pour les emails malicieux. Passer de DMARC p=none à DMARC p=reject pour les domaines critiques. SPF FAIL à 16.3% doit être réduit par une meilleure gouvernance des enregistrements DNS.

### R3 — Surveillance renforcée post-2026-05-18
> Horizon : Court terme | Priorité : 🟠

La semaine du 18 mai 2026 a montré que des crises multi-domaines simultanées sont possibles. Mettre en place un système d'alerte précoce basé sur l'IVC (Index de Vulnérabilité Composite) avec seuil d'alerte à IVC>70/100 et notification automatique.

### R4 — Accélération IPv6 dans les pays à faible adoption
> Horizon : Moyen terme | Priorité : 🟡

72 pays ont moins de 5% d'IPv6 — cette fragmentation crée des obstacles à la transition vers des protocoles modernes. Les gouvernements devraient imposer des mandats IPv6 pour les fournisseurs d'accès internet financés par des fonds publics.

### R5 — Sécurisation des ASNs à double rôle (hijackeurs + leakers)
> Horizon : Moyen terme | Priorité : 🟡

302 ASNs sont actifs à la fois dans des hijacks et des leaks — indicateur de mauvaise hygiène BGP. Ces ASNs devraient faire l'objet d'audits de configuration et de formation BGP (RIPE NCC, LACNIC, AFRINIC).

### R6 — Monitoring L7 Internet & Télécom
> Horizon : Moyen terme | Priorité : 🟡

Le secteur Internet & Télécom est la cible principale et en forte hausse (τ=+0.50). Les opérateurs de ce secteur devraient déployer des protections anti-DDoS L7 (WAF, rate-limiting) et participer aux CERT sectoriels.

### R7 — Programme d'accompagnement des pays en cluster 'Sous-équipés'
> Horizon : Long terme | Priorité : 🟢

15 pays forment un cluster avec bot rate 60%, HTTP/3 5% et IMP 37.6/100. Ces pays nécessitent un accompagnement technique pour moderniser leur pile réseau (IPv6, TLS 1.3, filtrage bot) — potentiellement via l'aide au développement numérique.

---
## 5. Index des Rapports Générés

| Phase | Fichier | Taille | Contenu |
|---|---|---|---|
| Phase C | `rapport_phase_C.md` | ~53 Ko | Analyse temporelle (23 séries, Mann-Kendall, ADF, STL, ARIMA) |
| Phase D | `rapport_phase_D.md` | ~45 Ko | Géographie (252 pays, HHI, IMP, top/bottom pays) |
| Phase E | `rapport_phase_E.md` | ~54 Ko | Attaques L3/L7 (protocoles, tailles, secteurs, méthodes HTTP) |
| Phase F | `rapport_phase_F.md` | ~39 Ko | Sécurité email (DMARC/DKIM/SPF/SPAM/SPOOF/MALICIOUS, ISE, Granger) |
| Phase G | `rapport_phase_G.md` | ~29 Ko | BGP hijacks & leaks (RPKI/IRR, ASN top, géographie, temporel) |
| Phase H | `rapport_phase_H.md` | ~30 Ko | Corrélations inter-domaines (29×29, Granger, CCF, IVC) |
| Phase I | `rapport_phase_I.md` | ~33 Ko | Clustering géographique (247 pays, PCA, k-means k=4) |
| Phase J | `rapport_phase_J.md` | ~17 Ko | Détection anomalies (Z, IQR, IForest, LOF, 21 séries) |
| Phase K | `rapport_phase_K.md` | ~18 Ko | Graphe réseau ASN (5287 nœuds, PageRank, Betweenness, HITS) |
| Phase L | `rapport_phase_L_synthese.md` | ~30 Ko | Synthèse finale (KPIs, findings, recommandations) |

## 6. Méthodes Statistiques Utilisées

| Méthode | Phase(s) | Objectif |
|---|---|---|
| Mann-Kendall τ | C, H, L | Détection de tendances monotones non-paramétriques |
| ADF (Augmented Dickey-Fuller) | C | Test de stationnarité des séries temporelles |
| OLS (régression linéaire) | C | Quantification de la tendance (pente, R²) |
| STL (Seasonal-Trend Decomposition) | C | Décomposition tendance/saisonnalité/résidu |
| ARIMA (AIC selection) | C | Modélisation et prévision à court terme |
| CCF (Cross-Correlation Function) | C, F, H | Lag optimal entre deux séries |
| Granger Causality (F-test) | C, F, H | Test de causalité temporelle inter-séries |
| Z-score (|z|≥2.5) | C, J | Détection d'anomalies univariées |
| IQR (×2.0) | J | Détection d'anomalies robuste aux queues |
| Isolation Forest | I, J | Détection d'anomalies multi-variées |
| Local Outlier Factor (LOF) | J | Détection d'outliers basée sur densité locale |
| Spearman ρ | H | Corrélation non-paramétrique inter-séries |
| Herfindahl-Hirschman Index (HHI) | D | Concentration géographique des protocoles |
| PCA (Analyse en Composantes Principales) | I | Réduction dimensionnelle features pays |
| K-Means Clustering | I | Segmentation pays par profil protocolaire |
| Silhouette Score | I | Sélection du nombre optimal de clusters |
| PageRank | K | Influence des ASNs dans le graphe de hijack |
| Betweenness Centrality | K | ASNs pivot dans le graphe de routage |
| HITS (Hubs & Authorities) | K | Identification hijackeurs systématiques vs victimes structurelles |

---
## 7. Conclusion

Cette étude de la sécurité internet sur 53 semaines (juin 2025 – juin 2026) via Cloudflare Radar révèle un **écosystème internet sous tension croissante** :

**Sur les menaces :** Le routage BGP reste vulnérable (56% des hijacks violent les ROAs RPKI), le spoofing email progresse structurellement (+63% en tendance), et les attaques L7 ciblent de plus en plus les opérateurs télécom. La semaine du 18 mai 2026 constitue un épisode de crise multi-dimensionnelle sans précédent dans le dataset.

**Sur les défenses :** La qualité DNS s'améliore fortement (+85% en tendance), les protocoles de messagerie (SPF, DKIM) progressent modestement, et l'adoption IPv6 continue sa hausse. Ces signes positifs restent insuffisants face à la dynamique offensive.

**Sur les inégalités :** La fracture entre pays matures (IMP 58/100) et pays sous-équipés (IMP 22/100) est systémique. 72 pays ont moins de 5% d'IPv6 et 15 pays forment un cluster à risque élevé nécessitant un accompagnement international.

La priorité absolue est l'accélération du déploiement RPKI/ROV et le renforcement de l'application DMARC, deux mesures à fort impact et faible coût d'implémentation pour les opérateurs disposant des ressources nécessaires.

---
*Rapport de synthèse généré le 2026-06-17 10:06:46 par `phase_L_synthese.py`.*  
*Projet : Analyse de sécurité internet — Cloudflare Radar API v4.*  
*Université Clermont Auvergne — Issakha Thiam.*