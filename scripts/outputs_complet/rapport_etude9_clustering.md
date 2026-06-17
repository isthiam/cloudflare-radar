# Taxonomie Mondiale de la Maturité en Cybersécurité : Approche par Clustering k-Means

**Auteur :** Issakha Thiam | **Email :** Issakha.THIAM@uca.fr | **Date :** Juin 2026

---

## Résumé

Cette étude applique un algorithme k-Means sur quatre métriques de maturité protocolaire (TLS 1.3, IPv6, HTTP/3, IQI bande passante) pour partitionner les 252 pays couverts par Cloudflare Radar en groupes homogènes. L'analyse identifie deux clusters distincts (score de silhouette optimal = 0,373), expliquant 74,9 % de la variance en projection PCA bidimensionnelle. Le cluster "avancé" (56 pays, TLS 1.3 moy. = 74,8 %) se distingue du cluster "en développement" (138 pays, TLS 1.3 = 63,7 %) principalement sur IPv6 et TLS 1.3. La corrélation entre résilience (TLS 1.3) et exposition (IQI) est quasi-nulle (ρ = 0,049), infirmant l'hypothèse d'un trade-off résilience-exposition.

## Introduction

La classification des pays selon leur niveau de maturité en cybersécurité permet d'identifier des groupes homogènes pour lesquels des politiques d'accompagnement ciblées pourraient être formulées. Le clustering non supervisé, par opposition aux classifications basées sur des jugements experts, laisse les données révéler leur propre structure. Nous testons également l'hypothèse selon laquelle les pays les plus exposés aux cybermenaces adoptent plus rapidement les protocoles de protection.

## Méthodes

### Variables et prétraitement

Les données proviennent de Cloudflare Radar sur 53 semaines (juin 2025 – juin 2026) pour 252 pays. Pour chaque pays, la moyenne temporelle de quatre métriques est calculée :
- **TLS 1.3** : adoption du protocole TLS v1.3 (%, moyenne mondiale sur tous les requêtes HTTP)
- **IPv6** : part du trafic IP en version 6 (%)
- **HTTP/3** : adoption du protocole HTTP/3 (%)
- **IQI p50** : médiane de la bande passante (Mbps, indicateur IQI Cloudflare)

Les pays présentant plus de 50 % de valeurs manquantes sur ces quatre métriques sont exclus. Les valeurs manquantes résiduelles sont imputées par la médiane globale. Une normalisation StandardScaler est appliquée avant le clustering.

### Sélection du nombre de clusters

Le nombre optimal k est sélectionné par maximisation du score de silhouette sur k ∈ {2, 3, 4, 5}.

## Résultats

### Sélection du k optimal

| k | Score de silhouette | Interprétation |
|---|---------------------|----------------|
| 2 | **0,373**           | Optimal        |
| 3 | 0,312               |                |
| 4 | 0,287               |                |
| 5 | 0,261               |                |

### Profil des deux clusters

| Cluster | Taille | TLS 1.3 (%) | IPv6 (%) | HTTP/3 (%) | IQI (Mbps) | Pays représentatifs |
|---------|--------|-------------|----------|------------|------------|---------------------|
| C0 — Intermédiaire | 138 | 63,7 | 17,1 | 28,3 | 12,7 | CY, CO, TR, BM, VI |
| C1 — Avancé | 56 | **74,8** | **29,2** | 15,5 | **20,2** | US, DE, FI, EC, MS |

Le cluster C1 "Avancé" se distingue principalement par une adoption TLS 1.3 supérieure (+11,1 points de pourcentage), une meilleure pénétration IPv6 (+12,1 pp) et une qualité réseau plus élevée (IQI = 20,2 vs 12,7 Mbps). L'adoption HTTP/3 est paradoxalement plus élevée dans C0 (28,3 %) que dans C1 (15,5 %), ce qui suggère que HTTP/3 s'est diffusé dans des marchés à infrastructure plus récente, sans nécessairement accompagner une adoption complète de TLS 1.3.

### Réduction dimensionnelle PCA

La projection sur les deux premières composantes principales explique **74,9 %** de la variance totale, ce qui valide la représentativité de la visualisation 2D. Les deux clusters sont visuellement séparés sur PC1 (principalement portée par TLS 1.3 et IPv6).

### Test de l'hypothèse résilience-exposition

La corrélation de Spearman entre l'adoption TLS 1.3 (proxy de résilience) et la qualité IQI (proxy d'exposition/infrastructure) est **ρ = 0,049** (p = 0,447), statistiquement non significative.

## Discussion

L'émergence de seulement deux clusters reflète la dichotomie fondamentale du paysage mondial de la sécurité internet : un groupe de pays à maturité avancée (principalement OCDE + grandes économies émergentes) et un groupe de pays en transition numérique. La faible corrélation résilience-exposition (ρ = 0,049) invalide l'hypothèse que les pays les plus exposés adoptent plus rapidement les protections — la maturité protocolaire est davantage corrélée au niveau de développement économique et à la qualité des infrastructures.

## Conclusion

La classification k-Means identifie deux groupes de pays avec des profils de maturité en cybersécurité distincts. Ces clusters constituent une base opérationnelle pour cibler les programmes de coopération internationale en cybersécurité, notamment vers les 138 pays du cluster C0 qui présentent un déficit structurel d'adoption IPv6 et de qualité réseau.

---

*Issakha Thiam — Issakha.THIAM@uca.fr*
