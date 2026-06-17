# La Fracture Numérique de Sécurité : Corrélation entre Développement Économique et Maturité Protocolaire

**Auteur :** Issakha Thiam | **Email :** Issakha.THIAM@uca.fr | **Date :** Juin 2026

---

## Résumé

Cette étude croise les données Cloudflare Radar sur 201 pays avec les données macroéconomiques de la Banque Mondiale (API, 2023) pour tester si le niveau de développement économique détermine l'adoption des protocoles de sécurité internet. Les résultats confirment une corrélation significative PIB/habitant — IPv6 (ρ = 0,339, p < 0,0001) et une différence inter-groupes sur TLS 1.3 (Kruskal-Wallis H = 10,22, p = 0,017). L'adoption IPv6 apparaît comme le marqueur le plus sensible à l'inégalité de développement, contrairement à TLS 1.3 et HTTP/3 qui restent relativement homogènes entre groupes de revenus.

## Introduction

La fracture numérique Nord-Sud a largement été documentée en termes d'accès à internet. Mais une dimension moins explorée concerne la **qualité de sécurité** de cet accès : les pays en développement, au-delà de l'accès, adoptent-ils les protocoles qui protègent cet accès ? L'hypothèse de la "fracture numérique de sécurité" stipule que les pays à faibles revenus présentent un retard structurel dans l'adoption de TLS 1.3, IPv6 et HTTP/3.

## Données et Méthodes

### Sources de données

- **Cloudflare Radar** : moyennes sur 53 semaines (juin 2025 – juin 2026) de TLS 1.3, IPv6 et HTTP/3 pour 252 pays.
- **Banque Mondiale (API REST)** : PIB par habitant en US$ courants (indicateur NY.GDP.PCAP.CD, année 2023) et classification par niveau de revenus (HIC, UMC, LMC, LIC).

### Méthodes statistiques

La corrélation de Spearman est utilisée pour l'association PIB/hab — métriques protocolaires (relation non linéaire). Le test de Kruskal-Wallis compare les quatre groupes de revenus. La jointure sur code ISO-2 produit 201 pays avec données complètes.

## Résultats

### Métriques par niveau de revenu

| Niveau de revenu        | n | TLS 1.3 (%) | IPv6 (%) | HTTP/3 (%) | PIB/hab moyen ($) |
|------------------------|---|-------------|----------|------------|-------------------|
| Revenus élevés (HIC)   | 33 | **69,27**   | **28,16** | 23,50     | 52 962            |
| Revenus moy. sup. (UMC) | 13 | 65,69      | 26,67    | 26,44      | 12 444            |
| Revenus moy. inf. (LMC) | 11 | 68,69      | 18,23    | 24,69      | 3 016             |
| Revenus faibles (LIC)  | 3  | 64,78       | 1,21     | 26,17      | 1 094             |

### Corrélations de Spearman (PIB/hab vs métriques)

| Métrique | ρ de Spearman | p-value | n | Significatif |
|----------|---------------|---------|---|--------------|
| TLS 1.3  | 0,158         | 0,0255  | 201 | Oui (faible) |
| IPv6     | **0,339**     | **< 0,0001** | 201 | **Oui (modéré)** |
| HTTP/3   | 0,056         | 0,4297  | 201 | Non          |

### Test Kruskal-Wallis (TLS 1.3 entre groupes de revenus)

H = **10,22** | p = **0,0168** — différences significatives entre les quatre niveaux de revenus.

## Discussion

L'IPv6 est le marqueur le plus discriminant de la fracture numérique de sécurité (ρ = 0,339) : son déploiement nécessite une mise à niveau coûteuse de l'ensemble de l'infrastructure réseau (routeurs, FAI, systèmes d'exploitation), ce qui le rend fortement corrélé au niveau de développement économique. En revanche, TLS 1.3 et HTTP/3, étant principalement des protocoles logiciels déployés au niveau applicatif (navigateurs, CDN), se diffusent plus uniformément grâce à des acteurs globaux comme Cloudflare, Google et Akamai qui standardisent ces protocoles côté serveur indépendamment du pays d'origine du client.

Le résultat surprenant des revenus moyens inférieurs (LMC) avec un TLS 1.3 légèrement supérieur aux revenus moyens supérieurs (UMC : 65,7 % vs 68,7 %) s'explique par la forte hétérogénéité au sein du groupe LMC et par la représentation limitée de chaque groupe dans l'échantillon avec données complètes.

## Conclusion

Cette étude confirme l'existence d'une fracture numérique de sécurité, particulièrement marquée sur IPv6 dont l'adoption est fortement corrélée au niveau de revenus (ρ = 0,339). TLS 1.3 et HTTP/3 semblent mieux résister à cette fracture, grâce à la standardisation imposée par les grands CDN mondiaux. Ces résultats invitent à repenser les programmes d'aide au développement numérique pour inclure explicitement des objectifs d'adoption IPv6.

---

*Issakha Thiam — Issakha.THIAM@uca.fr*
