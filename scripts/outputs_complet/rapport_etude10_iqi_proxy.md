# La Qualité Internet (IQI) comme Proxy du Niveau de Développement : Une Analyse sur 202 Pays

**Auteur :** Issakha Thiam | **Email :** Issakha.THIAM@uca.fr | **Date :** Juin 2026

---

## Résumé

Cette étude évalue dans quelle mesure l'indice de qualité internet de Cloudflare Radar (IQI bande passante) prédit le niveau de développement économique des pays. Sur 202 pays, la corrélation de Spearman entre IQI et PIB/habitant atteint **ρ = 0,789** (p < 0,0001), avec un R² de régression log-log de **0,618**. Paradoxalement, les pays émergents affichent une dynamique IQI croissante plus forte que les pays riches (ρ tendance = −0,571, p < 0,0001), indiquant que l'IQI est un indicateur avancé de rattrapage économique plutôt qu'un simple reflet du niveau actuel de développement.

## Introduction

La qualité des infrastructures de connectivité — exprimée par la bande passante disponible — est à la fois un déterminant et un indicateur du développement économique. L'IQI (Internet Quality Index) de Cloudflare Radar, fondé sur des mesures passives à l'échelle mondiale, offre une fenêtre unique sur cette qualité réseau dans 252 pays. Nous testons ici si l'IQI peut servir de proxy économique dans les contextes où les données statistiques nationales sont rares ou peu fiables.

## Données et Méthodes

La médiane de bande passante IQI (p50, en Mbps) est calculée sur 53 semaines (juin 2025 – juin 2026) pour chaque pays. Les données de PIB/habitant proviennent de la Banque Mondiale (API, 2023). La jointure produit 202 pays avec données complètes. La relation étant non linéaire et s'étendant sur plusieurs ordres de grandeur pour le PIB, une régression log-log est privilégiée.

Pour analyser la dynamique temporelle, la pente de régression linéaire de l'IQI sur les 53 semaines est calculée pour chaque pays (indicateur de tendance), puis corrélée au PIB/habitant.

Les pays sont classifiés en quatre quadrants selon leur position par rapport aux médianes globales de l'IQI et du PIB/habitant.

## Résultats

### Corrélation IQI — PIB/habitant

| Mesure | Valeur |
|--------|--------|
| ρ Spearman (IQI vs PIB/hab) | **0,789** |
| p-value | **< 0,0001** |
| n pays | 202 |
| Régression log-log : R² | **0,618** |
| Régression log-log : pente | 0,83 |

La pente de 0,83 en régression log-log signifie qu'un doublement du PIB/habitant est associé à une augmentation de 83 % de l'IQI médian — une élasticité légèrement infra-unitaire.

### Dynamique IQI et niveau de développement

La corrélation de Spearman entre la tendance IQI hebdomadaire et le PIB/habitant est **ρ = −0,571** (p < 0,0001), indiquant que **les pays émergents voient leur IQI progresser plus rapidement** que les pays développés — qui sont probablement déjà proches de la saturation technologique.

### Quadrants IQI × PIB

| Quadrant | n pays | Description | Exemples |
|----------|--------|-------------|----------|
| Leaders (haut IQI, haut PIB) | 81 | Économies matures avec bonne connexion | AE, DE, NL, SG |
| En retard (bas IQI, bas PIB) | 81 | Faible développement et connexion limitée | AF, BI, BF, ML |
| Sous-performants (bas IQI, haut PIB) | 20 | Pays riches avec qualité réseau insuffisante | CN, DM, AG |
| Efficaces (haut IQI, bas PIB) | 20 | Bon IQI malgré ressources limitées | BD, CO, HN |

## Discussion

Le coefficient de détermination R² = 0,618 place l'IQI parmi les proxies économiques les plus corrélés au PIB (à titre de comparaison, les mesures d'accès à l'électricité ou de scolarisation atteignent des R² similaires). Ce résultat suggère que l'IQI Cloudflare Radar pourrait compléter utilement les indicateurs macroéconomiques traditionnels, notamment pour les pays dont les statistiques nationales sont peu fréquentes.

L'identification de 20 pays "efficaces" (bon IQI relatif malgré un faible PIB) est particulièrement intéressante : ces pays ont su développer une infrastructure réseau qualitative malgré leurs contraintes économiques, probablement grâce à des investissements ciblés ou à des mutations technologiques directes (mobile broadband sans infrastructure fixe legacy).

## Conclusion

L'IQI bande passante de Cloudflare Radar est un proxy robuste du niveau de développement économique (ρ = 0,789, R² = 0,618), mais aussi un indicateur avancé du rattrapage des pays émergents, dont la dynamique IQI croissante dépasse celle des pays développés. Ces résultats positionnent l'IQI comme un outil de veille économique et géopolitique à faible coût, utilisable en temps quasi-réel.

---

*Issakha Thiam — Issakha.THIAM@uca.fr*
