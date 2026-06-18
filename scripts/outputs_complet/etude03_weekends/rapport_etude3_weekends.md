# Rythmes Temporels des Cyberattaques : Analyse des Effets Week-End et Jours Fériés

**Auteur :** Issakha Thiam | **Email :** Issakha.THIAM@uca.fr | **Date :** Juin 2026

---

## Résumé

Cette étude teste l'hypothèse selon laquelle les cyberattaques seraient plus fréquentes les week-ends et jours fériés, lorsque les équipes de sécurité sont réduites. L'analyse de 85 jours de données Cloudflare Radar sur les attaques L7 (mars–juin 2026) révèle que **l'hypothèse n'est pas confirmée** statistiquement : les secteurs Finance et Gambling ciblés par les attaques montrent une proportion similaire en semaine (32,0 %) et le week-end (32,1 %), sans différence significative (Mann-Whitney p = 0,58 ; Cohen d = 0,04). Ces résultats suggèrent que les attaquants modernes s'adaptent aux horaires des cibles plutôt qu'aux absences défensives.

## Introduction

L'hypothèse de la "fenêtre défensive affaiblie" postule que les cyberattaques exploitent les périodes où les équipes de réponse aux incidents sont réduites (week-ends, jours fériés). Plusieurs études de l'industrie suggèrent en effet que de nombreux ransomwares sont déclenchés le vendredi soir. Nous testons cette hypothèse sur des données mondiales de distribution sectorielle des attaques applicatives (L7) issues de Cloudflare Radar.

## Données et Méthodes

Les données proviennent du fichier `attacks_l7_vertical_clean.csv` couvrant 85 jours (17 mars – 9 juin 2026), avec la répartition quotidienne des attaques L7 par secteur économique cible. Comme les colonnes représentent des distributions en pourcentage (somme = 100 %), nous construisons un indice de sensibilité "week-end" ciblant les secteurs a priori plus actifs le week-end : Finance, Gambling, Shopping, Arts et Loisirs.

Les tests utilisés sont le test de Mann-Whitney U (non paramétrique, ne supposant pas la normalité) et le test de Kruskal-Wallis sur les sept jours de la semaine. L'ampleur de l'effet est quantifiée par le d de Cohen.

## Résultats

### Distribution par jour de la semaine

| Jour       | Score moyen (%) | Écart-type | n jours |
|------------|----------------|------------|---------|
| Lundi      | 32,09           | 2,54       | 12      |
| Mardi      | 31,80           | 3,66       | 13      |
| Mercredi   | 31,92           | 2,53       | 12      |
| Jeudi      | 31,60           | 1,47       | 12      |
| Vendredi   | 32,75           | 3,44       | 12      |
| **Samedi** | **31,88**       | 2,67       | 12      |
| **Dimanche** | **32,40**     | 2,65       | 12      |

### Tests statistiques

| Test | Statistique | p-value | Interprétation |
|------|-------------|---------|----------------|
| Mann-Whitney U (WE vs JO) | — | 0,5812 | Non significatif |
| Kruskal-Wallis (7 jours) | H = 2,01 | 0,9184 | Non significatif |
| Cohen d (WE−JO) | 0,040 | — | Effet négligeable |
| Ratio WE/JO | 1,003 | — | Quasi-identique |

### Secteurs les plus ciblés

Les secteurs dominants dans les attaques L7 sont, dans l'ordre : Informatique & Électronique (~26 %), Internet & Télécoms (~20 %), puis Finance (~8 %) et Gambling (~8 %). La part du secteur Finance est légèrement supérieure le vendredi (pic à 32,75 %) sans atteindre la significativité statistique.

## Discussion

L'absence de différence significative entre week-ends et jours ouvrés suggère que les cybercriminels ont adopté une stratégie indépendante du calendrier défensif. Deux explications sont plausibles : (1) la mondialisation des attaques permet de cibler 24/7 sans dépendre d'un fuseau horaire ou d'un calendrier particulier ; (2) les attaques L7 observées dans ce jeu de données sont largement automatisées (bots, scrapers, DDoS applicatifs), et les botnets ne "font pas le week-end". La donnée disponible (85 jours de répartition sectorielle) ne capture pas les volumes absolus d'attaque, ce qui constitue une limite importante.

## Conclusion

Sur la période mars–juin 2026, les données Cloudflare Radar ne permettent pas de valider l'hypothèse de la "fenêtre défensive affaiblie" pour les attaques applicatives L7. La distribution sectorielle des attaques est quasi-identique tous les jours de la semaine (ratio WE/JO = 1,003). Ce résultat plaide pour une vigilance constante des équipes SOC, indépendamment du calendrier.

---

*Issakha Thiam — Issakha.THIAM@uca.fr*
