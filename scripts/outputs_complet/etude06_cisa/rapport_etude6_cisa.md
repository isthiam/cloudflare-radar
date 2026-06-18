# Exploitation Armée des Vulnérabilités : Analyse CISA KEV et Réponse des Protocoles Réseau

**Auteur :** Issakha Thiam | **Email :** Issakha.THIAM@uca.fr | **Date :** Juin 2026

---

## Résumé

Cette étude croise le catalogue CISA Known Exploited Vulnerabilities (KEV) — des vulnérabilités confirmées comme exploitées dans la nature — avec les données Cloudflare Radar sur les événements BGP et l'adoption TLS 1.3. Sur la période juin 2025 – juin 2026, 254 vulnérabilités KEV ont été ajoutées au catalogue (environ 4,8/semaine). Microsoft domine avec 43 entrées. L'analyse de corrélation révèle des liens faibles entre l'intensité hebdomadaire des ajouts KEV et les événements BGP (p = 0,064 pour le test Mann-Whitney ≥ 5 KEV/semaine), suggérant que la réponse des opérateurs réseau aux alertes CISA est lente ou non mesurable à la granularité hebdomadaire.

## Introduction

Le catalogue CISA KEV (Known Exploited Vulnerabilities) est la liste officielle américaine des vulnérabilités dont l'exploitation active est confirmée par des agences de renseignement. Contrairement aux CVE divulguées (qui incluent des risques théoriques), les KEV représentent des menaces certifiées en cours d'exploitation. L'hypothèse testée ici est que les semaines avec de nombreuses additions KEV sont corrélées à une augmentation des anomalies BGP (hijacking, leaks) et à une accélération de l'adoption TLS 1.3 (réponse défensive).

## Données

### CISA KEV (API officielle)

Le catalogue a été téléchargé depuis l'API officielle CISA (JSON). Sur la période d'analyse, **254 vulnérabilités** ont été ajoutées, soit une moyenne de **4,8 KEV/semaine**. Les champs exploités sont : vendeur (vendorProject), produit, date d'ajout, et action corrective requise.

### Cloudflare Radar

- **BGP hijacks** : événements de détournement BGP agrégés par semaine
- **TLS 1.3** : adoption mondiale moyenne hebdomadaire (252 pays)

## Résultats

### Top 10 vendeurs dans le catalogue KEV (2025-2026)

| Vendeur | Nombre de KEV |
|---------|--------------|
| Microsoft | 43 |
| Cisco | 23 |
| Apache | 18 |
| VMware | 15 |
| Fortinet | 12 |
| Ivanti | 11 |
| Adobe | 10 |
| Google | 9 |
| F5 | 8 |
| SolarWinds | 7 |

### Corrélations KEV → indicateurs réseau (lags 0–4 semaines)

**KEV → BGP hijacks :**

| Délai | ρ Spearman | p-value |
|-------|------------|---------|
| +0 sem | −0,003 | 0,982 |
| +1 sem | 0,028 | 0,848 |
| +2 sem | −0,045 | 0,752 |
| +3 sem | 0,026 | 0,856 |
| +4 sem | 0,034 | 0,817 |

**KEV → TLS 1.3 adoption :**

Toutes corrélations KEV→TLS 1.3 sont inférieures à |ρ| = 0,1 et non significatives (p > 0,5).

### Test Mann-Whitney : semaines à forte activité KEV (≥ 5) vs ordinaires

Mann-Whitney U = 449,0 | **p = 0,064** (tendance non significative à α = 0,05)

Ce résultat est à la frontière de la significativité statistique : les semaines avec ≥ 5 KEV tendent à présenter légèrement plus d'activité BGP anormale, sans atteindre le seuil de 5 %.

## Discussion

L'absence de corrélation significative entre les additions KEV et les événements BGP suggère que les hijackings BGP ne sont pas directement déclenchés ou détectés en réponse aux alertes CISA. Deux facteurs expliquent ce résultat : (1) le BGP hijacking est un phénomène distinct de l'exploitation applicative de CVE — il concerne l'infrastructure de routage plutôt que les applications ; (2) le délai entre une alerte CISA et une éventuelle réponse BGP peut dépasser les 4 semaines analysées.

La domination de Microsoft (43 KEV, 17 % du total) confirme son statut de cible prioritaire des États-nations et des groupes criminels. La présence d'Ivanti (11 KEV) et SolarWinds (7 KEV) rappelle les campagnes d'espionnage parrainées par des États exploitant des équipements d'administration réseau.

## Conclusion

Le catalogue CISA KEV fournit un signal d'alerte de haute qualité sur les vulnérabilités actives, mais son impact sur les indicateurs réseau Cloudflare n'est pas directement mesurable à la granularité hebdomadaire. Une analyse à résolution quotidienne, ou ciblant spécifiquement les KEV liées à des protocoles réseau (BGP, DNS, TLS), serait nécessaire pour détecter un signal plus précis.

---

*Issakha Thiam — Issakha.THIAM@uca.fr*
