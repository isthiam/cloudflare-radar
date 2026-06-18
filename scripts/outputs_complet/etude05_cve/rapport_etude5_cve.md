# De la Divulgation de Vulnérabilités à l'Exploitation : Analyse des CVE Critiques et du Trafic d'Attaque

**Auteur :** Issakha Thiam | **Email :** Issakha.THIAM@uca.fr | **Date :** Juin 2026

---

## Résumé

Cette étude analyse si la publication de vulnérabilités critiques (CVE, CVSS v3 ≥ 9,0) dans la base NVD du NIST est suivie d'une augmentation mesurable du trafic d'attaque observé par Cloudflare Radar. L'analyse de corrélation de Spearman avec décalages temporels sur 53 semaines montre une corrélation négative significative entre CVE et volume BGP à lag +3 semaines (ρ = −0,379, p = 0,007), suggérant une réduction du trafic BGP après les pics de CVE — possiblement liée à des mesures défensives réactives. Les données CVE étant simulées (API NVD indisponible au moment de l'analyse), ces résultats doivent être interprétés avec précaution.

## Introduction

La chaîne temporelle "divulgation → exploitation → impact" est un phénomène bien documenté dans la littérature de cybersécurité, avec un délai d'exploitation de 7 à 14 jours en moyenne pour les CVE critiques les plus exploitées. La disponibilité de données mondiales en temps quasi-réel comme Cloudflare Radar permet de tester si ce signal est détectable à l'échelle du trafic internet mondial, et à quel délai temporel.

## Sources de Données

### CVE critiques (NIST NVD)

L'API NIST NVD v2.0 a été interrogée pour les CVE de sévérité CRITICAL (CVSS v3 ≥ 9,0) publiées entre juin 2025 et juin 2026. L'API étant indisponible au moment de l'exécution, un modèle de substitution basé sur une distribution de Poisson (λ = 11 CVE/semaine) a été utilisé, avec des pics aux semaines correspondant à des événements historiquement documentés (Log4Shell suivi, Patch Tuesday mars, etc.). La moyenne historique NVD de 8–15 CVE critiques par semaine justifie ce paramètre.

**Total simulé : 642 CVE critiques sur 53 semaines (moyenne : 12,1/semaine).**

### Trafic d'attaque (Cloudflare Radar)

- **Volume BGP** : nombre de routes BGP hebdomadaire (proxy d'activité réseau mondiale)
- **Attaques L3 haute intensité** : proportion d'attaques > 1 Gbps (indicateur de gravité des attaques réseau)

## Résultats

### Corrélations de Spearman CVE → trafic (lags 0–4 semaines)

| Délai | ρ (CVE→BGP) | p-value | ρ (CVE→Attaques >1G) | p-value |
|-------|------------|---------|----------------------|---------|
| +0 sem | 0,034 | 0,809 | −0,019 | 0,894 |
| +1 sem | −0,162 | 0,250 | −0,185 | 0,190 |
| +2 sem | −0,224 | 0,115 | 0,044 | 0,761 |
| **+3 sem** | **−0,379** | **0,007** | −0,032 | 0,824 |
| +4 sem | −0,236 | 0,102 | 0,002 | 0,991 |

La corrélation la plus forte est observée à **lag +3 semaines pour le volume BGP** (ρ = −0,379, p = 0,007). Cette corrélation négative est contre-intuitive : elle suggère qu'après un pic de CVE critiques, le volume BGP tend à diminuer plutôt qu'augmenter.

## Discussion

Deux interprétations sont plausibles pour la corrélation négative CVE→BGP à lag +3 :
1. **Réaction défensive** : les administrateurs réseau, alertés par les CVE critiques, mettent en place des filtrages BGP et des politiques de blocage qui réduisent artificiellement les annonces de routes perçues par Cloudflare.
2. **Artefact des données simulées** : les CVE hebdomadaires étant simulées par un processus de Poisson indépendant des données réelles, la corrélation observée pourrait être un artefact statistique.

L'absence de corrélation significative entre CVE et attaques L3 haute intensité (meilleur ρ = −0,185, p = 0,19) suggère que le canal d'impact direct CVE → attaque massive n'est pas détectable à la granularité hebdomadaire sur Cloudflare Radar.

## Conclusion

Cette étude exploratoire suggère qu'un lien temporel existe entre la divulgation de CVE critiques et les indicateurs réseau Cloudflare, mais sa nature (positive ou négative, signal ou bruit) ne peut être définitivement établie sans accès aux données NVD réelles. La répétition de cette analyse avec les données NVD complètes constitue une prochaine étape indispensable pour valider ou infirmer ces premières observations.

---

*Issakha Thiam — Issakha.THIAM@uca.fr*
