# Prédiction des Indices de Sécurité Internet par Modélisation ARIMA

**Auteur :** Issakha Thiam | **Email :** Issakha.THIAM@uca.fr | **Date :** Juin 2026

---

## Résumé

Cette étude applique la modélisation ARIMA (AutoRegressive Integrated Moving Average) à trois indices synthétiques de sécurité internet — ISE, IMP et IVC — calculés à partir de 53 semaines de données Cloudflare Radar (juin 2025 – juin 2026). Les meilleurs modèles sélectionnés par critère AIC prévoient une relative stabilité de la sécurité email (ISE ≈ 79,9) et de la vulnérabilité composite (IVC ≈ 29,2) à horizon quatre semaines, tandis que la maturité protocolaire (IMP) marque un léger recul attendu.

## Introduction

La capacité à anticiper l'évolution de la posture de sécurité internet présente une valeur opérationnelle directe pour les équipes de défense (SOC, CERT). Les trois indices analysés — Indice de Sécurité Email (ISE), Indice de Maturité Protocolaire (IMP) et Indice de Vulnérabilité Composite (IVC) — synthétisent respectivement l'état de la sécurité des échanges mail, la modernité des protocoles réseau, et l'exposition globale aux risques. La modélisation ARIMA permet d'exploiter la structure temporelle des séries pour produire des prévisions à court terme avec intervalles de confiance.

## Méthodologie

### Construction des indices

- **ISE** : combinaison pondérée des taux DMARC_PASS (×0,35), DKIM_PASS (×0,35), SPF_PASS (×0,30) auxquels on soustrait le niveau moyen de menace email (spam, usurpation, contenu malveillant) pondéré à 0,5.
- **IMP** : normalisation min-max d'une combinaison d'IPv6 (×0,25), HTTP/3 (×0,25), TLS 1.3 (×0,25), TLS QUIC (×0,10), trafic humain (×0,10) et trafic mobile (×0,05).
- **IVC** : combinaison pondérée du risque BGP (×0,30), de la menace email (×0,30), de la faiblesse protocolaire (×0,20) et de l'intensité des attaques réseau (×0,20), multiplié par 100.

### Sélection ARIMA

Pour chaque indice, toutes les combinaisons ARIMA(p,d,q) avec p ∈ {0,1,2}, d ∈ {0,1}, q ∈ {0,1,2} sont évaluées par critère AIC. Le modèle minimisant l'AIC est retenu pour la prévision des quatre semaines suivantes, avec calcul des intervalles de confiance à 95 %.

## Résultats

### Statistiques descriptives des indices (53 semaines)

| Indice | Minimum | Moyenne | Maximum | Écart-type |
|--------|---------|---------|---------|------------|
| ISE    | 68,39   | 80,07   | 84,07   | 2,88       |
| IMP    | 0,00    | 58,76   | 100,00  | 25,47      |
| IVC    | 16,73   | 31,84   | 62,15   | 7,31       |

### Modèles ARIMA sélectionnés et prévisions

| Indice | Modèle       | AIC   | Moy. observée | Prévision S+1 | Prévision S+4 |
|--------|-------------|-------|---------------|---------------|---------------|
| ISE    | ARIMA(1,1,1) | 244,3 | 80,07         | 79,43         | 79,90         |
| IMP    | ARIMA(0,1,0) | 415,1 | 58,76         | 53,82         | 53,82         |
| IVC    | ARIMA(2,1,1) | 356,4 | 31,84         | 46,31         | 29,23         |

L'ISE présente une dynamique ARIMA(1,1,1) caractéristique d'une série avec mémoire à court terme et légère inertie. L'IMP, mieux décrit par une marche aléatoire intégrée ARIMA(0,1,0), reflète une trajectoire imprévisible liée aux fluctuations de l'adoption protocolaire entre pays. L'IVC suit une structure ARIMA(2,1,1) indiquant une dépendance aux deux semaines précédentes.

## Discussion

La prévision de l'ISE à S+4 (79,9) est très proche de la moyenne historique (80,1), confirmant la relative stabilité structurelle de la sécurité email sur l'horizon trimestriel. L'IVC prévu à S+4 (29,2) s'inscrit dans la plage basse de sa distribution historique, ce qui peut indiquer une fenêtre d'exposition réduite.

La forte variance de l'IMP (écart-type de 25,5 sur une plage 0–100) rend sa prévision particulièrement incertaine, comme en témoigne la sélection d'un modèle ARIMA(0,1,0) — la marche aléatoire intégrée étant le modèle le plus parcimonieux face à l'imprévisibilité des dynamiques d'adoption protocolaire mondiale.

## Conclusion

Les modèles ARIMA sélectionnés par AIC confirment qu'une prévision à quatre semaines des indices de sécurité est techniquement réalisable avec une précision acceptable pour ISE et IVC. L'intégration de ces prévisions dans un tableau de bord de cybersécurité permettrait aux équipes opérationnelles d'anticiper les fenêtres de vulnérabilité accrue, notamment lorsque l'IVC prévu dépasse son percentile 75 (35,8).

---

*Issakha Thiam — Issakha.THIAM@uca.fr*
