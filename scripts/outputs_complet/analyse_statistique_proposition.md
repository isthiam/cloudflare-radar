# Proposition d'analyse statistique exhaustive
## Cloudflare Radar — Dataset Vulnérabilités Internet (juin 2025 – juin 2026)

**Périmètre :** 25 fichiers CSV, ~2,9M points de données, 7 catégories thématiques, 253 pays, 52 semaines  
**Chercheur :** Issakha Thiam — Université Clermont Auvergne  
**Date de collecte :** 9 juin 2026  
**Source :** Cloudflare Radar API v4

---

## A. Préparation et qualité des données

### A1. Audit de complétude
- Taux de valeurs manquantes par fichier et par colonne (IQI en particulier : nombreuses cellules vides)
- Matrice de présence/absence par pays × semaine (heatmap) → identifier les zones géographiques sous-représentées
- Vérification de la cohérence des sommes : chaque ligne de distribution doit totaliser ~100 % (tolérance ±0,1 %)

### A2. Nettoyage
- Parsing des colonnes de tableaux JSON dans BGP (`prefixes`, `peer_asns`, `tags`, `countries`) → expansion en colonnes propres
- Normalisation des timestamps : tous en UTC, alignement sur semaine ISO
- Détection des doublons dans `bgp_hijacks.csv` et `bgp_leaks.csv` (sur le champ `id`)
- Suppression du symbole `%` et conversion en float

### A3. Enrichissement externe (optionnel)
- Joindre un référentiel ISO 3166 pour ajouter région ONU, continent, PIB/habitant, niveau de développement numérique → permettre des analyses par blocs géopolitiques

---

## B. Statistiques descriptives globales

### B1. Par jeu de données
Pour chaque fichier : moyenne, médiane, écart-type, min/max, percentiles p5/p25/p75/p95, coefficient de variation, asymétrie (skewness), aplatissement (kurtosis)

| Fichier | Variables cibles |
|---|---|
| `attacks_l3_bitrate` | 5 catégories de taille d'attaque |
| `attacks_l3_protocol` | UDP, TCP, GRE, ICMP |
| `email_*` | PASS/FAIL/NONE par protocole |
| `http_*` | Distributions par pays |
| `iqi_*` | p25, p50, p75 par pays |

### B2. Résumé des grandes tendances
- Part globale des attaques UDP vs TCP sur l'année
- Taux mondial de DMARC PASS, DKIM PASS, SPF PASS (moyenne annuelle)
- Répartition mondiale des navigateurs, OS, appareils
- Part de trafic bot global (moyenne annuelle, tous pays)

---

## C. Analyse temporelle (séries chronologiques)

### C1. Tendances annuelles (52 semaines)
- **BGP timeseries :** tendance linéaire + décomposition STL (Seasonal-Trend Decomposition) → identifier saisonnalité, tendance de fond, résidus
- **DNS timeseries :** idem, plus test de stationnarité ADF (Augmented Dickey-Fuller)
- **Email security :** évolution hebdomadaire du taux de spam, spoofing, malicieux → pic saisonnier ? (holidays, campagnes de phishing)
- **L3 attacks :** tendance de la part des grosses attaques (>100 Gbps) sur 52 semaines

### C2. Granularité journalière (L7 attacks, 85 jours)
- Profil intra-semaine : le trafic DDoS L7 varie-t-il entre jours ouvrés et week-end ?
- Détection de pics : identifier les journées anormalement attaquées (z-score > 3σ)
- Évolution des méthodes HTTP d'attaque dans le temps (GET vs POST)

### C3. Tests statistiques sur les séries
- Test de Mann-Kendall (tendance monotone non paramétrique) sur chaque série temporelle
- Test de Granger : la série BGP timeseries prédit-elle les variations du DNS timeseries ?
- Corrélation croisée (CCF) entre séries décalées : e.g., pics de spam → pics d'attaques L7 ?

### C4. Modélisation prévisionnelle
- ARIMA / SARIMA sur BGP timeseries et DNS timeseries
- Prévision à 4 semaines avec intervalle de confiance 95 %
- RMSE sur validation croisée (walk-forward)

---

## D. Analyse géographique (HTTP + IQI, 253 pays)

### D1. Rankings par métrique
Pour chaque semaine et en moyenne annuelle :
- **Top/Bottom 20 pays** pour chaque indicateur : taux IPv6, taux TLS 1.3, taux HTTP/3, taux bot, latence DNS médiane, bande passante médiane
- **Cartes choroplèthes** (monde) : une carte par variable clé (Python + geopandas ou R + ggplot2)

### D2. Analyse de la maturité protocolaire par pays
Créer un **indice composite de maturité numérique** combinant :

| Indicateur | Pondération |
|---|---|
| % IPv6 | 20 % |
| % TLS 1.3 | 20 % |
| % HTTP/3 | 15 % |
| % HTTP/2 | 10 % |
| Médiane bande passante IQI | 20 % |
| Médiane latence DNS IQI (inversée) | 15 % |

→ Classement mondial, corrélation avec PIB/habitant (si enrichissement externe)

### D3. Analyse de la part de bots par pays
- Distribution des taux de bot (histogramme, boîte à moustaches)
- Test de Kruskal-Wallis : la part de bot varie-t-elle significativement selon le continent ?
- Pays outliers : taux de bot anormalement élevé ou faible (z-score ou IQR)

### D4. Adoption mobile vs desktop par pays
- Corrélation entre taux mobile et niveau de revenu national
- Pays à dominance mobile écrasante (>70 %) vs pays à dominance desktop
- Évolution temporelle : trend mobile ascendant universel ou hétérogène ?

### D5. Qualité Internet (IQI)
- Distribution des médianes de bande passante et de latence DNS (histogrammes log-scale)
- Coefficient de variation intra-pays (stabilité dans le temps)
- Test de Wilcoxon signé : la latence DNS s'est-elle améliorée entre sem. 1 et sem. 52 ?
- Boxplots par région ONU (Afrique, Europe, Asie-Pacifique, Amériques, etc.)

---

## E. Analyse des attaques réseau (L3 / L7)

### E1. Profil des attaques L3
- **Évolution de la taille des attaques :** part des catégories >10 Gbps et >100 Gbps sur 52 semaines → les méga-attaques augmentent-elles ?
- **Composition protocolaire :** test de stabilité de la part UDP/TCP (variance hebdomadaire, test chi² sur distributions)
- **IPv4 vs IPv6 dans les attaques L3 :** comparer avec la part IPv6 du trafic normal (`http_ip_version`) → les attaques utilisent-elles proportionnellement moins d'IPv6 que le trafic légitime ?

### E2. Profil des attaques L7
- **Répartition par secteur d'activité :** qui est le plus ciblé ? (Computer/Electronics 25%, Internet/Telecom 20%…) — barplot avec IC à 95 %
- **Méthodes HTTP :** GET (83%) vs POST (13%) — ces parts sont-elles stables sur les 85 jours ou y a-t-il des périodes de changement de tactique ?
- **Versions HTTP dans les attaques L7 vs HTTP normal :** les attaques sur-utilisent-elles HTTP/1.x par rapport au trafic légitime ?
- **Heatmap secteur × méthode :** certains secteurs sont-ils attaqués préférentiellement via POST (credential stuffing) ?

---

## F. Sécurité email (DMARC / DKIM / SPF)

### F1. Analyse de conformité par protocole
- Distributions des taux PASS/FAIL/NONE pour chaque protocole (boxplots sur 52 semaines)
- Comparaison des taux d'échec : SPF FAIL (16-20%) > DMARC FAIL (4-10%) > DKIM FAIL (1-2%) → hiérarchie attendue ou anormale ?
- Test t apparié (ou Wilcoxon) : les taux de PASS ont-ils significativement évolué sur l'année ?

### F2. Corrélations entre protocoles
- Corrélation Pearson/Spearman : DMARC PASS ~ DKIM PASS ~ SPF PASS
- Quelle combinaison de protocoles prédit le mieux le faible taux de spam/spoofing ?
- Régression : `spam_rate = f(DMARC_fail, DKIM_fail, SPF_fail)` → importance relative de chaque protocole

### F3. Analyse du spam et du spoofing
- Corrélation temporelle entre taux de spam et taux de spoofing (décalé de 0 à 4 semaines)
- Saisonnalité : pic de spam en Q4 (fêtes) ? Pic de phishing au printemps (déclarations fiscales) ?
- Taux de détection malicieux : tendance à la hausse ou stabilisation ?

### F4. Matrice de cohérence email
Corrélation matricielle entre les 6 métriques email → identifier les redondances et les variables indépendantes

---

## G. Analyse BGP (hijacks et leaks)

### G1. Statistiques descriptives des événements

**Hijacks (20 000 événements) :**
- Distribution de la durée (`duration`) : histogramme log-scale, médiane, % d'événements < 1 min / 1h / 24h
- Distribution du `hijack_msgs_count`
- Distribution du `confidence_score` (0-10) : bimodale ? quels seuils ?
- Distribution du `peer_ip_count` et du `on_going_count`
- Nombre de préfixes IP par événement (parse du champ `prefixes`)

**Leaks (20 000 événements) :**
- Distribution du `leak_count`
- Distribution du `peer_count`, `prefix_count`, `origin_count`
- Longueur du segment de fuite `leak_seg` (nombre d'ASNs intermédiaires)
- Proportion d'événements `finished` vs `on_going`

### G2. Analyse temporelle des événements BGP
- Distribution temporelle des hijacks par heure UTC → y a-t-il des horaires préférentiels ?
- Durée des hijacks dans le temps → les hijacks deviennent-ils plus courts (meilleure détection) ?
- Nombre d'événements par jour → identification de journées à activité anormale

### G3. Analyse des acteurs (ASNs)
- **Top 20 ASNs hijackeurs** (`hijacker_asn`) : fréquence, confidence score moyen
- **Top 20 ASNs victimes** (`victim_asns` parsé) : récidive des victimes
- **Top 20 ASNs impliqués dans les leaks** (`leak_asn`)
- Distribution des ASNs : Pareto — est-ce que 20% des ASNs génèrent 80% des événements ?
- Réseau de co-occurrence ASN hijackeur → victime : graphe orienté (NetworkX / igraph)

### G4. Analyse géographique des événements BGP
- **Top pays hijackeurs** (`hijacker_country`) : carte choroplèthe des origines
- **Top pays victimes** (`victim_countries` parsé) : carte des victimes
- **Matrice origine → victime** : heatmap pays hijackeur × pays victime (top 20 × top 20)
- **BGP leaks par pays** : quels pays ont le plus de préfixes impliqués dans des leaks ?

### G5. Analyse de la gravité
- Segmentation par `confidence_score` : haute confiance (≥8) vs basse confiance (<5)
- Les hijacks haute confiance sont-ils plus durables ? Impliquent-ils plus de préfixes ?
- ANOVA ou Kruskal-Wallis : duration ~ confidence_score_quartile
- Analyse des tags (champ `tags` parsé) : quels types de violations RPKI/IRR sont les plus fréquents ?

### G6. BGP Timeseries
- Décomposition STL du volume hebdomadaire de routes BGP
- Comparaison des pics de la timeseries BGP avec les pics d'événements de hijacks
- Corrélation entre volume total BGP et fréquence d'incidents

---

## H. Corrélations inter-domaines

### H1. Sécurité email × qualité Internet
- Corrélation pays : qualité DNS (p50 latence) ~ taux de spam
- Les pays avec meilleure infrastructure réseau ont-ils moins de spam/spoofing ?

### H2. Protocoles web × géographie
- Corrélation : taux IPv6 (HTTP) ~ latence DNS (IQI) par pays
- Corrélation : taux TLS 1.3 ~ bande passante médiane par pays
- Les pays qui adoptent plus vite HTTP/3 ont-ils aussi une meilleure qualité réseau ?

### H3. Trafic bot × protocoles
- Les pays avec plus de trafic bot utilisent-ils proportionnellement plus d'anciens protocoles (TLS 1.0/1.1, HTTP/1.x) ?
- Régression multiple : `bot_rate ~ f(TLS_1.3_rate, HTTP3_rate, bandwidth_p50)`

### H4. Attaques L3/L7 × BGP × DNS
- Les semaines avec plus d'événements BGP correspondent-elles à des pics du trafic BGP global ?
- La série DNS timeseries baisse-t-elle lors des semaines d'activité BGP intense ?

### H5. Adoption mobile × browser × OS
- Corrélation : taux mobile ~ taux Safari (iOS) ; taux desktop ~ taux Chrome/Edge/Firefox
- Cohérence interne Android ~ mobile, iOS ~ mobile (sanity check + détection d'outliers)

---

## I. Clustering et segmentation

### I1. Clustering des pays (k-means / DBSCAN)
**Variables :** taux IPv6, TLS 1.3, HTTP/3, bot_rate, bandwidth_p50, dns_p50, mobile_rate, Chrome %

- Normalisation StandardScaler
- Nombre de clusters optimal : méthode du coude + silhouette score
- Profil de chaque cluster (radar chart par cluster)
- Labelling géopolitique des clusters → correspondent-ils à des blocs (UE, Afrique sub-saharienne, Asie-Pacifique développée, etc.) ?

### I2. Clustering des événements BGP hijacks
**Variables :** duration, peer_ip_count, prefix_count, confidence_score, on_going_count, hijack_msgs_count

- Identifier les types d'attaques BGP (rapide/ciblée, longue/distribuée, etc.)
- Comparer les clusters par pays d'origine

### I3. Analyse en composantes principales (ACP / PCA)
- ACP sur les métriques HTTP par pays → réduire 20+ variables en 2-3 composantes interprétables
- Biplot : visualiser les pays et les variables dans l'espace factoriel
- Variance expliquée par composante

---

## J. Détection d'anomalies

### J1. Anomalies temporelles
- Z-score hebdomadaire sur toutes les séries → alertes si |z| > 3
- Isolation Forest sur BGP timeseries et DNS timeseries
- CUSUM (Cumulative Sum Control Chart) pour détecter des changements structurels dans les tendances email

### J2. Anomalies géographiques
- Pays outliers pour chaque métrique HTTP (méthode IQR)
- Identifier les pays dont les métriques sont incohérentes entre elles (e.g., fort taux iOS mais peu de Safari)
- Map des anomalies géographiques : Z-score par pays × métrique

### J3. Anomalies dans les événements BGP
- ASNs avec fréquence anormalement élevée de hijacks (distribution de Poisson)
- Confidence scores outliers : événements à très faible score récurrents du même ASN
- Durées extrêmes de hijack (top 1 %)

---

## K. Analyse de réseau (BGP)

### K1. Graphe ASN hijackeur → victime
- Nœuds : ASNs ; arêtes orientées : hijackeur → victime (pondérées par fréquence)
- Métriques de graphe : degré entrant/sortant, betweenness centrality, PageRank
- Identifier les ASNs centraux (hubs de victimisation)
- Communautés : algorithme de Louvain → clusters d'ASNs qui s'attaquent mutuellement

### K2. Graphe des leaks (chaîne ASN)
- Modéliser le champ `leak_seg` comme une chaîne d'ASNs
- Identifier les ASNs transitaires récurrents dans les leaks (intermédiaires)

---

## L. Synthèse et visualisations

### L1. Dashboard récapitulatif
Un rapport HTML interactif (Plotly Dash ou Streamlit) avec :
- Timeline globale des incidents (BGP + attaques + email)
- Carte mondiale interactive par métrique sélectionnable
- Évolution temporelle comparative email sécurité

### L2. Rapport PDF exportable
- Executive summary : 5 findings clés chiffrés
- Infographies : top attaquants BGP, carte des taux de bot, évolution TLS
- Tableaux de rankings par pays

### L3. Matrice de corrélation globale
Grande heatmap de corrélation (Spearman) entre toutes les métriques globales disponibles (~30 variables) pour identifier les liaisons systémiques.

---

## Récapitulatif des livrables

| Phase | Méthodes principales | Output attendu |
|---|---|---|
| A — Préparation | Audit qualité, parsing JSON, normalisation | 25 CSVs validés + rapport qualité |
| B — Descriptif | Moments statistiques, distributions | Tableaux de stats par fichier |
| C — Temporel | STL, ADF, Mann-Kendall, Granger, ARIMA | Graphes + modèles prévisionnels |
| D — Géographie | Rankings, choroplèthes, Kruskal-Wallis | Cartes mondiales + classements pays |
| E — Attaques L3/L7 | Chi², comparaisons, heatmaps | Profils d'attaque + comparatif trafic |
| F — Email | Corrélations, régression, Wilcoxon | Modèle spam + matrice cohérence |
| G — BGP | Stats événements, graphe ASN, Pareto | Graphe orienté + carte hijacks |
| H — Inter-domaines | Corrélations, régressions multiples | Matrice inter-domaine |
| I — Clustering | k-means, DBSCAN, PCA | Segmentation pays + profils clusters |
| J — Anomalies | Z-score, Isolation Forest, CUSUM | Alertes temporelles + outliers géo |
| K — Réseau | NetworkX, Louvain, PageRank | Graphe ASN + métriques centrality |
| L — Synthèse | Plotly Dash / Streamlit, PDF | Dashboard interactif + rapport final |

---

## Stack technique recommandée

```
Python
├── pandas, numpy          — manipulation et calcul
├── scipy, statsmodels     — tests statistiques, ARIMA, décomposition STL
├── scikit-learn           — clustering, PCA, Isolation Forest
├── networkx               — graphes ASN (hijacks, leaks)
├── plotly, matplotlib     — visualisations interactives et statiques
├── geopandas, folium      — cartes choroplèthes
└── streamlit / Dash       — dashboard final
```

**Organisation suggérée :** un notebook Jupyter par phase (A à L), plus un notebook `00_pipeline.ipynb` qui orchestre l'ensemble.
