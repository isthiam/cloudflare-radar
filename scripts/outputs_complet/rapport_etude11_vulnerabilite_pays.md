# Étude 11 — Indice de Vulnérabilité par Pays : Exposition vs Expérience des Chocs
**Cloudflare Radar Dataset — Juin 2025 / Juin 2026**  
**Auteur :** Issakha Thiam  
**Généré le :** 2026-06-18 10:44:20  

---

## 1. Cadre conceptuel

Cette étude distingue deux dimensions orthogonales de la vulnérabilité internet par pays :

| Dimension | Définition | Variables |
|-----------|------------|-----------|
| **IEC** — Indice d'Exposition aux Chocs | Vulnérabilité structurelle : comment la
qualité de l'infrastructure expose un pays aux perturbations | IPv4 vs IPv6, vieux TLS, absence HTTP/3, faible bande passante, forte latence DNS |
| **IExC** — Indice d'Expérience des Chocs | Chocs effectivement subis : dégradations
mesurées sur la période | Chutes de bande passante, pics de latence DNS, BGP hijacks ciblant le pays, intensité attaques L3 |

> **IVC2** = (IEC + IExC) / 2 — Indice composite de vulnérabilité réalisée

---

## 2. Données et méthode

- **Pays couverts :** 252
- **Semaines :** 53 (Juin 2025 – Juin 2026)
- **Observations totales :** 13,409

### Sources par composante

**IEC (Exposition) :**
- `http_ip_version_clean.csv` → taux IPv4 (dépendance, exposé aux attaques v4)
- `http_tls_version_clean.csv` → proportion TLS ≤ 1.2 (protocoles anciens)
- `http_http_version_clean.csv` → absence HTTP/3 / QUIC
- `iqi_bandwidth_clean.csv` → bande passante médiane (faible = exposé)
- `iqi_dns_clean.csv` → latence DNS médiane (élevée = exposé)

**IExC (Expérience) :**
- `iqi_bandwidth_clean.csv` → chute semaine-sur-semaine de la bande passante
- `iqi_dns_clean.csv` → pic semaine-sur-semaine de la latence DNS
- `bgp_hijacks_clean.csv` → hijacks BGP ciblant ce pays (champ `victim_countries`)
- `attacks_l3_bitrate_clean.csv` → intensité attaques L3 globales (composante mondiale)

**Normalisation :** min-max [0,1] global sur l'ensemble du panel (pays × semaines).  
**IExC = 60% local** (bande passante + DNS + BGP pays) **+ 40% global** (L3 attacks).

---

## 3. Résultats

### 3.1 Corrélation IEC ↔ IExC

**ρ de Spearman = 0.020** (p = 0.0187)

Les deux dimensions sont **quasi-indépendantes** : exposition structurelle et chocs subis mesurent bien des réalités distinctes.

### 3.2 Pays les plus exposés (IEC moyen)

| Rang | Pays | IEC moyen |
|------|------|-----------|
| 1 | GQ | 0.666 |
| 2 | YE | 0.658 |
| 3 | GW | 0.655 |
| 4 | IM | 0.650 |
| 5 | NE | 0.642 |

### 3.3 Pays ayant le plus subi (IExC moyen)

| Rang | Pays | IExC moyen |
|------|------|------------|
| 1 | US | 0.129 |
| 2 | AI | 0.090 |
| 3 | AS | 0.089 |
| 4 | PM | 0.084 |
| 5 | CN | 0.084 |

### 3.4 Pays les moins exposés

| Rang | Pays | IEC moyen |
|------|------|-----------|
| 1 | TF | 0.431 |
| 2 | CX | 0.427 |
| 3 | CC | 0.424 |
| 4 | PN | 0.398 |
| 5 | UM | 0.373 |

### 3.5 Analyse par quadrants

| Quadrant | Description | Nombre de pays |
|----------|-------------|----------------|
| Haute exposition, forts chocs | — | **66** |
| Haute exposition, faibles chocs | — | **60** |
| Faible exposition, forts chocs | — | **60** |
| Faible exposition, faibles chocs | — | **66** |

**Pays à haute exposition mais faibles chocs** *(résilients malgré leur vulnérabilité structurelle)* :

| Pays | IEC | IExC | Écart |
|------|-----|------|-------|
| YE | 0.658 | 0.056 | +0.602 |
| GQ | 0.666 | 0.065 | +0.601 |
| IM | 0.650 | 0.062 | +0.587 |
| GW | 0.655 | 0.069 | +0.586 |
| NE | 0.642 | 0.058 | +0.584 |

---

## 4. Visualisations

| Fichier | Description |
|---------|-------------|
| `etude11_heatmap_iec.png` | Heatmap IEC — Top 30 pays × 53 semaines |
| `etude11_heatmap_iexc.png` | Heatmap IExC — Top 30 pays × 53 semaines |
| `etude11_scatter_iec_iexc.png` | Scatter IEC vs IExC par pays (4 quadrants) |
| `etude11_series_globales.png` | Évolution temporelle mondiale IEC & IExC |
| `etude11_pays_semaine_vulnerabilite.csv` | Données complètes pays × semaine |

---

## 5. Discussion

L'analyse de 252 pays sur 53 semaines révèle une fracture nette entre exposition
structurelle et expérience effective des chocs. Les pays à faible adoption IPv6 et
HTTP/3 présentent les IEC les plus élevés, confirmant que la modernisation protocolaire
est un levier majeur de résilience.

La composante pays du IExC (BGP hijacks ciblés + variations IQI) permet d'identifier
des épisodes de perturbation que les indicateurs agrégés masquent. Couplé à l'IEC,
ce double indice fournit un cadre de priorisation pour les politiques de renforcement
de la sécurité Internet par pays.

---

*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*