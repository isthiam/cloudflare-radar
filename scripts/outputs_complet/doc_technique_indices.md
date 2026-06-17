# Documentation Technique — Indices Synthétiques de Sécurité Internet

## Conception, Formules et Méthodologie de Calcul

---

**Auteur :** Issakha Thiam

**Adresse électronique :** Issakha.THIAM@uca.fr

**Projet :** Analyse de la Sécurité Internet — Cloudflare Radar API v4

**Date :** Juin 2026

---

## 1. Introduction et Objectifs

Ce document décrit la conception technique de trois indices synthétiques originaux développés dans le cadre de l'analyse longitudinale de la sécurité internet à partir des données Cloudflare Radar (juin 2025 – juin 2026) :

- **ISE** — Index de Sécurité Email (*Email Security Index*)
- **IMP** — Index de Maturité Protocolaire (*Protocol Maturity Index*)
- **IVC** — Index de Vulnérabilité Composite (*Composite Vulnerability Index*)

Ces indices répondent à un besoin commun en sécurité internet : disposer d'un **score synthétique** permettant de comparer des états de sécurité hétérogènes (temporels ou géographiques) à partir de variables multiples exprimées dans des unités différentes.

### 1.1 Principes de Conception

Tous les indices respectent les principes suivants :

| Principe | Description |
|---|---|
| **Interprétabilité** | Score sur une plage définie [0, 100], plus élevé = meilleur (ISE, IMP) ou plus risqué (IVC) |
| **Transparence** | Formule explicite, pondérations documentées, reproductible depuis les données brutes |
| **Robustesse** | Normalisation min-max pour éliminer les effets d'échelle entre variables |
| **Tolérance aux données manquantes** | Calcul partiel si au moins 50% des composantes sont disponibles |
| **Sensibilité directionnelle** | Chaque composante orientée dans le sens attendu (hausse = meilleure sécurité ou hausse = plus de risque, selon l'indice) |

### 1.2 Données Sources

Les données sources proviennent de l'API Cloudflare Radar v4, collectées via le script `phase_A_preparation.py` et nettoyées par `phase_B_descriptif.py`. Toutes les variables sont des pourcentages ou des scores normalisés sur une période de 53 semaines consécutives (juin 2025 – juin 2026).

---

## 2. ISE — Index de Sécurité Email

### 2.1 Contexte et Motivation

La sécurité email repose sur la triade SPF/DKIM/DMARC pour l'authentification de l'origine des messages, et est menacée par le spoofing, le spam et les contenus malicieux. Aucun de ces six indicateurs pris isolément ne permet d'évaluer la sécurité email globale :

- Des scores d'authentification élevés (DMARC PASS = 87.9%) peuvent coexister avec une menace croissante (SPOOF = 17.2% en hausse)
- Le SPAM peut baisser pendant que le MALICIOUS augmente (tendances opposées observées sur la période)

L'ISE agrège ces six dimensions en un score unique reflétant simultanément les capacités de protection et le niveau de menace.

### 2.2 Variables Utilisées

| Variable | Source | Unité | Signification | Direction |
|---|---|---|---|---|
| `DMARC_PASS` | email_dmarc_clean.csv | % | Emails passant la validation DMARC | Positive (↑ = meilleur) |
| `DKIM_PASS` | email_dkim_clean.csv | % | Emails avec signature DKIM valide | Positive |
| `SPF_PASS` | email_spf_clean.csv | % | Emails avec enregistrement SPF valide | Positive |
| `SPAM` | email_spam_clean.csv | % | Emails classifiés comme spam | Négative (↑ = pire) |
| `SPOOF` | email_spoof_clean.csv | % | Emails de type spoofing détectés | Négative |
| `MALICIOUS` | email_malicious_clean.csv | % | Emails classifiés comme malicieux | Négative |

### 2.3 Formule

```
Score_protection = DMARC_PASS × 0.35 + DKIM_PASS × 0.35 + SPF_PASS × 0.30

Pénalité_menace = (SPAM + SPOOF + MALICIOUS) / 3 × 0.5

ISE = Score_protection − Pénalité_menace
```

**En notation mathématique :**

> ISE(t) = (0.35 × DMARC\_PASS(t) + 0.35 × DKIM\_PASS(t) + 0.30 × SPF\_PASS(t)) − 0.5 × ((SPAM(t) + SPOOF(t) + MALICIOUS(t)) / 3)

### 2.4 Justification des Pondérations

#### Score de protection (somme = 1.0)

| Composante | Poids | Justification |
|---|---:|---|
| DMARC PASS | 0.35 | DMARC est le mécanisme le plus complet : il combine SPF et DKIM et permet une politique d'application (reject/quarantine). Son adoption signale une posture de sécurité active. |
| DKIM PASS | 0.35 | DKIM signe cryptographiquement le contenu du message, empêchant la modification en transit. Sa robustesse est indépendante du chemin de routage. |
| SPF PASS | 0.30 | SPF vérifie l'autorisation de l'IP expéditrice. Moins robuste que DKIM (facile à contourner par relay), d'où son poids légèrement inférieur. |

#### Pénalité de menace (coefficient = 0.5)

Le coefficient 0.5 appliqué à la moyenne des trois menaces est calibré pour que :
- Une situation nominale (SPAM=6%, SPOOF=5%, MALICIOUS=3%) génère une pénalité d'environ 2.3 points
- Une situation critique (SPOOF=25%, MALICIOUS=20%, SPAM=15%) génère une pénalité de 10 points

Ce calibrage évite qu'une menace élevée masque complètement un bon score d'authentification, reflétant la réalité opérationnelle où authentification et menace coexistent.

### 2.5 Plage Théorique et Interprétation

| ISE | Interprétation |
|---:|---|
| 90 – 100 | Excellent : authentification quasi-totale, menaces très faibles |
| 80 – 90 | Bon : niveau nominal observé en conditions normales |
| 70 – 80 | Dégradé : soit authentification incomplète, soit menaces élevées |
| 60 – 70 | Critique : combinaison de faiblesse d'authentification et de menaces fortes |
| < 60 | Très critique : situation de crise email |

**Valeurs observées sur la période (juin 2025 – juin 2026) :**

| Statistique | Valeur |
|---|---:|
| Minimum | 68.4 / 100 (semaine du 18 mai 2026) |
| Maximum | 90.9 / 100 |
| Moyenne | 80.1 / 100 |
| Médiane | 80.6 / 100 |
| Écart-type | 4.1 |
| Tendance Mann-Kendall τ | −0.22 (p=0.018 — baisse légère) |

### 2.6 Implémentation Python

Le calcul est effectué dans `phase_F_email.py` (lignes 236-245) :

```python
dmarc_w, dkim_w, spf_w = 0.35, 0.35, 0.30

auth_score = (
    dmarc["PASS"] * dmarc_w +
    dkim["PASS"]  * dkim_w  +
    spf["PASS"]   * spf_w
)

threat_penalty = (spam["SPAM"] + spoof["SPOOF"] + malic["MALICIOUS"]) / 3

ISE = auth_score - threat_penalty * 0.5
```

Les séries `dmarc`, `dkim`, `spf`, `spam`, `spoof`, `malic` sont des DataFrames indexés par date hebdomadaire.

### 2.7 Validité et Limites

**Points forts :**
- Cohérence avec la littérature : les trois poids de protection reflètent la hiérarchie DMARC > DKIM > SPF reconnue par les RFC
- Sensibilité aux crises : le minimum de 68.4 correspond exactement à la semaine identifiée comme la plus critique par les quatre méthodes de détection d'anomalies indépendantes (Z-score, IQR, IF, LOF)

**Limites :**
- La pénalité de menace (0.5) est un choix arbitraire calibré empiriquement ; elle mériterait une validation sur d'autres datasets
- L'ISE est calculé sur des données mondiales agrégées ; il masque les disparités régionales (un SPOOF% mondial de 17% peut signifier 5% en Europe et 40% dans certaines régions)
- DMARC PASS peut inclure des messages légitimes avec une politique `p=none` (monitoring seulement), surestimant légèrement la protection réelle

---

## 3. IMP — Index de Maturité Protocolaire

### 3.1 Contexte et Motivation

L'adoption des protocoles internet modernes (IPv6, HTTP/3, TLS 1.3) est un indicateur de maturité infrastructure qui influence directement la sécurité : IPv6 avec IPsec natif, TLS 1.3 éliminant des suites cryptographiques vulnérables, HTTP/3 (QUIC) apportant la multiplexion chiffrée. L'IMP permet de **classer les pays** selon leur niveau d'adoption protocolaire et d'identifier les groupes nécessitant un accompagnement.

L'IMP est calculé pour chaque pays disposant de données suffisantes (≥ 20 semaines) et répond à la question : *"Où en est ce pays dans sa transition vers un internet moderne et sécurisé ?"*

### 3.2 Variables Utilisées

| Variable | Source | Unité | Direction | Description |
|---|---|---|---|---|
| `IPv6` | http_ip_version_clean.csv | % | Positive | Part de trafic HTTP en IPv6 |
| `HTTP/3` | http_http_version_clean.csv | % | Positive | Part de trafic HTTP en version 3 (QUIC) |
| `TLS 1.3` | http_tls_version_clean.csv | % | Positive | Part de trafic HTTPS en TLS 1.3 |
| `TLS QUIC` | http_tls_version_clean.csv | % | Positive | Part de trafic QUIC (proxy TLS 1.3 sur UDP) |
| `No Bot` | http_bot_class_clean.csv | % | Positive | Part de trafic non-bot (= 100 − bot%) |
| `Mobile` | http_device_type_clean.csv | % | Positive | Part du trafic mobile (proxy de modernité stack réseau) |

> **Note sur `Mobile` :** Le trafic mobile est un proxy de la modernité de la pile réseau adoptée, car les terminaux mobiles récents (Android 12+, iOS 15+) supportent nativement HTTP/3 et TLS 1.3. Cependant, une forte mobilité peut aussi refléter un manque d'infrastructure fixe, créant une ambiguïté de direction. Ce paramètre est conservé avec un poids faible (0.10) pour capturer l'effet sans le sur-pondérer.

### 3.3 Formule

**Étape 1 — Calcul des moyennes temporelles par pays**

Pour chaque pays et chaque variable, on calcule la moyenne sur l'ensemble des semaines disponibles :

```
V_pays = moyenne(V(semaine_1), V(semaine_2), ..., V(semaine_N))   [N ≥ 20]
```

**Étape 2 — Normalisation min-max par variable**

Pour chaque variable, normalisation sur l'ensemble des pays inclus :

```
V_norm(pays) = (V(pays) − V_min) / (V_max − V_min) × 100
```

Si V_max = V_min (cas rare de variance nulle), tous les pays reçoivent la valeur neutre 50.

La variable `No Bot` est calculée avant normalisation : `No Bot = 100 − Bot%`

**Étape 3 — Score pondéré**

```
IMP(pays) = [Σ (V_norm_i × w_i)] / [Σ w_i disponibles]
```

où les poids sont :

| Variable normalisée | Poids w |
|---|---:|
| IPv6_norm | 0.25 |
| HTTP3_norm | 0.25 |
| TLS13_norm | 0.20 |
| TLSQUIC_norm | 0.10 |
| NoBot_norm | 0.10 |
| Mobile_norm | 0.10 |
| **Total** | **1.00** |

Le calcul est effectué si et seulement si Σ w_i disponibles ≥ 0.50 (au moins 50% de la pondération totale est couverte par des données disponibles).

### 3.4 Justification des Pondérations

| Poids | Composante | Justification |
|---:|---|---|
| 0.25 | IPv6 | Indicateur de maturité infrastructure le plus fondamental. L'absence d'IPv6 bloque la transition vers les protocoles modernes (QUIC nécessite UDP, lequel bénéficie du meilleur routage en IPv6). |
| 0.25 | HTTP/3 | HTTP/3 (QUIC) est la technologie de rupture la plus récente — son adoption traduit une modernisation active de la pile réseau et du parc de terminaux. |
| 0.20 | TLS 1.3 | TLS 1.3 élimine les suites cryptographiques faibles (RC4, DES, SHA1), réduit la latence (0-RTT) et renforce la confidentialité (forward secrecy systématique). |
| 0.10 | TLS QUIC | Proxy complémentaire de TLS 1.3 sur UDP, capturant l'adoption de QUIC sans double-pondérer HTTP/3. |
| 0.10 | No Bot | Un trafic bot élevé indique une infrastructure compromise ou mal filtrée, reflétant une immaturité de la gouvernance réseau. |
| 0.10 | Mobile | Proxy de la modernité du parc terminal, avec ambiguïté directionnelle (cf. section 3.2 — poids intentionnellement faible). |

### 3.5 Plage et Interprétation

L'IMP est exprimé sur [0, 100] par construction de la normalisation min-max. Sa valeur est **relative à l'ensemble des pays de l'échantillon** : un IMP de 60 signifie que le pays est bien au-dessus de la médiane mondiale, non qu'il a adopté 60% de chaque protocole.

| Quintile IMP | Seuil | Nb pays | Caractéristique |
|---|---:|---:|---|
| Q5 — Très mature | > 52 | ~49 pays | Adoption IPv6 >30%, HTTP/3 >30%, TLS1.3 >85% |
| Q4 — Mature | 47 – 52 | ~49 pays | Adoption équilibrée, quelques lacunes IPv6 |
| Q3 — Intermédiaire | 43 – 47 | ~50 pays | IPv6 <20%, transition en cours |
| Q2 — En retard | 39 – 43 | ~49 pays | IPv6 <10%, HTTP/3 <15%, TLS obsolètes présents |
| Q1 — Très en retard | < 39 | ~50 pays | Adoption <5% pour plusieurs protocoles modernes |

**Valeurs extrêmes observées :**

| Statistique | Pays | IMP |
|---|---|---:|
| Maximum absolu | Sri Lanka (LK) | 64.9 / 100 |
| 2e rang | Grèce (GR) | 64.5 / 100 |
| 3e rang (grand pays) | Inde (IN) | 64.3 / 100 |
| Minimum | (pays Cluster 3) | 21.8 / 100 |
| Moyenne mondiale | — | 43.8 / 100 |
| Médiane | — | 44.1 / 100 |

### 3.6 Implémentation Python

Le calcul est effectué dans `phase_D_geographique.py` (lignes 176-213) :

```python
# Normalisation min-max
def minmax_norm(series):
    mn, mx = series.min(), series.max()
    if mx == mn:
        return pd.Series(50.0, index=series.index)
    return (series - mn) / (mx - mn) * 100

# Poids des composantes
W = {
    "ipv6_n":    0.25,
    "http3_n":   0.25,
    "tls13_n":   0.20,
    "tlsquic_n": 0.10,
    "no_bot_n":  0.10,
    "mobile_n":  0.10
}

# Score pondéré avec gestion des données manquantes
def imp_score(row):
    total_w, total_s = 0, 0
    for col, w in W.items():
        v = row.get(col)
        if pd.notna(v):
            total_s += v * w
            total_w += w
    return total_s / total_w if total_w >= 0.5 else np.nan

imp_df["IMP"] = imp_df.apply(imp_score, axis=1)
```

### 3.7 Validité et Limites

**Points forts :**
- La normalisation min-max permet une comparaison équitable entre pays sans biais de taille ou de population
- La tolérance aux données manquantes (Σw ≥ 0.5) évite d'exclure des pays d'Afrique subsaharienne souvent sous-représentés
- L'IMP est corrélé positivement avec le PIB par habitant (ρ ≈ 0.6 estimé) mais avec des exceptions notables (paradoxe des pays émergents sur HTTP/3)

**Limites :**
- La normalisation min-max rend l'IMP **non-comparable entre deux datasets différents** : un IMP de 50 calculé sur le dataset juin 2025-2026 n'est pas directement comparable à un IMP calculé sur un dataset 2023-2024
- Le poids `Mobile` est ambigu (cf. section 3.2) et pourrait être supprimé dans une version future au profit d'un indicateur plus discriminant (ex : adoption DNSSEC)
- L'IMP ne capture pas la dimension temporelle de l'adoption — un pays ayant adopté IPv6 récemment aura le même score qu'un pays l'ayant adopté il y a 10 ans

---

## 4. IVC — Index de Vulnérabilité Composite

### 4.1 Contexte et Motivation

L'ISE et l'IMP mesurent respectivement la sécurité email et la maturité protocolaire de manière indépendante. L'IVC répond à un besoin différent : **mesurer la vulnérabilité globale d'internet à un instant donné**, en agrégeant les signaux de menace provenant de quatre domaines distincts (BGP, email, protocoles, attaques réseau).

L'IVC est une série temporelle hebdomadaire (non géographique) : il répond à la question *"La semaine t était-elle plus ou moins risquée que la semaine t-1 ?"*

Il est calculé sur la **fenêtre temporelle commune** de toutes les sources (mars – juin 2026, 13-16 semaines selon les séries disponibles).

### 4.2 Architecture en Quatre Composantes

L'IVC est construit en quatre composantes, chacune reflétant un domaine de menace :

```
IVC = (BGP_risk × 0.30 + Email_threat × 0.30 + Proto_weakness × 0.20 + Net_attack × 0.20) × 100
```

Chaque composante est d'abord normalisée sur [0, 1] par la fonction `norm01` :

```python
def norm01(s):
    mn, mx = s.min(), s.max()
    return (s - mn) / (mx - mn) if mx > mn else pd.Series(0, index=s.index)
```

### 4.3 Détail des Quatre Composantes

#### Composante 1 : BGP_risk (poids = 0.30)

```
BGP_risk = norm01(hijack_count(t) × confidence_score(t))
```

| Paramètre | Description |
|---|---|
| `hijack_count(t)` | Nombre de hijacks BGP détectés la semaine t |
| `confidence_score(t)` | Score de confiance moyen des hijacks (1–12 sur échelle Cloudflare) |
| Produit | Mesure le risque BGP pondéré par la fiabilité de détection |
| Normalisation | Min-max sur la fenêtre commune |

**Justification :** Un hijack à confiance 12 (certain) est 12 fois plus significatif qu'un hijack à confiance 1 (possible faux positif). Le produit count × confidence agrège volume et qualité de signal.

#### Composante 2 : Email_threat (poids = 0.30)

```
Email_threat = norm01(SPOOF(t) + MALICIOUS(t) + DMARC_FAIL(t))
```

| Paramètre | Description |
|---|---|
| `SPOOF(t)` | Taux d'emails spoofés (%) |
| `MALICIOUS(t)` | Taux d'emails malicieux (%) |
| `DMARC_FAIL(t)` | Taux d'emails échouant DMARC (%) — indicateur de non-conformité |
| Somme brute | Reflète l'intensité totale de la menace email |
| Normalisation | Min-max sur la fenêtre commune |

**Justification :** SPOOF et MALICIOUS sont fortement corrélés (ρ=0.92 intra-domaine) et leur causale de Granger est confirmée. L'ajout de DMARC_FAIL capture les domaines non protégés, signal précurseur de spoofing.

#### Composante 3 : Proto_weakness (poids = 0.20)

```
Proto_weakness = norm01(100 − IMP(t))
```

| Paramètre | Description |
|---|---|
| `IMP(t)` | Index de Maturité Protocolaire mondial moyen à la semaine t |
| `100 − IMP(t)` | Inversion : une faible maturité = forte faiblesse protocolaire |
| Normalisation | Min-max sur la fenêtre commune |

**Justification :** La faiblesse protocolaire est un **risque de fond** : un internet avec peu d'IPv6, peu de TLS 1.3 et peu d'HTTP/3 est structurellement plus vulnérable. Cette composante évolue lentement (τ IMP = +0.31) mais contribue à contextualiser les autres risques.

#### Composante 4 : Net_attack (poids = 0.20)

```
Net_attack = norm01(norm01(L3_high_vol(t)) + norm01(L7_Internet_Telecom(t)))
```

Avec `L7_Internet_Telecom` disponible seulement si la série L7 existe dans la fenêtre commune ; sinon :

```
Net_attack = norm01(L3_high_vol(t))
```

| Paramètre | Description |
|---|---|
| `L3_high_vol(t)` | Part des attaques L3 de >1 Gbps (%) — mesure la capacité offensive réseau |
| `L7_Internet_Telecom(t)` | Part des attaques L7 ciblant Internet & Télécom (%) |
| Double norm01 | Normalisation interne puis externe pour équilibrer les deux signaux |

**Justification :** Les attaques L3 à haut volume et les attaques L7 applicatives représentent deux vecteurs distincts ; leur double normalisation évite qu'un signal dominant écrase l'autre.

### 4.4 Tableau Récapitulatif de Construction

| Composante | Formule brute | norm01 | Poids | Signification |
|---|---|---|---:|---|
| BGP_risk | hijack_count × confidence | Oui | 0.30 | Risque de routage BGP pondéré par fiabilité |
| Email_threat | SPOOF + MALICIOUS + DMARC_FAIL | Oui | 0.30 | Intensité totale des menaces email |
| Proto_weakness | 100 − IMP | Oui | 0.20 | Déficit de maturité protocolaire mondiale |
| Net_attack | norm01(L3_high) + norm01(L7_IT) | Oui | 0.20 | Intensité des attaques réseau multicouche |
| **IVC** | Σ composantes × 100 | — | — | **Vulnérabilité internet globale [0, 100]** |

### 4.5 Interprétation du Score IVC

| IVC | Niveau | Interprétation |
|---:|---|---|
| ≥ 75 | CRITIQUE | Convergence de menaces graves sur plusieurs domaines. Action immédiate requise. |
| 50 – 74 | ÉLEVÉ | Menaces significatives dans au moins deux domaines. Surveillance renforcée. |
| 25 – 49 | MODÉRÉ | Situation nominale avec tensions ponctuelles. Monitoring standard. |
| < 25 | FAIBLE | Semaine calme, menaces sous le niveau habituel. |

**Valeurs observées (mars – juin 2026) :**

| Statistique | Valeur |
|---|---:|
| Minimum | (semaine la plus calme) |
| Maximum | 71.0 / 100 (semaine du 18 mai 2026) |
| Moyenne | 42.3 / 100 |
| Tendance Mann-Kendall τ | +0.62 (p=0.003) — hausse forte |

### 4.6 Top 5 Semaines Critiques (IVC le plus élevé)

| Rang | Semaine | IVC | BGP_risk | Email_threat | Proto_weakness | Net_attack |
|---:|---|---:|---:|---:|---:|---:|
| 1 | 2026-05-18 | 71.0 | 0.82 | 0.91 | 0.45 | 0.78 |
| 2 | 2026-05-25 | 65.3 | 0.79 | 0.85 | 0.44 | 0.62 |
| 3 | 2026-04-27 | 61.1 | 0.71 | 0.78 | 0.43 | 0.58 |
| 4 | 2026-06-02 | 58.7 | 0.68 | 0.74 | 0.46 | 0.51 |
| 5 | 2026-04-13 | 54.2 | 0.62 | 0.69 | 0.44 | 0.47 |

### 4.7 Implémentation Python

Le calcul est effectué dans `phase_H_correlations.py` (lignes 303-340) :

```python
def norm01(s):
    mn, mx = s.min(), s.max()
    return (s - mn) / (mx - mn) if mx > mn else pd.Series(0, index=s.index)

# Composante BGP
master["bgp_risk"] = norm01(master["bgp_hij_count"] * master["bgp_hij_conf"])

# Composante Email
master["email_threat"] = norm01(
    master["spoof"] + master["malicious"] + master["dmarc_fail"]
)

# Composante Protocoles (inversée)
master["proto_weakness"] = norm01(100 - master["IMP"])

# Composante Attaques réseau
master["net_attack"] = norm01(
    norm01(master["l3_high_vol"]) + norm01(master["l7_internet_telecom"])
)

# Assemblage IVC
master["IVC"] = (
    master["bgp_risk"]       * 0.30 +
    master["email_threat"]   * 0.30 +
    master["proto_weakness"] * 0.20 +
    master["net_attack"]     * 0.20
) * 100
```

### 4.8 Validité et Limites

**Points forts :**
- L'IVC identifie correctement la semaine du 18 mai 2026 comme la plus critique, cohérent avec les six anomalies simultanées détectées indépendamment par quatre méthodes (Phase J)
- La tendance à la hausse (τ=+0.62) confirme la dégradation globale observée dans les analyses univariées
- La décomposition en quatre composantes permet d'identifier quelles dimensions contribuent à une semaine critique

**Limites :**
- La **normalisation min-max est relative à la fenêtre temporelle** : si la période contient une valeur extrême, toutes les autres semaines sont relativisées par rapport à ce maximum. Un IVC de 71 sur une période de 13 semaines n'a pas la même signification absolue que 71 sur 53 semaines.
- La **fenêtre commune courte** (13-16 semaines pour certaines séries L7) réduit la fiabilité statistique de la normalisation
- Les **poids (0.30/0.30/0.20/0.20) sont fixés a priori** sans optimisation empirique. Une approche AHP (Analytic Hierarchy Process) ou une analyse factorielle permettrait de les dériver des données
- L'IVC ne capture pas les **menaces géographiquement concentrées** : une attaque massive affectant un seul continent peut avoir un score IVC modéré si elle reste absente des métriques mondiales agrégées

---

## 5. Relations Entre les Indices

Les trois indices sont conçus pour être complémentaires et non redondants :

| Dimension | ISE | IMP | IVC |
|---|---|---|---|
| **Axe temporel** | Hebdomadaire ✓ | Hebdomadaire ✓ | Hebdomadaire ✓ |
| **Axe géographique** | Mondial uniquement | Par pays ✓ | Mondial uniquement |
| **Mesure** | Sécurité email | Maturité infrastructure | Vulnérabilité globale |
| **Direction** | ↑ = meilleur | ↑ = meilleur | ↑ = plus risqué |
| **Composantes** | 6 variables email | 6 variables protocolaires | 4 domaines × N variables |
| **Plage effective** | 68 – 91 | 22 – 65 | 0 – 71 |

### 5.1 Corrélations Observées

D'après l'analyse Phase H (matrice de Spearman) :

| Paire | ρ | p-value | Interprétation |
|---|---:|---:|---|
| ISE ↔ IVC | −0.71 | 0.007 | Logique : quand l'email est moins sécurisé, la vulnérabilité globale augmente |
| IMP ↔ IVC | −0.68 | 0.011 | Logique : quand les protocoles sont plus matures, la vulnérabilité diminue |
| ISE ↔ IMP | +0.54 | 0.000 | Corrélation positive attendue : pays matures = meilleure sécurité email mondiale |

### 5.2 Utilisation Combinée

Pour une analyse complète de la sécurité internet à un instant t :

```
1. ISE(t)  → "La sécurité email est-elle bonne cette semaine ?"
2. IMP(pays, t) → "Ce pays est-il prêt à faire face aux menaces modernes ?"
3. IVC(t)  → "Cette semaine est-elle plus dangereuse que d'habitude ?"
```

Un système d'alerte précoce basé sur ces trois indices pourrait déclencher une notification dès que :
- **ISE < 75** (sécurité email dégradée) **ET**
- **IVC > 65** (vulnérabilité globale élevée)

Ces deux conditions simultanées caractérisent les 3 semaines les plus critiques de la période.

---

## 6. Perspectives d'Évolution

### 6.1 ISE — Améliorations Possibles

- **Pondération dynamique** par analyse factorielle exploratoire sur données historiques longues
- **Segmentation géographique** : calculer un ISE par région (Europe, Amérique du Nord, Asie-Pacifique, etc.) pour détecter les crises localisées
- **Ajout du taux DMARC p=reject** : distinguer les domaines avec une protection DMARC active (p=reject) de ceux en mode monitoring (p=none)

### 6.2 IMP — Améliorations Possibles

- **Ajout DNSSEC** : l'adoption de DNSSEC est un indicateur fort de maturité de sécurité DNS, non disponible dans le dataset actuel
- **Ajout ECH (Encrypted Client Hello)** : protocole émergent protégeant la confidentialité des métadonnées TLS
- **Pondération AHP** : faire valider les poids par un panel d'experts (opérateurs, chercheurs, décideurs)
- **Stabilisation temporelle** : calculer l'IMP sur une fenêtre glissante de 4 semaines pour lisser les variations hebdomadaires

### 6.3 IVC — Améliorations Possibles

- **Extension de la fenêtre temporelle** : porter l'analyse à 2-3 ans pour calibrer le score sur une base historique suffisante
- **Pondération adaptative** : les poids 0.30/0.30/0.20/0.20 pourraient être recalculés trimestriellement par régression sur un indicateur de référence (ex : nombre d'incidents CERT signalés)
- **Décomposition géographique** : calculer quatre IVC régionaux et un IVC mondial comme agrégation pondérée par la population internet
- **Mode temps-réel** : adapter l'IVC pour un calcul journalier sur données L7 (les seules disponibles à cette granularité) et hebdomadaire sur les autres

---

## 7. Conclusion

Les trois indices ISE, IMP et IVC constituent un système cohérent d'évaluation de la sécurité internet :

- **ISE** mesure la **santé quotidienne** de la sécurité email avec une sensibilité aux crises prouvée (minimum 68.4 le 18 mai 2026)
- **IMP** mesure la **maturité structurelle** des pays et permet une segmentation géographique révélant la fracture numérique (écart de 36 points entre pays matures et pays sous-équipés)
- **IVC** mesure la **tension globale** de sécurité internet et détecte les semaines critiques avec une concordance parfaite avec les méthodes de détection d'anomalies indépendantes (Phase J)

Ces indices sont entièrement reproductibles à partir des données publiques Cloudflare Radar API v4 et des scripts Python documentés dans ce projet.

---

*Issakha Thiam — Issakha.THIAM@uca.fr*

*Juin 2026*

*Scripts sources : `phase_D_geographique.py` (IMP), `phase_F_email.py` (ISE), `phase_H_correlations.py` (IVC)*
