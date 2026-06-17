# Rapport Phase K — Analyse de Graphe Réseau ASN
**Cloudflare Radar Dataset — Déc. 2025 / Juin 2026**  
**Auteur :** Issakha Thiam  
**Généré le :** 2026-06-16 22:23:23

---
## 1. Résumé Exécutif — Topologie du Graphe

### 1.1 Graphe BGP Hijacks

| Indicateur | Valeur |
|---|---|
| Nœuds (ASNs) | **5,287** |
| Arêtes (paires hijacker→victime) | **5,697** |
| Densité du graphe | 0.000204 (graphe très creux) |
| Composantes fortement connexes | 4,652 |
| Plus grande SCC | 498 nœuds |
| Composantes faiblement connexes | 886 |
| Plus grande WCC | 3,220 nœuds |
| ASNs hijackeurs (out_degree > 0) | 2,219 |
| ASNs victimes (in_degree > 0) | 4,082 |
| ASNs jouant les 2 rôles | 1,014 |

### 1.2 Graphe BGP Leaks

| Indicateur | Valeur |
|---|---|
| Nœuds (ASNs) | **2,703** |
| Arêtes (transitions de chemin) | **5,795** |
| ASNs leakers distincts (position 1) | **1,848** |
| ASNs actifs hijacks ET leaks | **302** |

---
## 2. Distribution des Degrés

### 2.1 Distribution Out-Degree (Hijackeurs)

| Out-degree | Nb ASNs | % des hijackeurs | Interprétation |
|---:|---:|---:|---|
| 1 | 1627 | 73.3% | uniques |
| 2 | 297 | 13.4% | occasionnels |
| 3 | 116 | 5.2% | occasionnels |
| 4 | 58 | 2.6% | occasionnels |
| 5 | 31 | 1.4% | occasionnels |
| 6 | 19 | 0.9% | occasionnels |
| 7 | 11 | 0.5% | occasionnels |
| 8 | 13 | 0.6% | occasionnels |
| 9 | 10 | 0.5% | occasionnels |
| 10 | 5 | 0.2% | actifs |
| 11 | 6 | 0.3% | actifs |
| 12 | 2 | 0.1% | actifs |
| 13 | 4 | 0.2% | actifs |
| 14 | 1 | 0.0% | actifs |
| 15 | 1 | 0.0% | actifs |
| 16 | 6 | 0.3% | actifs |
| 18 | 4 | 0.2% | actifs |
| 19 | 1 | 0.0% | actifs |
| 20 | 1 | 0.0% | actifs |
| 21 | 1 | 0.0% | actifs |
| 34 | 1 | 0.0% | actifs |
| ≥50 | 4 | 0.2% | hyperactifs (attaque systématique) |

| **Statistique** | **Out-degree** |
|---|---:|
| Médiane | 1 |
| Moyenne | 2.57 |
| P90 | 3 |
| P99 | 13 |
| Maximum | 1611 |

### 2.2 Distribution In-Degree (Victimes)

| Statistique | In-degree (victimes) |
|---|---:|
| Médiane | 1 |
| Moyenne | 1.40 |
| P90 | 2 |
| P99 | 6 |
| Maximum | 182 |

---
## 3. PageRank — ASNs les Plus Influents dans le Réseau de Hijack

> PageRank (damping=0.85, pondéré) : mesure l'influence d'un ASN comme vecteur de propagation dans le graphe.
> Un PageRank élevé = ASN vers lequel beaucoup d'autres ASN à fort PageRank pointent (victime d'acteurs influents).

| Rang | ASN | PageRank | Out-deg | In-deg | Rôle |
|---:|---:|---:|---:|---:|---|
| 1 | AS834 | 0.025851 | 134 | 163 | Hijackeur+Victime |
| 2 | AS28629 | 0.014451 | 1611 | 182 | Hijackeur+Victime |
| 3 | AS174 | 0.010736 | 76 | 88 | Hijackeur+Victime |
| 4 | AS9009 | 0.003381 | 52 | 26 | Hijackeur+Victime |
| 5 | AS9304 | 0.002682 | 9 | 17 | Hijackeur+Victime |
| 6 | AS208185 | 0.002648 | 16 | 20 | Hijackeur+Victime |
| 7 | AS11404 | 0.002335 | 2 | 6 | Hijackeur+Victime |
| 8 | AS2914 | 0.002271 | 7 | 20 | Hijackeur+Victime |
| 9 | AS2386 | 0.001837 | 6 | 6 | Hijackeur+Victime |
| 10 | AS16276 | 0.001816 | 7 | 10 | Hijackeur+Victime |
| 11 | AS20473 | 0.001779 | 2 | 16 | Hijackeur+Victime |
| 12 | AS212238 | 0.001736 | 4 | 25 | Hijackeur+Victime |
| 13 | AS4808 | 0.001729 | 6 | 6 | Hijackeur+Victime |
| 14 | AS63199 | 0.001697 | 4 | 15 | Hijackeur+Victime |
| 15 | AS328608 | 0.001640 | 5 | 10 | Hijackeur+Victime |
| 16 | AS7029 | 0.001637 | 16 | 12 | Hijackeur+Victime |
| 17 | AS23724 | 0.001569 | 4 | 5 | Hijackeur+Victime |
| 18 | AS22773 | 0.001532 | 6 | 3 | Hijackeur+Victime |
| 19 | AS209372 | 0.001530 | 4 | 9 | Hijackeur+Victime |
| 20 | AS202829 | 0.001392 | 0 | 1 | Victime |
| 21 | AS36352 | 0.001390 | 5 | 3 | Hijackeur+Victime |
| 22 | AS62240 | 0.001355 | 18 | 7 | Hijackeur+Victime |
| 23 | AS203963 | 0.001345 | 5 | 4 | Hijackeur+Victime |
| 24 | AS29802 | 0.001342 | 16 | 5 | Hijackeur+Victime |
| 25 | AS60781 | 0.001313 | 11 | 9 | Hijackeur+Victime |
| 26 | AS58232 | 0.001299 | 1 | 2 | Hijackeur+Victime |
| 27 | AS6 | 0.001289 | 1 | 4 | Hijackeur+Victime |
| 28 | AS6079 | 0.001271 | 13 | 17 | Hijackeur+Victime |
| 29 | AS205949 | 0.001265 | 1 | 2 | Hijackeur+Victime |
| 30 | AS12 | 0.001244 | 1 | 2 | Hijackeur+Victime |

---
## 4. Centralité de Betweenness — Nœuds Pivot du Graphe

> Betweenness centrality : proportion des plus courts chemins passant par ce nœud.
> Un nœud pivot élevé = ASN qui *sert de pont* entre sous-réseaux de hijack.

| Rang | ASN | Betweenness | Out-deg | In-deg | Rôle |
|---:|---:|---:|---:|---:|---|
| 1 | AS28629 | 0.060551 | 1611 | 182 | Hijackeur+Victime |
| 2 | AS834 | 0.029097 | 134 | 163 | Hijackeur+Victime |
| 3 | AS174 | 0.013428 | 76 | 88 | Hijackeur+Victime |
| 4 | AS21859 | 0.005415 | 34 | 14 | Hijackeur+Victime |
| 5 | AS53107 | 0.004757 | 4 | 2 | Hijackeur+Victime |
| 6 | AS2914 | 0.004085 | 7 | 20 | Hijackeur+Victime |
| 7 | AS2 | 0.003056 | 6 | 6 | Hijackeur+Victime |
| 8 | AS2386 | 0.002992 | 6 | 6 | Hijackeur+Victime |
| 9 | AS20473 | 0.002860 | 2 | 16 | Hijackeur+Victime |
| 10 | AS9009 | 0.002764 | 52 | 26 | Hijackeur+Victime |
| 11 | AS40676 | 0.002407 | 9 | 8 | Hijackeur+Victime |
| 12 | AS63199 | 0.002332 | 4 | 15 | Hijackeur+Victime |
| 13 | AS20326 | 0.002254 | 21 | 10 | Hijackeur+Victime |
| 14 | AS211826 | 0.002223 | 4 | 1 | Hijackeur+Victime |
| 15 | AS18186 | 0.002075 | 6 | 4 | Hijackeur+Victime |
| 16 | AS16276 | 0.001968 | 7 | 10 | Hijackeur+Victime |
| 17 | AS59642 | 0.001961 | 4 | 4 | Hijackeur+Victime |
| 18 | AS4 | 0.001918 | 4 | 5 | Hijackeur+Victime |
| 19 | AS43350 | 0.001910 | 3 | 3 | Hijackeur+Victime |
| 20 | AS23724 | 0.001896 | 4 | 5 | Hijackeur+Victime |
| 21 | AS23844 | 0.001895 | 1 | 2 | Hijackeur+Victime |
| 22 | AS4808 | 0.001894 | 6 | 6 | Hijackeur+Victime |
| 23 | AS47272 | 0.001888 | 1 | 4 | Hijackeur+Victime |
| 24 | AS16589 | 0.001513 | 2 | 5 | Hijackeur+Victime |
| 25 | AS208185 | 0.001484 | 16 | 20 | Hijackeur+Victime |

---
## 5. Analyse HITS — Hubs et Autorités

> **Hubs** : ASNs qui pointent vers beaucoup de victimes importantes (hijackeurs systématiques).
> **Autorités** : ASNs qui sont ciblés par beaucoup de hijackeurs importants (victimes structurelles).

### 5.1 Top 20 Hubs (Hijackeurs Systématiques)

| Rang | ASN | Hub Score | Out-deg | Actif dans leaks |
|---:|---:|---:|---:|---|
| 1 | AS138421 | 0.388349 | 4 | — |
| 2 | AS17621 | 0.339844 | 5 | — |
| 3 | AS136958 | 0.100120 | 2 | — |
| 4 | AS4808 | 0.037743 | 6 | — |
| 5 | AS59083 | 0.027888 | 1 | — |
| 6 | AS4811 | 0.025046 | 9 | — |
| 7 | AS137280 | 0.015878 | 1 | — |
| 8 | AS131516 | 0.009591 | 2 | — |
| 9 | AS9802 | 0.007209 | 1 | — |
| 10 | AS133119 | 0.006892 | 1 | — |
| 11 | AS834 | 0.005037 | 134 | — |
| 12 | AS138156 | 0.004791 | 2 | — |
| 13 | AS135581 | 0.004780 | 1 | — |
| 14 | AS174 | 0.004017 | 76 | — |
| 15 | AS4812 | 0.002732 | 4 | — |
| 16 | AS131274 | 0.002006 | 4 | — |
| 17 | AS55994 | 0.001918 | 1 | — |
| 18 | AS211826 | 0.001916 | 4 | — |
| 19 | AS134366 | 0.001648 | 1 | — |
| 20 | AS201986 | 0.001528 | 2 | — |

### 5.2 Top 20 Autorités (Victimes Structurelles)

| Rang | ASN | Auth Score | In-deg | Actif dans leaks |
|---:|---:|---:|---:|---|
| 1 | AS4811 | 0.314615 | 5 | — |
| 2 | AS4812 | 0.269142 | 3 | — |
| 3 | AS63199 | 0.156830 | 15 | ✅ |
| 4 | AS149511 | 0.068113 | 1 | — |
| 5 | AS59019 | 0.050097 | 4 | — |
| 6 | AS58466 | 0.045070 | 2 | — |
| 7 | AS139118 | 0.027596 | 2 | — |
| 8 | AS23724 | 0.012997 | 5 | — |
| 9 | AS17621 | 0.010020 | 2 | — |
| 10 | AS138421 | 0.009334 | 2 | — |
| 11 | AS4847 | 0.006633 | 3 | — |
| 12 | AS17775 | 0.004585 | 1 | — |
| 13 | AS63647 | 0.002546 | 1 | — |
| 14 | AS23844 | 0.000679 | 2 | — |
| 15 | AS18241 | 0.000509 | 1 | — |
| 16 | AS834 | 0.000474 | 163 | — |
| 17 | AS202829 | 0.000452 | 1 | — |
| 18 | AS55996 | 0.000424 | 4 | — |
| 19 | AS9304 | 0.000398 | 17 | ✅ |
| 20 | AS36352 | 0.000374 | 3 | — |

---
## 6. Top Paires Hijacker → Victime

> Paires (hijacker_ASN, victim_ASN) les plus fréquentes dans le dataset.

| Rang | Hijackeur | Victime | Nb events | Conf. moy. |
|---:|---:|---:|---:|---:|
| 1 | AS6453 | AS5416 | 128 | 12.0 |
| 2 | AS58519 | AS134542 | 126 | 2.0 |
| 3 | AS134542 | AS58519 | 124 | 2.0 |
| 4 | AS12668 | AS2854 | 109 | 4.0 |
| 5 | AS199524 | AS59245 | 105 | 9.8 |
| 6 | AS4847 | AS4808 | 104 | 2.3 |
| 7 | AS138421 | AS4811 | 103 | 6.4 |
| 8 | AS36901 | AS29032 | 103 | 4.0 |
| 9 | AS23724 | AS4808 | 103 | 2.1 |
| 10 | AS17025 | AS10753 | 101 | 2.0 |
| 11 | AS140716 | AS138950 | 100 | 4.0 |
| 12 | AS136958 | AS58466 | 100 | 5.8 |
| 13 | AS1031 | AS999 | 98 | 4.4 |
| 14 | AS45629 | AS7693 | 98 | 12.0 |
| 15 | AS17621 | AS4812 | 97 | 5.0 |
| 16 | AS10753 | AS17025 | 97 | 3.0 |
| 17 | AS45629 | AS58955 | 97 | 11.8 |
| 18 | AS58466 | AS136958 | 95 | 2.0 |
| 19 | AS45102 | AS45700 | 93 | 6.0 |
| 20 | AS24203 | AS17885 | 93 | 8.0 |
| 21 | AS9802 | AS23724 | 91 | 4.0 |
| 22 | AS4816 | AS17622 | 91 | 2.0 |
| 23 | AS140570 | AS54801 | 88 | 7.7 |
| 24 | AS17621 | AS4811 | 88 | 4.5 |
| 25 | AS4811 | AS17621 | 87 | 3.6 |
| 26 | AS133119 | AS23724 | 87 | 2.0 |
| 27 | AS5468 | AS44868 | 85 | 4.0 |
| 28 | AS199524 | AS206317 | 83 | 10.0 |
| 29 | AS58065 | AS48950 | 82 | 2.1 |
| 30 | AS4766 | AS56971 | 82 | 2.1 |

---
## 7. ASNs à Double Rôle (Hijackeurs ET Victimes)

> Ces ASNs apparaissent à la fois comme hijackeurs (out_degree > 0) et comme victimes (in_degree > 0).
> Ils représentent des réseaux potentiellement compromis ou des opérateurs avec une mauvaise hygiène BGP.

**1014 ASNs** jouent les deux rôles (hijackeur + victime).

| Rang | ASN | Out-deg (hijacks) | In-deg (victimes) | Activité totale | PageRank | Hub | Auth |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | AS28629 | 1611 | 182 | 1820 | 0.014451 | 0.001020 | 0.000034 |
| 2 | AS174 | 76 | 88 | 876 | 0.010736 | 0.004017 | 0.000193 |
| 3 | AS834 | 134 | 163 | 859 | 0.025851 | 0.005037 | 0.000474 |
| 4 | AS23724 | 4 | 5 | 474 | 0.001569 | 0.000013 | 0.012997 |
| 5 | AS4811 | 9 | 5 | 402 | 0.000561 | 0.025046 | 0.314615 |
| 6 | AS134542 | 2 | 2 | 374 | 0.000766 | -0.000000 | -0.000000 |
| 7 | AS138421 | 4 | 2 | 366 | 0.000390 | 0.388349 | 0.009334 |
| 8 | AS4808 | 6 | 6 | 354 | 0.001729 | 0.037743 | 0.000008 |
| 9 | AS17621 | 5 | 2 | 340 | 0.000517 | 0.339844 | 0.010020 |
| 10 | AS58519 | 2 | 2 | 331 | 0.000691 | -0.000000 | -0.000000 |
| 11 | AS9009 | 52 | 26 | 323 | 0.003381 | 0.001104 | 0.000012 |
| 12 | AS10753 | 8 | 11 | 292 | 0.000893 | 0.000004 | 0.000014 |
| 13 | AS7029 | 16 | 12 | 278 | 0.001637 | 0.000011 | 0.000028 |
| 14 | AS136958 | 2 | 1 | 271 | 0.000459 | 0.100120 | -0.000000 |
| 15 | AS199524 | 8 | 2 | 233 | 0.000259 | 0.000001 | 0.000050 |
| 16 | AS63199 | 4 | 15 | 219 | 0.001697 | 0.000009 | 0.156830 |
| 17 | AS131284 | 10 | 1 | 218 | 0.000114 | 0.000000 | 0.000005 |
| 18 | AS4812 | 4 | 3 | 216 | 0.000462 | 0.002732 | 0.269142 |
| 19 | AS26042 | 11 | 7 | 213 | 0.000406 | 0.000132 | 0.000098 |
| 20 | AS6453 | 20 | 2 | 211 | 0.000188 | 0.000000 | 0.000000 |
| 21 | AS212477 | 13 | 2 | 210 | 0.000142 | 0.000005 | 0.000005 |
| 22 | AS3257 | 10 | 7 | 206 | 0.000338 | 0.000016 | 0.000001 |
| 23 | AS58466 | 2 | 2 | 205 | 0.000433 | -0.000000 | 0.045070 |
| 24 | AS138407 | 2 | 2 | 205 | 0.000454 | -0.000000 | -0.000000 |
| 25 | AS17025 | 1 | 2 | 199 | 0.000534 | 0.000008 | 0.000007 |
| 26 | AS137085 | 10 | 2 | 196 | 0.000264 | 0.000000 | 0.000000 |
| 27 | AS6079 | 13 | 17 | 178 | 0.001271 | 0.000033 | 0.000023 |
| 28 | AS19905 | 16 | 4 | 173 | 0.000972 | 0.000000 | 0.000000 |
| 29 | AS20326 | 21 | 10 | 173 | 0.000920 | 0.000041 | 0.000010 |
| 30 | AS45700 | 2 | 3 | 172 | 0.000703 | 0.000002 | 0.000018 |

---
## 8. Analyse du Graphe BGP Leaks

### 8.1 Top 30 ASNs Leakers (Position 1 dans le chemin)

> L'ASN en position 1 (index 1) du chemin est l'ASN qui a *re-annoncé* la route hors de sa zone (valley-free violation).

| Rang | ASN Leaker | Nb leaks | Actif hijacks |
|---:|---:|---:|---|
| 1 | AS199310 | 252 | — |
| 2 | AS30990 | 233 | — |
| 3 | AS268624 | 151 | ✅ hijackeur |
| 4 | AS25145 | 148 | ✅ hijackeur |
| 5 | AS7473 | 139 | — |
| 6 | AS136897 | 138 | ✅ hijackeur |
| 7 | AS4761 | 126 | ✅ hijackeur |
| 8 | AS37440 | 108 | ✅ hijackeur |
| 9 | AS4775 | 107 | ✅ hijackeur |
| 10 | AS18001 | 102 | ✅ hijackeur |
| 11 | AS9927 | 94 | — |
| 12 | AS28663 | 94 | — |
| 13 | AS205941 | 93 | — |
| 14 | AS24812 | 93 | ✅ hijackeur |
| 15 | AS37133 | 90 | — |
| 16 | AS136255 | 88 | ✅ hijackeur |
| 17 | AS51765 | 87 | ✅ hijackeur |
| 18 | AS53153 | 79 | — |
| 19 | AS214941 | 74 | — |
| 20 | AS19551 | 73 | — |
| 21 | AS206119 | 72 | ✅ hijackeur |
| 22 | AS52025 | 72 | — |
| 23 | AS199524 | 69 | ✅ hijackeur |
| 24 | AS61468 | 69 | — |
| 25 | AS204464 | 66 | ✅ hijackeur |
| 26 | AS20598 | 66 | — |
| 27 | AS51202 | 65 | ✅ hijackeur |
| 28 | AS45903 | 64 | — |
| 29 | AS47890 | 64 | — |
| 30 | AS45430 | 64 | ✅ hijackeur |

### 8.2 Longueur des Chemins de Leak

| Longueur chemin | Nb leaks | % |
|---:|---:|---:|
| 3 ASNs | 19,999 | 100.0% |

### 8.3 Top Transitions dans les Chemins de Leak

| Rang | ASN A | ASN B | Nb transitions |
|---:|---:|---:|---:|
| 1 | AS199310 | AS139317 | 247 |
| 2 | AS58453 | AS30990 | 152 |
| 3 | AS22356 | AS268624 | 96 |
| 4 | AS9304 | AS136897 | 91 |
| 5 | AS37100 | AS37133 | 90 |
| 6 | AS30990 | AS23764 | 90 |
| 7 | AS22356 | AS28663 | 88 |
| 8 | AS18001 | AS45489 | 83 |
| 9 | AS3356 | AS7473 | 82 |
| 10 | AS199995 | AS24812 | 80 |
| 11 | AS52025 | AS34927 | 72 |
| 12 | AS37100 | AS37440 | 64 |
| 13 | AS9002 | AS4761 | 64 |
| 14 | AS207529 | AS210176 | 62 |
| 15 | AS8455 | AS51088 | 61 |
| 16 | AS204471 | AS50877 | 61 |
| 17 | AS58453 | AS59257 | 57 |
| 18 | AS7473 | AS4761 | 56 |
| 19 | AS263880 | AS61568 | 56 |
| 20 | AS139009 | AS9498 | 56 |

---
## 9. Structure des Composantes Connexes

### 9.1 Distribution des Composantes Faiblement Connexes (WCC)

| Rang | Taille WCC | % des nœuds |
|---:|---:|---:|
| 1 | 3220 | 60.9% |
| 2 | 12 | 0.2% |
| 3 | 10 | 0.2% |
| 4 | 8 | 0.2% |
| 5 | 7 | 0.1% |
| 6 | 7 | 0.1% |
| 7 | 6 | 0.1% |
| 8 | 6 | 0.1% |
| 9 | 6 | 0.1% |
| 10 | 6 | 0.1% |
| 11 | 6 | 0.1% |
| 12 | 6 | 0.1% |
| 13 | 6 | 0.1% |
| 14 | 6 | 0.1% |
| 15 | 5 | 0.1% |
| ... | ... | ... |
| Isolats (WCC=1) | 0 | 0.0% |

### 9.2 Composantes Fortement Connexes (SCC)

| Rang | Taille SCC | % des nœuds |
|---:|---:|---:|
| 1 | 498 | 9.42% |
| 2 | 7 | 0.13% |
| 3 | 7 | 0.13% |
| 4 | 5 | 0.09% |
| 5 | 5 | 0.09% |
| 6 | 4 | 0.08% |
| 7 | 3 | 0.06% |
| 8 | 3 | 0.06% |
| 9 | 3 | 0.06% |
| 10 | 3 | 0.06% |
| Singletons | 4547 | 86.0% |

---
## 10. ASNs Actifs dans Hijacks ET Leaks

> **302** ASNs apparaissent à la fois comme hijackeurs et comme leakers.
> Ces ASNs sont potentiellement mal configurés ou compromis.

| Rang | ASN | Hijacks initiés | Leaks | Victimisations (in-deg) | Total activité |
|---:|---:|---:|---:|---:|---:|
| 1 | AS136255 | 89 | 88 | 0 | **177** |
| 2 | AS199524 | 105 | 69 | 2 | **174** |
| 3 | AS37440 | 62 | 108 | 4 | **170** |
| 4 | AS268624 | 1 | 151 | 3 | **152** |
| 5 | AS25145 | 2 | 148 | 0 | **150** |
| 6 | AS136897 | 1 | 138 | 2 | **139** |
| 7 | AS4761 | 12 | 126 | 1 | **138** |
| 8 | AS4775 | 1 | 107 | 0 | **108** |
| 9 | AS9009 | 106 | 1 | 26 | **107** |
| 10 | AS18001 | 1 | 102 | 1 | **103** |
| 11 | AS45629 | 102 | 1 | 0 | **103** |
| 12 | AS140570 | 98 | 4 | 1 | **102** |
| 13 | AS18747 | 61 | 36 | 3 | **97** |
| 14 | AS24203 | 93 | 3 | 1 | **96** |
| 15 | AS24812 | 1 | 93 | 0 | **94** |
| 16 | AS138965 | 41 | 50 | 0 | **91** |
| 17 | AS206119 | 17 | 72 | 3 | **89** |
| 18 | AS51765 | 1 | 87 | 0 | **88** |
| 19 | AS36962 | 56 | 26 | 1 | **82** |
| 20 | AS26042 | 80 | 1 | 7 | **81** |
| 21 | AS38757 | 56 | 24 | 0 | **80** |
| 22 | AS4800 | 72 | 7 | 0 | **79** |
| 23 | AS133296 | 76 | 2 | 0 | **78** |
| 24 | AS137831 | 72 | 4 | 0 | **76** |
| 25 | AS20326 | 59 | 13 | 10 | **72** |
| 26 | AS327708 | 67 | 5 | 1 | **72** |
| 27 | AS3255 | 8 | 63 | 0 | **71** |
| 28 | AS45430 | 6 | 64 | 1 | **70** |
| 29 | AS29802 | 68 | 1 | 5 | **69** |
| 30 | AS36926 | 29 | 40 | 3 | **69** |

---
## 11. Findings et Implications Réseau

### 11.1 Structure du Graphe

1. **Graphe extrêmement creux** : densité = 0.000204. Sur 5,287 ASNs, seulement 5,697 paires hijacker→victime sont observées. La majorité des ASNs sont victimes d'un seul hijackeur.

2. **Fragmentation** : 886 composantes faiblement connexes — le graphe n'est PAS un composant unique. La plus grande WCC couvre 60.9% des nœuds.

3. **Pas de grande SCC** : La plus grande SCC contient 498 nœuds, ce qui indique peu de cycles hijack A→B→A (pas de 'guerre BGP' circulaire systématique).

### 11.2 Acteurs Clés

- **PageRank #1** : AS834 (score=0.025851) — ASN le plus influent dans la structure de victimisation
- **Hub #1** (hijackeur systématique) : AS138421 (score=0.388349)
- **Autorité #1** (victime structurelle) : AS4811 (score=0.314615)
- **Betweenness #1** (pivot réseau) : AS28629 (score=0.060551)

### 11.3 Risque des ASNs à Double Rôle

1014 ASNs jouent à la fois le rôle de hijackeur et de victime. 302 sont également actifs dans des leaks. Ces entités représentent un risque particulier car leur infrastructure BGP est à la fois une source de menace et une cible vulnérable.

### 11.4 Économie du Routage Malveillant

| Rôle ASN | Nb | % |
|---|---:|---:|
| Hijackeur uniquement | 1,205 | 22.8% |
| Victime uniquement | 3,068 | 58.0% |
| Hijackeur + Victime | 1,014 | 19.2% |

---
*Rapport généré automatiquement par `phase_K_network.py` le 2026-06-16 22:23:23.*  
*Sources : Cloudflare Radar API v4 — bgp_hijacks, bgp_leaks.*  
*Prochaine étape : Phase L — Synthèse finale et dashboard.*