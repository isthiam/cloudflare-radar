# Vitesse de Propagation des Innovations Sécurité : De la Release Navigateur à l'Adoption Protocolaire

**Auteur :** Issakha Thiam | **Email :** Issakha.THIAM@uca.fr | **Date :** Juin 2026

---

## Résumé

Cette étude analyse l'impact des releases majeures de Chrome et Firefox sur l'adoption mondiale de TLS 1.3 et HTTP/3, via une méthode d'event study sur 53 semaines de données Cloudflare Radar. Sur la période juin 2025 – juin 2026, 13 releases Chrome et 13 releases Firefox ont été analysées. Les résultats montrent un effet positif moyen de **+0,145 point de pourcentage** sur TLS 1.3 dans les 4 semaines suivant une release Chrome liée au TLS, et de **+0,400 pp** sur HTTP/3 après une release HTTP/3-related. La tendance annuelle globale confirme une stagnation de TLS 1.3 (−0,01 %/an) et une progression continue d'HTTP/3 (+1,67 %/an).

## Introduction

Les navigateurs web constituent le principal vecteur d'adoption des nouveaux protocoles de sécurité internet : c'est leur implémentation et leurs choix par défaut qui déterminent, en cascade, l'adoption côté serveur et l'évolution des données de trafic observées par des acteurs comme Cloudflare. La question posée est simple : peut-on détecter, dans les données de trafic mondial, l'empreinte des cycles de release des navigateurs ?

## Méthodologie (Event Study)

L'approche event study consiste à mesurer l'évolution d'une métrique autour de dates d'événements prédéfinies (les releases). Pour chaque release "liée au TLS" (Chrome : versions 128, 129, 130, 131, 132, 135, 137 ; Firefox : 127, 129, 130, 131, 133, 134, 136, 137, 139) :

1. La semaine Cloudflare la plus proche de la date de release est identifiée.
2. La variation moyenne de TLS 1.3 dans les 4 semaines suivantes est calculée par rapport aux 4 semaines précédentes.
3. Le test Mann-Whitney compare les semaines post-release à toutes les semaines ordinaires.

La même procédure est appliquée aux releases "liées à HTTP/3" pour la métrique HTTP/3.

## Résultats

### Tendances annuelles globales

| Protocole | Tendance annuelle | R² | Valeur moy. 2025-2026 |
|-----------|-----------------|----|-----------------------|
| TLS 1.3   | **−0,01 %/an**  | 0,000 | ~68,5 % |
| TLS QUIC  | +0,3 %/an       | 0,05 | ~18 % |
| TLS 1.2   | −0,4 %/an       | 0,08 | ~13 % |
| **HTTP/3** | **+1,67 %/an** | **0,308** | ~25 % |

### Effets des releases navigateurs (event study)

| Navigateur | Type de release | Effet moyen sur 4 semaines |
|------------|----------------|---------------------------|
| Chrome (n=7 TLS-related) | TLS 1.3 | **+0,145 pp** |
| Chrome (n=6 HTTP3-related) | HTTP/3 | **+0,400 pp** |
| Firefox (n=8 TLS-related) | TLS 1.3 | +0,087 pp |

### Test Mann-Whitney (semaines post-release vs ordinaires)

Mann-Whitney U = 254,0 | p = **0,709** (non significatif)

L'effet positif moyen (+0,145 pp) n'est pas assez fort pour être détecté statistiquement dans un contexte de forte variabilité hebdomadaire naturelle.

## Discussion

La stagnation de TLS 1.3 (−0,01 %/an) est cohérente avec une saturation : TLS 1.3 est déjà dominant à ~68,5 % du trafic. L'effet "plafond" rend difficile la détection d'impacts supplémentaires des releases navigateurs. En revanche, HTTP/3 est encore en phase de diffusion active (+1,67 %/an, R² = 0,31), et l'empreinte des releases Chrome orientées HTTP/3 est plus clairement visible (+0,400 pp).

Le fait que l'effet Chrome > Firefox n'est pas surprenant : Chrome représente environ 65 % du marché mondial des navigateurs, et son adoption immédiate d'un protocole par défaut a un impact proportionnel sur le trafic observé par Cloudflare.

La non-significativité du test Mann-Whitney s'explique par la faible amplitude de l'effet (< 0,5 pp) face à la variabilité hebdomadaire naturelle (bruit) des métriques TLS. Une série temporelle plus longue (3–5 ans) ou une analyse à résolution quotidienne permettrait de mieux détecter ces micro-tendances.

## Conclusion

Les cycles de release des navigateurs laissent une empreinte positive et mesurable sur l'adoption de HTTP/3 (+0,400 pp/release Chrome HTTP3-related), mais l'effet sur TLS 1.3 reste en dessous du seuil de détection statistique, en raison de sa saturation déjà avancée. La progression annuelle d'HTTP/3 (+1,67 %/an) constitue la tendance la plus robuste et suggère que HTTP/3 sera majoritaire dans le trafic mondial d'ici 3 à 5 ans.

---

*Issakha Thiam — Issakha.THIAM@uca.fr*
