# Étude 12 — Trajectoires de Convergence des Pays vers les Standards de Sécurité
**Auteur :** Issakha Thiam  
**Généré le :** 2026-06-18 11:59:09

---
## 1. Questions de recherche

Les pays en retard technologique rattrapent-ils les leaders ? La dispersion mondiale des indicateurs de sécurité diminue-t-elle (σ-convergence) ? Les pays initialement faibles progressent-ils plus vite (β-convergence) ?

## 2. Méthodes

- **Mann-Kendall** : tendance monotone significative par pays par indicateur (H₀ : pas de tendance)
- **β-convergence** : régression Δindicateur ~ indicateur_initial (pente négative = convergence)
- **σ-convergence** : évolution de l'écart-type mondial sur 53 semaines

## 3. Résultats Mann-Kendall

| Indicateur | ↑ Hausse | = Stable | ↓ Baisse |
|------------|----------|----------|---------|
| TLS 1.3 | 95 | 87 | 70 |
| IPv6 | 130 | 67 | 55 |
| HTTP/3 | 113 | 89 | 50 |
| bw_p50 | 4 | 47 | 201 |

## 4. β-convergence

| Indicateur | β | r | p | Interprétation |
|------------|---|---|---|----------------|
| TLS 1.3 | -0.804 | -0.669 | 0.0000 | **convergence** |
| IPv6 | -0.222 | -0.421 | 0.0000 | **convergence** |
| HTTP/3 | -0.360 | -0.450 | 0.0000 | **convergence** |
| bw_p50 | -0.552 | -0.116 | 0.0718 | **convergence** |

## 5. σ-convergence

- **TLS 1.3** : écart-type final / initial = 0.778 (convergence)
- **IPv6** : écart-type final / initial = 0.993 (convergence)
- **HTTP/3** : écart-type final / initial = 0.959 (convergence)
- **bw_p50** : écart-type final / initial = 4.955 (divergence)

---
*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*