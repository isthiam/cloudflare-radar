# Étude 17 — Paradoxe de Résilience : les Pays Vulnérables Subissent-ils Davantage les Chocs ?
**Auteur :** Issakha Thiam  
**Généré le :** 2026-06-18 12:10:32

---
## 1. Hypothèse

La vulnérabilité structurelle (IEC élevé) devrait entraîner plus de chocs réalisés (IExC élevé). Si cette corrélation est faible, on parle de **paradoxe de résilience** : certains pays structurellement fragiles n'expérimentent pas davantage de chocs — peut-être parce qu'ils génèrent moins de trafic et sont donc moins ciblés.

## 2. Résultat principal

- Corrélation Spearman IEC ~ IExC : **ρ=0.140**  p=0.0259
- Interprétation : Corrélation quasi-nulle — paradoxe de résilience confirmé

## 3. Régression OLS multiple

**R² = 0.0097**  (n=241)

| Variable | β | SE | t | p | Sig |
|----------|---|-----|---|---|-----|
| Intercept | 0.0626 | 0.0135 | 4.642 | 0.0000 | *** |
| IEC | -0.0024 | 0.0235 | -0.102 | 0.9187 |  |
| bot_ratio | 0.0026 | 0.0048 | 0.547 | 0.5847 |  |
| IPv6 | -0.0000 | 0.0001 | -0.464 | 0.6430 |  |
| bw_p50 | 0.0000 | 0.0001 | 0.907 | 0.3652 |  |

## 4. Quadrants IEC / IExC

| Quadrant | Pays |
|----------|------|
| Résilient-Épargné | 66 |
| Vulnérable-Impacté | 66 |
| Résilient-Impacté | 60 |
| Vulnérable-Épargné | 60 |

---
*Issakha Thiam — Issakha.THIAM@uca.fr — Juin 2026*